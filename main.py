from fastapi import FastAPI, APIRouter, Depends, HTTPException
from pydantic import BaseModel, EmailStr, field_validator, ValidationInfo
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker, Session, relationship
from sqlalchemy import create_engine, select, ForeignKey, DateTime, Numeric
from contextlib import asynccontextmanager
from typing import Annotated
from jwt import encode, decode
from jwt.exceptions import InvalidTokenError, ExpiredSignatureError
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from hashlib import scrypt
import os
import base64
from datetime import timedelta, datetime, timezone
import httpx
from dotenv import load_dotenv

load_dotenv()

engine = create_engine("sqlite:///data.db", echo=True)
PAYPAL_CLIENT_ID = os.getenv("PAYPAL_CLIENT_ID")
PAYPAL_CLIENT_SECRET = os.getenv("PAYPAL_CLIENT_SECRET")
SECRET_KEY = os.getenv("SECRET_KEY")
security = HTTPBearer()

class Base(DeclarativeBase):
    pass

@asynccontextmanager
async def lifespan(app: FastAPI):
    Base.metadata.create_all(engine)
    yield

app = FastAPI(lifespan=lifespan)

new_session = sessionmaker(engine, expire_on_commit=False)

def get_session():
    with new_session() as session:
        yield session

SessionDep = Annotated[Session, Depends(get_session)]

class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(unique=True)
    password: Mapped[str]
    email: Mapped[str]

    transactions: Mapped[list["Transactions"]] = relationship(back_populates="user", cascade="all, delete-orphan")

class Transactions(Base):
    __tablename__ = "transactions"

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False)
    order_id: Mapped[str] = mapped_column(unique=True)
    amount: Mapped[float] = mapped_column(Numeric(12, 2))
    status: Mapped[str] = mapped_column(default="CREATED")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(tz=timezone.utc),
        nullable=False,
    )

    user: Mapped["User"] = relationship(back_populates="transactions") 

class UserLoginSchema(BaseModel):
    username: str
    password1: str

class UserRegisterSchema(UserLoginSchema):
    password2: str
    email: EmailStr

    @field_validator("password2")
    @classmethod
    def check_passwords_match(cls, value: str, info: ValidationInfo):
        if value != info.data["password1"]:
            raise ValueError('Passwords do not match')
        return value
    
class UserOutSchema(BaseModel):
    id: int
    username: str
    email: EmailStr

class CreateOrderSchema(BaseModel):
    value: float

class CaptureOrderSchema(BaseModel):
    order_id: str
    
def encode_user(user):
    return encode({"sub": str(user.id), "exp": datetime.now(tz=timezone.utc) + timedelta(minutes=15)}, SECRET_KEY, algorithm="HS256")

def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security), session: Session = Depends(get_session)):
    token = credentials.credentials
    try:
        payload = decode(token, SECRET_KEY, algorithms=["HS256"])
    except ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token is expired")
    except InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")
    
    user = session.get(User, payload.get("sub"))
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user

GetCurrentUserDep = Annotated[User, Depends(get_current_user)]

def hash_password(password: str) -> str:
    salt = os.urandom(16)
    key = scrypt(
        password=password.encode(),
        salt=salt,
        n=2**14,
        r=8,
        p=1,
        dklen=64,
    )
    return base64.b64encode(salt + key).decode()

def verify_password(password: str, stored: str) -> bool:
    raw = base64.b64decode(stored)
    salt = raw[:16]
    stored_key = raw[16:]
    key = scrypt(
        password=password.encode(),
        salt=salt,
        n=2**14,
        r=8,
        p=1,
        dklen=64,
    )
    return key == stored_key

def get_paypal_access_token():
    auth = httpx.BasicAuth(PAYPAL_CLIENT_ID, PAYPAL_CLIENT_SECRET)
    with httpx.Client(auth=auth) as client:
        headers = {
            "Content-Type": "application/x-www-form-urlencoded"
        }
        data = {
            "grant_type":"client_credentials"
        }
        response = client.post(
            "https://api-m.sandbox.paypal.com/v1/oauth2/token",
            headers=headers,
            data=data,
            timeout=10,
            )
        response.raise_for_status()
        payload = response.json()
        return payload["access_token"]

user_router = APIRouter()

@app.get("/")
def root():
    return {"status": "OK"}

@user_router.get("/", response_model=list[UserOutSchema])
def get_users(session: SessionDep):
    query = select(User)
    result = session.execute(query)
    return result.scalars().all()

@user_router.post("/register")
def register(data: UserRegisterSchema, session: SessionDep):
    query = select(User).where(User.username == data.username)
    exists = session.execute(query).scalar_one_or_none()
    if exists:
        raise HTTPException(status_code=401, detail="User already exists")
    hashed_password = hash_password(data.password1)
    user = User(
        username=data.username,
        password=hashed_password,
        email=data.email,
    )
    session.add(user)
    session.commit()
    return {"token": encode_user(user)}

@user_router.get("/login_required")
def login_required(user: GetCurrentUserDep):
    return user

@user_router.post("/get_token")
def get_token(data: UserLoginSchema, session: SessionDep):
    queary = select(User).where(User.username == data.username)
    user = session.execute(queary).scalar_one_or_none()
    if not user or not verify_password(data.password1, user.password):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    return {"token": encode_user(user)}

@app.post("/create_order")
def create_order(data: CreateOrderSchema):
    ACCESS_TOKEN = get_paypal_access_token()
    headers = {
    "Content-Type": "application/json",
    "Authorization": f"Bearer {ACCESS_TOKEN}"
    }
    json = {
        "intent": "CAPTURE",
        "purchase_units": [
            {
                "amount": {
                    "currency_code": "USD",
                    "value": str(data.value)
                }
            }
        ],
    }
    with httpx.Client() as client:
        response = client.post(
            "https://api-m.sandbox.paypal.com/v2/checkout/orders/",
            headers=headers,
            json=json,
                )
        response.raise_for_status()
    payload = response.json()
    for link in payload["links"]:
        if link["rel"] == "approve":
            return {
                "link": link["href"],
                "id": payload["id"]
                }

@app.post("/capture_order")
def capture_order(data: CaptureOrderSchema):
    ACCESS_TOKEN = get_paypal_access_token()
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {ACCESS_TOKEN}"
    }
    with httpx.Client() as client:
        response = client.post(f"https://api-m.sandbox.paypal.com/v2/checkout/orders/{data.order_id}/capture", headers=headers)
    payload = response.json()

app.include_router(user_router, prefix="/user")