from fastapi import FastAPI, APIRouter, Depends, HTTPException
from pydantic import BaseModel, EmailStr, field_validator, ValidationInfo
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker, Session
from sqlalchemy import create_engine, select
from contextlib import asynccontextmanager
from typing import Annotated
from jwt import encode, decode
from jwt.exceptions import InvalidTokenError, ExpiredSignatureError
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from hashlib import scrypt
import os
import base64
from datetime import timedelta, datetime, timezone

engine = create_engine("sqlite:///data.db", echo=True)
SECRET_KEY = "SECRET_KEY"
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
    
class UserOut(BaseModel):
    id: int
    username: str
    email: EmailStr
    
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

user_router = APIRouter()

@app.get("/")
def root():
    return {"status": "OK"}

@user_router.get("/", response_model=list[UserOut])
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
def login_required(user = Depends(get_current_user)):
    return user

@user_router.post("/get_token")
def get_token(data: UserLoginSchema, session: SessionDep):
    queary = select(User).where(User.username == data.username)
    user = session.execute(queary).scalar_one_or_none()
    if not user or not verify_password(data.password1, user.password):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    return {"token": encode_user(user)}

app.include_router(user_router, prefix="/user")