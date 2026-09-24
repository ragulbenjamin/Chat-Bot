"""JWT authentication for the API.

    POST /auth/register   create an account (JSON: email, password, username?)
    POST /auth/token      log in (form: username=<email>, password) -> bearer token
    GET  /auth/me         the logged-in user

Protect any route with:  user: User = Depends(get_current_user)
"""

import hmac
from datetime import datetime, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, ConfigDict, EmailStr, Field
from sqlalchemy.orm import Session

from admin import MIN_PASSWORD_LENGTH
from auth import create_user, get_user_by_email
from database import get_db
from models import User
from security import DUMMY_HASH, create_access_token, decode_access_token, password_fingerprint, verify_password

router = APIRouter(prefix="/auth", tags=["auth"])
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/token")

DbSession = Annotated[Session, Depends(get_db)]


class RegisterIn(BaseModel):
    email: EmailStr
    password: str = Field(min_length=MIN_PASSWORD_LENGTH)
    username: str | None = Field(default=None, max_length=100)


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    email: str
    username: str
    is_staff: bool
    is_superuser: bool


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"


def get_current_user(token: Annotated[str, Depends(oauth2_scheme)], db: DbSession) -> User:
    unauthorized = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    claims = decode_access_token(token)
    if claims is None or not str(claims["sub"]).isdigit():
        raise unauthorized
    user = db.get(User, int(claims["sub"]))
    if (
        user is None
        or not user.is_active
        or not hmac.compare_digest(claims["pwd"], password_fingerprint(user.hashed_password)[:16])
    ):
        raise unauthorized
    return user


CurrentUser = Annotated[User, Depends(get_current_user)]


@router.post("/register", response_model=UserOut, status_code=status.HTTP_201_CREATED)
def register(data: RegisterIn, db: DbSession):
    try:
        return create_user(db, email=data.email, password=data.password, username=data.username)
    except ValueError:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Email already registered")


@router.post("/token", response_model=Token)
def login(form: Annotated[OAuth2PasswordRequestForm, Depends()], db: DbSession):
    user = get_user_by_email(db, form.username)
    if user is None:
        verify_password(form.password, DUMMY_HASH)  # same timing as a real check
    if user is None or not verify_password(form.password, user.hashed_password) or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    user.last_login = datetime.now(timezone.utc)
    db.commit()
    return Token(access_token=create_access_token(user.id, user.hashed_password))


@router.get("/me", response_model=UserOut)
def me(user: CurrentUser):
    return user
