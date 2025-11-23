from datetime import UTC, datetime, timedelta
from typing import Any, cast

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from sqlalchemy.orm import Session

import crud
from database import DBUser, get_db
from models import User

SECRET_KEY = "your-secret-key-here"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


def convert_db_user_to_user(db_user: DBUser) -> User:
    """Convert database user to Pydantic user model."""
    # Cast to proper types to fix Pyright errors
    username = cast(str, db_user.username)
    email = cast(str, db_user.email)
    full_name = cast(str, db_user.full_name)
    is_active = cast(bool, db_user.is_active)

    return User(
        username=username,
        email=email,
        full_name=full_name,
        disabled=not is_active,
        roles=[role.name for role in db_user.roles],
    )


def create_access_token(
    data: dict[str, Any], expires_delta: timedelta | None = None
) -> str:
    """Create a JWT access token."""
    to_encode: dict[str, Any] = data.copy()
    if expires_delta:
        expire = datetime.now(UTC) + expires_delta
    else:
        expire = datetime.now(UTC) + timedelta(minutes=15)

    to_encode.update({"exp": expire})
    encoded_jwt: str = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


async def get_current_user(
    token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)
) -> User:
    """Get the current user from the JWT token."""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str | None = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    db_user = crud.get_user_by_username(db, username=username)
    if db_user is None:
        raise credentials_exception

    return convert_db_user_to_user(db_user)


async def get_current_active_user(
    current_user: User = Depends(get_current_user),
) -> User:
    """Get the current active user (not disabled)."""
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user
