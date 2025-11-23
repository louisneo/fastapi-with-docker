from datetime import timedelta
from typing import cast

import uvicorn
from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session

import crud
from auth import (
    ACCESS_TOKEN_EXPIRE_MINUTES,
    create_access_token,
    get_current_active_user,
)
from database import DBUser, get_db
from models import User, UserCreate

app = FastAPI(title="FastAPI Authentication with Database", version="1.0.0")

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)


@app.get("/")
async def root():
    return {"message": "Welcome to FastAPI Authentication Demo"}


@app.post("/register", response_model=User)
async def register_user(user: UserCreate, db: Session = Depends(get_db)):
    """Register a new user."""

    db_user = crud.get_user_by_username(db, username=user.username)
    if db_user:
        raise HTTPException(status_code=400, detail="Username already registered")

    db_user = crud.get_user_by_email(db, email=user.email)
    if db_user:
        raise HTTPException(status_code=400, detail="Email already registered")

    new_user = crud.create_user(db=db, user=user)

    # Cast to proper types to fix Pyright errors
    username = cast(str, new_user.username)
    email = cast(str, new_user.email)
    full_name = cast(str, new_user.full_name)
    is_active = cast(bool, new_user.is_active)

    return User(
        username=username,
        email=email,
        full_name=full_name,
        disabled=not is_active,
        roles=[role.name for role in new_user.roles],
    )


@app.post("/token")
async def login_for_access_token(
    form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)
):
    """Authenticate user and return JWT access token."""
    user = crud.authenticate_user(db, form_data.username, form_data.password)
    if not user or user is False:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Type narrowing: at this point user is DBUser
    assert isinstance(user, DBUser)
    username = cast(str, user.username)

    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": username}, expires_delta=access_token_expires
    )

    return {"access_token": access_token, "token_type": "bearer"}


@app.get("/users/me", response_model=User)
async def read_users_me(current_user: User = Depends(get_current_active_user)):
    """Get current user information."""
    return current_user


@app.get("/protected")
async def protected_route(current_user: User = Depends(get_current_active_user)):
    """Protected route that requires valid token."""
    return {"message": f"Hello {current_user.full_name}, this is a protected route!"}
