from pydantic import BaseModel


class User(BaseModel):
    username: str
    email: str | None = None
    full_name: str | None = None
    disabled: bool | None = None
    roles: list[str] = []


class UserInDB(User):
    hashed_password: str


class UserCreate(BaseModel):
    username: str
    email: str
    full_name: str
    password: str
