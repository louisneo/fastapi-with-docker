from passlib.context import CryptContext
from sqlalchemy.orm import Session

from database import DBRole, DBUser
from models import UserCreate

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def get_user_by_id(db: Session, user_id: int):
    """Get user by ID."""
    return db.query(DBUser).filter(DBUser.id == user_id).first()


def get_user_by_username(db: Session, username: str):
    """Get user by username."""
    return db.query(DBUser).filter(DBUser.username == username).first()


def get_user_by_email(db: Session, email: str):
    """Get user by email."""
    return db.query(DBUser).filter(DBUser.email == email).first()


def create_user(db: Session, user: UserCreate):
    """Create a new user safely with bcrypt truncation handling."""
    raw_password = str(user.password or "").strip()

    encoded_pw = raw_password.encode("utf-8")
    if len(encoded_pw) > 72:
        encoded_pw = encoded_pw[:72]
        raw_password = encoded_pw.decode("utf-8", errors="ignore")

    try:
        hashed_password = pwd_context.hash(raw_password)
    except Exception as e:
        raise ValueError(f"Error hashing password: {e}")

    db_user = DBUser(
        username=user.username,
        email=user.email,
        full_name=user.full_name,
        hashed_password=hashed_password,
    )

    user_role = db.query(DBRole).filter(DBRole.name == "user").first()
    if user_role:
        db_user.roles.append(user_role)

    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user


def authenticate_user(db: Session, username: str, password: str):
    """Authenticate user with username and password."""
    user = get_user_by_username(db, username)
    if not user:
        return False
    if not pwd_context.verify(password, user.hashed_password):
        return False
    return user


def create_role(db: Session, name: str, description: str = ""):
    """Create a new role."""
    db_role = DBRole(name=name, description=description)
    db.add(db_role)
    db.commit()
    db.refresh(db_role)
    return db_role


def get_role_by_name(db: Session, name: str):
    """Get a role by its name."""
    return db.query(DBRole).filter(DBRole.name == name).first()


def get_all_users(db: Session, skip: int = 0, limit: int = 100):
    """Get all users with pagination."""
    return db.query(DBUser).offset(skip).limit(limit).all()
