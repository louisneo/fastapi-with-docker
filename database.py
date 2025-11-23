import os

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Table,
    create_engine,
)
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker
from sqlalchemy.sql import func


def get_database_url() -> str:
    """Get database URL from environment variables or Docker secrets."""
    # Read password from Docker secret file
    password_file = os.getenv("POSTGRES_PASSWORD_FILE")

    if password_file and os.path.exists(password_file):
        with open(password_file) as f:
            password = f.read().strip()
    else:
        # Fallback for local development
        password = os.getenv("POSTGRES_PASSWORD", "postgres")

    # Get other database config from environment
    server = os.getenv("POSTGRES_SERVER", "localhost")
    user = os.getenv("POSTGRES_USER", "postgres")
    db = os.getenv("POSTGRES_DB", "example")

    return f"postgresql://{user}:{password}@{server}:5432/{db}"


# Get database URL
DATABASE_URL = get_database_url()

# For PostgreSQL, we don't need check_same_thread
engine = create_engine(DATABASE_URL)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

user_roles = Table(
    "user_roles",
    Base.metadata,
    Column("user_id", Integer, ForeignKey("users.id")),
    Column("role_id", Integer, ForeignKey("roles.id")),
)


class DBUser(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    email = Column(String, unique=True, index=True)
    full_name = Column(String)
    hashed_password = Column(String)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=func.now())

    roles = relationship("DBRole", secondary=user_roles, back_populates="users")


class DBRole(Base):
    __tablename__ = "roles"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, index=True)
    description = Column(String)

    users = relationship("DBUser", secondary=user_roles, back_populates="roles")


# Create tables
Base.metadata.create_all(bind=engine)


def get_db():
    """Dependency to get database session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
