import crud
from database import Base, SessionLocal, engine

Base.metadata.create_all(bind=engine)


def init_db():
    """Initialize the database with default roles."""
    db = SessionLocal()

    if not crud.get_role_by_name(db, "user"):
        crud.create_role(db, "user", "Regular user")

    if not crud.get_role_by_name(db, "admin"):
        crud.create_role(db, "admin", "Administrator")

    if not crud.get_role_by_name(db, "moderator"):
        crud.create_role(db, "moderator", "Moderator")

    db.close()
    print("✅ Database initialized successfully!")


if __name__ == "__main__":
    init_db()
