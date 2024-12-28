from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base
from sqlalchemy.orm import Session

# Database URL (hardcoded for now)
SQLALCHEMY_DATABASE_URL = "postgresql://postgres:95920822@localhost/postgres"

# Create SQLAlchemy engine
engine = create_engine(SQLALCHEMY_DATABASE_URL, echo=True)

# Session local class for managing DB sessions
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Base class for all ORM models
Base = declarative_base()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()