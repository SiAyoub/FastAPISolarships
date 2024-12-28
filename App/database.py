from sqlalchemy import create_engine, inspect
from sqlalchemy.ext.asyncio import AsyncAttrs, AsyncSession
from sqlalchemy.future import select
from sqlalchemy.exc import SQLAlchemyError
from fastapi import HTTPException, status
from sqlalchemy.orm import sessionmaker, declarative_base
from sqlalchemy.orm import Session
from fastapi import HTTPException, status
from pydantic import PostgresDsn
from sqlalchemy import select
from sqlalchemy.ext.asyncio import (
    AsyncAttrs,
    async_sessionmaker,
    create_async_engine,
    AsyncSession,
)
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import DeclarativeBase

from app.auth import config
# Database URL (hardcoded for now)
SQLALCHEMY_DATABASE_URL = "postgresql://postgres:toor@localhost/apiscolar"

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
class Base(AsyncAttrs, DeclarativeBase):
    async def save(self, db: Session):
        """
        :param db:
        :return:
        """
        try:
            db.add(self)
            return  db.commit()
        except SQLAlchemyError as ex:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=repr(ex)
            ) from ex

    @classmethod
    async def find_by_id(cls, db: Session, id: str):
        query = select(cls).where(cls.id == id)
        result =  db.execute(query)
        return result.scalars().first()


inspector = inspect(engine)
tables = inspector.get_table_names()  # This retrieves all the table names in the connected database
print(tables)