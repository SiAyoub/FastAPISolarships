import datetime
from sqlalchemy import Column, Integer, String, ForeignKey, Text, Float, select
from passlib.context import CryptContext
from sqlalchemy.orm import relationship, Session
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import Mapped, mapped_column
from app.auth.hash import verify_password
from app.utils import utcnow
from app.database import Base
import uuid
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

class User(Base):
    __tablename__ = "users"
    id: Mapped[uuid.UUID] = mapped_column(
        primary_key=True, index=True, default=uuid.uuid4
    )
    email: Mapped[str] = mapped_column(unique=True, index=True)
    full_name: Mapped[str]
    password: Mapped[str]
    is_active: Mapped[bool] = mapped_column(default=True)
    created_at: Mapped[datetime.datetime] = mapped_column(server_default=utcnow())
    updated_at: Mapped[datetime.datetime] = mapped_column(
        server_default=utcnow(), server_onupdate=utcnow(), onupdate=utcnow()
    )

    
    @classmethod
    async def find_by_email(cls, db: Session, email: str):
        query = select(cls).where(cls.email == email)
        result =  db.execute(query)
        return result.scalar_one_or_none()
    @classmethod
    async def authenticate(cls, db: AsyncSession, email: str, password: str):
        user =  await cls.find_by_email(db=db, email=email)
        if not user or not verify_password(password, user.password):
            return False
        return user


class BlackListToken(Base):
    __tablename__ = "blacklisttokens"
    id: Mapped[uuid.UUID] = mapped_column(
        primary_key=True, index=True, default=uuid.uuid4
    )
    expire: Mapped[datetime.datetime]
    created_at: Mapped[datetime.datetime] = mapped_column(server_default=utcnow())

    # def send_email_to_partner(self):
    #     # Logic to send email to the partner who posted the scholarship
    #     partner_email = self.scholarship.partner.user.email
    #     # Assuming you have a function send_email(to, subject, body)
    #     send_email(
    #         to=partner_email,
    #         subject="New Application Received",
    #         body=f"A new application has been submitted by {self.student.user.username} for your scholarship {self.scholarship.title}."
    #     )