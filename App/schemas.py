from enum import Enum
from typing import Any, Optional
from datetime import datetime
from uuid import UUID
from pydantic import BaseModel, UUID4, root_validator, validator, EmailStr

class UserTypeEnum(str, Enum):
    student = "student"
    partner = "partner"
class UserBase(BaseModel):
    email: EmailStr
    full_name: str
    user_type: UserTypeEnum = UserTypeEnum.student  # Default to 'student'

class UserCreate(UserBase):
    password: str


class User(UserBase):
    id: UUID4

    class Config:
        orm_mode = True
        from_attributes = True  # Required for Pydantic v2

    @validator("id")
    def convert_to_str(cls, v, values, **kwargs):
        return str(v) if v else v


class UserRegister(UserBase):
    password: str
    confirm_password: str
    university: Optional[str] = None  # Only for student
    username: Optional[str] = None    # Only for student
    phone_number: Optional[str] = None  # Only for partner
    website: Optional[str] = None     # Only for partner
    address: Optional[str] = None     # Only for partner
    country: Optional[str] = None     # Only for partner

    @validator("confirm_password")
    def verify_password_match(cls, v, values, **kwargs):
        password = values.get("password")
        if v != password:
            raise ValueError("The two passwords did not match.")
        return v

    @root_validator(pre=True)
    def check_user_type_fields(cls, values):
        user_type = values.get('user_type')
        
        if user_type == 'student':
            if not values.get('university') or not values.get('username'):
                raise ValueError("For a student, university and username must be provided.")
        
        if user_type == 'partner':
            if not values.get('phone_number') or not values.get('website') or not values.get('address') or not values.get('country'):
                raise ValueError("For a partner, phone_number, website, address, and country must be provided.")

        return values

# Schema for creating a student record
class StudentCreate(BaseModel):
    user_id: UUID
    university: str
    username: str

# Schema for creating a partner record
class PartnerCreate(BaseModel):
    user_id: UUID
    phone_number: str
    website: str
    address: str
    country: str

class UserLogin(BaseModel):
    email: EmailStr
    password: str


class JwtTokenSchema(BaseModel):
    token: str
    payload: dict
    expire: datetime


class TokenPair(BaseModel):
    access: JwtTokenSchema
    refresh: JwtTokenSchema


class RefreshToken(BaseModel):
    refresh: str


class SuccessResponseScheme(BaseModel):
    msg: str


class BlackListToken(BaseModel):
    id: UUID4
    expire: datetime

    class Config:
        orm_mode = True
        from_attributes = True  # Required for Pydantic v2


class MailBodySchema(BaseModel):
    token: str
    type: str


class EmailSchema(BaseModel):
    recipients: list[EmailStr]
    subject: str
    body: MailBodySchema


class MailTaskSchema(BaseModel):
    user: User
    body: MailBodySchema


class ForgotPasswordSchema(BaseModel):
    email: EmailStr


class PasswordResetSchema(BaseModel):
    password: str
    confirm_password: str

    @validator("confirm_password")
    def verify_password_match(cls, v, values, **kwargs):
        password = values.get("password")

        if v != password:
            raise ValueError("The two passwords did not match.")

        return v


class PasswordUpdateSchema(PasswordResetSchema):
    old_password: str


class OldPasswordErrorSchema(BaseModel):
    old_password: bool

    @validator("old_password")
    def check_old_password_status(cls, v, values, **kwargs):
        if not v:
            raise ValueError("Old password is not corret")


class ArticleCreateSchema(BaseModel):
    title: str
    content: str


class ArticleListScheme(ArticleCreateSchema):
    id: UUID4
    author_id: UUID4

    class Config:
        orm_mode = True
        from_attributes = True

class ScholarshipCreate(BaseModel):
    title: str
    description: str
    location: str
    application_link: str
    field_of_study: str
    funding_type: str
    funding_amount: float
    duration: int
    status: str = "open"
    

    class Config:
        orm_mode = True

class FeedbackCreate(BaseModel):
    scholarship_id: UUID4
    comment: str  # Optional for comments
    liked: bool          # Indicates whether the student liked the scholarship

class Scholarship(BaseModel):
    id: UUID4
    title: str
    description: str
    location: str
    application_link: str
    field_of_study: str
    funding_type: str
    funding_amount: float
    duration: int
    status: str = "open"

    class Config:
        orm_mode = True
