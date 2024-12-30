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
    major: Optional[str] = None       # Only for student
    gpa: Optional[float] = None       # Only for student
    company_name: Optional[str] = None  # Only for partner
    company_address: Optional[str] = None  # Only for partner
    contact_number: Optional[str] = None  # Only for partner

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
            if not values.get('university') or not values.get('major') or values.get('gpa') is None:
                raise ValueError("For a student, university, major, and GPA must be provided.")
        
        if user_type == 'partner':
            if not values.get('company_name') or not values.get('company_address') or not values.get('contact_number'):
                raise ValueError("For a partner, company_name, company_address, and contact_number must be provided.")

        return values
# Schema for creating a student record
class StudentCreate(BaseModel):
    user_id: UUID
    university: str
    major: str
    gpa: float

# Schema for creating a partner record
class PartnerCreate(BaseModel):
    user_id: UUID
    company_name: str
    company_address: str
    contact_number: str


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

    class Config:
        orm_mode = True

class FeedbackCreate(BaseModel):
    scholarship_id: UUID4
    comment: str  # Optional for comments
    liked: bool          # Indicates whether the student liked the scholarship

