from asyncio.log import logger

from typing import Annotated
from datetime import datetime

from fastapi import APIRouter, HTTPException, Depends, BackgroundTasks, Request, Response, Cookie, dependencies, status
from fastapi.exceptions import RequestValidationError
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError

import requests
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Session

from pydantic import BaseModel, ValidationError

from app import schemas, models

from app.auth import jwt
from app.auth.config import ALGORITHM, SECRET_KEY
from app.auth.hash import get_password_hash, verify_password
from app.database import get_db
from app.auth.jwt import (
    create_token_pair,
    refresh_token_state,
    decode_access_token,
    mail_token,
    add_refresh_token_cookie,
    SUB,
    JTI,
    EXP,
)
from app.exceptions import BadRequestException, NotFoundException, ForbiddenException



router = APIRouter()

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")


@router.post("/register", response_model=schemas.User)
async def register(
    data: schemas.UserRegister,
    bg_task: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
):
    user = await models.User.find_by_email(db=db, email=data.email)
    if user:
        raise HTTPException(status_code=400, detail="Email has already been registered")

    # Hash password and prepare user data
    user_data = data.dict(exclude={"confirm_password", "university", "major", "gpa", "company_name", "company_address", "contact_number"})
    user_data["password"] = get_password_hash(user_data["password"])
    user_data["user_type"] = data.user_type if data.user_type else "student"

    # Create the user
    user = models.User(**user_data)
    user.is_active = False
    await user.save(db=db)

    # Create student or partner based on the user_type
    if user.user_type == models.UserType.STUDENT:
        student_data = schemas.StudentCreate(user_id=user.id, university=data.university, major=data.major, gpa=data.gpa)
        student = models.Student(**student_data.dict())
        db.add(student)
        db.commit()

    elif user.user_type == models.UserType.PARTNER:
        partner_data = schemas.PartnerCreate(user_id=user.id, company_name=data.company_name, company_address=data.company_address, contact_number=data.contact_number)
        partner = models.Partner(**partner_data.dict())
        db.add(partner)
        db.commit()

    return user







    user_schema = schemas.User.from_orm(user)
    return user_schema


from fastapi.security import OAuth2PasswordRequestForm

@router.post("/login")
async def login(
    response: Response,
    form_data: OAuth2PasswordRequestForm = Depends(),  # Handles username/password and grant_type
    db: AsyncSession = Depends(get_db),
):
    # Authenticate user
    user = await models.User.authenticate(
        db=db, email=form_data.username, password=form_data.password
    )

    if not user:
        raise HTTPException(status_code=400, detail="Incorrect username or password")

    # Generate token pair
    token_pair = create_token_pair(user=schemas.User.from_orm(user))

    # Add refresh token as a secure cookie
    add_refresh_token_cookie(response=response, token=token_pair.refresh.token)

    return {"access_token": token_pair.access.token, "token_type": "bearer"}



@router.post("/refresh")
async def refresh(refresh: Annotated[str | None, Cookie()] = None):
    print(refresh)
    if not refresh:
        raise BadRequestException(detail="refresh token required")
    return refresh_token_state(token=refresh)


@router.get("/verify", response_model=schemas.SuccessResponseScheme)
async def verify(token: str, db: AsyncSession = Depends(get_db)):
    payload = await decode_access_token(token=token, db=db)
    user = await models.User.find_by_id(db=db, id=payload[SUB])
    if not user:
        raise NotFoundException(detail="User not found")

    user.is_active = True
    await user.save(db=db)
    return {"msg": "Successfully activated"}


@router.post("/logout", response_model=schemas.SuccessResponseScheme)
async def logout(
    token: Annotated[str, Depends(oauth2_scheme)],
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    payload = await decode_access_token(token=token, db=db)
    black_listed = models.BlackListToken(
        id=payload[JTI], expire=datetime.utcfromtimestamp(payload[EXP])
    )
    await black_listed.save(db=db)
    return {"msg": "Successfully logged out"}





@router.post("/password-reset", response_model=schemas.SuccessResponseScheme)
async def password_reset_token(
    token: str,
    data: schemas.PasswordResetSchema,
    db: AsyncSession = Depends(get_db),
):
    payload = await decode_access_token(token=token, db=db)
    user = await models.User.find_by_id(db=db, id=payload[SUB])
    if not user:
        raise NotFoundException(detail="User not found")

    user.password = get_password_hash(data.password)
    await user.save(db=db)

    return {"msg": "Password succesfully updated"}


@router.post("/password-update", response_model=schemas.SuccessResponseScheme)
async def password_update(
    token: Annotated[str, Depends(oauth2_scheme)],
    data: schemas.PasswordUpdateSchema,
    db: AsyncSession = Depends(get_db),
):
    payload = await decode_access_token(token=token, db=db)
    user = await models.User.find_by_id(db=db, id=payload[SUB])
    if not user:
        raise NotFoundException(detail="User not found")

    # raise Validation error
    if not verify_password(data.old_password, user.password):
        try:
            schemas.OldPasswordErrorSchema(old_password=False)
        except ValidationError as e:
            raise RequestValidationError(e.raw_errors)
    user.password = get_password_hash(data.password)
    await user.save(db=db)

    return {"msg": "Successfully updated"}

class TokenData(BaseModel):
    user_id: str
    user_type: str  # 'PARTNER', 'STUDENT', etc.

async def get_current_user(token: str = Depends(oauth2_scheme), db: AsyncSession = Depends(get_db)):
    try:
        # Log the token right when it's received
        logger.info(f"Received token: {token}")

        payload = await jwt.decode_access_token(token, db)
        logger.info(f"Decoded token payload: {payload}")
        
        user = TokenData(**payload)  # Parse user data from the token
        logger.info(f"User data parsed from token: {user}")
        
        return user
    except JWTError:
        logger.error("Invalid token error")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

@router.post("/scholarships/")
async def create_scholarship(
    scholarship_data: schemas.ScholarshipCreate,
    db: AsyncSession = Depends(get_db),
    current_user: TokenData = Depends(get_current_user),
):
    # Check if the current user is a partner
    if current_user.user_type != 'partner':
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You do not have permission to add scholarships"
        )
    
    # Create the scholarship and associate it with the partner
    partner = db.execute(
        select(models.Partner).filter(models.Partner.user_id == current_user.user_id)
    )
    partner = partner.scalars().first()
    if not partner:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Partner not found"
        )
    
    scholarship = models.Scholarship(
        title=scholarship_data.title,
        description=scholarship_data.description,
        partner_id=partner.id  # Associate the scholarship with the partner
    )
    
    db.add(scholarship)
    db.commit()
    db.refresh(scholarship)
    return scholarship

@router.post("/feedback/")
async def create_feedback(
    feedback_data: schemas.FeedbackCreate,
    db: AsyncSession = Depends(get_db),
    current_user: TokenData = Depends(get_current_user),
):
    # Fetch the student corresponding to the current user
    student = db.execute(
        select(models.Student).filter(models.Student.user_id == current_user.user_id)
    )
    student = student.scalars().first()
    if not student:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Student not found for the current user"
        )

    # Verify that the scholarship exists
    scholarship = db.execute(
        select(models.Scholarship).filter(models.Scholarship.id == feedback_data.scholarship_id)
    )
    scholarship = scholarship.scalars().first()
    if not scholarship:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scholarship not found"
        )

    # Create the feedback
    feedback = models.Feedback(
        scholarship_id=feedback_data.scholarship_id,
        student_id=student.id,  # Use the `id` of the corresponding student
        comment=feedback_data.comment,
        liked=feedback_data.liked,
        created_at=datetime.utcnow(),
    )
    db.add(feedback)
    db.commit()
    db.refresh(feedback)
    return feedback

DISCORD_BOT_TOKEN = ""
DISCORD_GUILD_ID = "1323194210085634110"  # Replace with your Discord server ID

class Scholarship(BaseModel):
    title: str

@router.post("/create-channel/")
async def create_channel(scholarship: Scholarship):
    """
    Create a Discord channel for the given scholarship.
    """
    url = f"https://discord.com/api/v10/guilds/{DISCORD_GUILD_ID}/channels"
    headers = {
        "Authorization": f"Bot {DISCORD_BOT_TOKEN}",
        "Content-Type": "application/json",
    }
    payload = {
        "name": scholarship.title.replace(" ", "-").lower(),  # Channel name
        "type": 0,  # 0 = Text channel
        "topic": f"Discussion channel for {scholarship.title}"
    }
    
    response = requests.post(url, json=payload, headers=headers)
    
    if response.status_code == 201:
        channel_data = response.json()
        return {"status": "Channel created", "channel_id": channel_data["id"]}
    else:
        raise HTTPException(status_code=response.status_code, detail=response.json())