from asyncio.log import logger

from typing import Annotated, List
from datetime import datetime

from fastapi import APIRouter, HTTPException, Depends, BackgroundTasks, Request, Response, Cookie, status
from fastapi.exceptions import RequestValidationError
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError

import requests
from sqlalchemy import UUID, delete, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Session

from pydantic import UUID4, BaseModel, ValidationError

from app import schemas, models

from app.auth import jwt
from app.auth.hash import get_password_hash, verify_password
from app.database import get_db
from app.auth.jwt import (
    create_token_pair,
    refresh_token_state,
    decode_access_token,
    add_refresh_token_cookie,
    SUB,
    JTI,
    EXP,
)
from app.exceptions import BadRequestException, NotFoundException



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
    user_data = data.dict(exclude={"confirm_password", "university", "username", "phone_number", "website", "address", "country"})
    user_data["password"] = get_password_hash(user_data["password"])
    user_data["user_type"] = data.user_type if data.user_type else "student"

    # Create the user
    user = models.User(**user_data)
    user.is_active = False
    await user.save(db=db)

    # Create student or partner based on the user_type
    if user.user_type == models.UserType.STUDENT:
        student_data = schemas.StudentCreate(user_id=user.id, university=data.university, username=data.username)
        student = models.Student(**student_data.dict())
        db.add(student)
        db.commit()

    elif user.user_type == models.UserType.PARTNER:
        partner_data = schemas.PartnerCreate(user_id=user.id, phone_number=data.phone_number, website=data.website, address=data.address, country=data.country)
        partner = models.Partner(**partner_data.dict())
        db.add(partner)
        db.commit()

    return schemas.User.from_orm(user)


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
        location=scholarship_data.location,
        application_link=scholarship_data.application_link,
        field_of_study=scholarship_data.field_of_study,
        funding_type=scholarship_data.funding_type,
        funding_amount=scholarship_data.funding_amount,
        duration=scholarship_data.duration,
        status=scholarship_data.status,
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
        likes_count=0,
        created_at=datetime.utcnow(),
    )
    db.add(feedback)
    db.commit()
    db.refresh(feedback)
    return feedback
@router.post("/feedback/{feedback_id}/like")
async def add_like(
    feedback_id: UUID4,
    db: AsyncSession = Depends(get_db),
    current_user: TokenData = Depends(get_current_user),
):
    # Check if the feedback exists
    feedback_query = db.execute(
        select(models.Feedback).filter(models.Feedback.id == feedback_id)
    )
    feedback = feedback_query.scalars().first()
    if not feedback:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Feedback not found"
        )

    # Fetch the student corresponding to the current user
    student_query = db.execute(
        select(models.Student).filter(models.Student.user_id == current_user.user_id)
    )
    student = student_query.scalars().first()
    if not student:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Student not found for the current user"
        )

    # Check if the student has already liked this feedback
    like_query = db.execute(
        select(models.Likes).filter(
            models.Likes.feedback_id == feedback_id,
            models.Likes.student_id == student.id,
        )
    )
    existing_like = like_query.scalars().first()
    if existing_like:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="You have already liked this feedback"
        )

    # Add the like
    like = models.Likes(
        feedback_id=feedback_id,
        student_id=student.id
    )
    db.add(like)

    # Increment the likes_count
    feedback.likes_count += 1
    db.commit()
    db.refresh(feedback)

    return {"message": "Like added successfully", "likes_count": feedback.likes_count}


DISCORD_BOT_TOKEN = ""
DISCORD_GUILD_ID = "1323194210085634110"  # Replace with your Discord server ID

class Scholarship(BaseModel):
    id: str
    title: str

@router.post("/create-channel/")
async def create_channel(
    scholarship: Scholarship, 
    db: Session = Depends(get_db),
    current_user: TokenData = Depends(get_current_user),  # Authorization handled here
):
    """
    Create a Discord channel for a scholarship or retrieve the existing one.
    """
    # Check if a discussion already exists for the scholarship
    existing_discussion = db.query(models.Discussion).filter(
        models.Discussion.scholarship_id == scholarship.id
    ).first()
    
    if existing_discussion:
        # If the channel already exists, return the link
        channel_id = existing_discussion.channel_id
        channel_link = f"https://discord.com/channels/{DISCORD_GUILD_ID}/{channel_id}"
        return {"status": "Channel already exists", "channel_link": channel_link}
    
    # Create a new Discord channel
    url = f"https://discord.com/api/v10/guilds/{DISCORD_GUILD_ID}/channels"
    headers = {
        "Authorization": f"Bot {DISCORD_BOT_TOKEN}",
        "Content-Type": "application/json",
    }
    payload = {
        "name": scholarship.title.replace(" ", "-").lower(),  # Channel name
        "type": 0,  # Text channel
        "topic": f"Discussion channel for {scholarship.title}"
    }
    
    response = requests.post(url, json=payload, headers=headers)
    
    if response.status_code == 201:
        # Save the new discussion to the database
        channel_data = response.json()
        new_discussion = models.Discussion(
            user_id=current_user.user_id,  # Link the discussion to the user
            scholarship_id=scholarship.id,  # Link the discussion to the scholarship
            channel_id=channel_data["id"],  # Discord channel ID
        )
        db.add(new_discussion)
        db.commit()
        
        # Return the newly created channel's link
        channel_link = f"https://discord.com/channels/{DISCORD_GUILD_ID}/{channel_data['id']}"
        return {"status": "Channel created", "channel_link": channel_link}
    else:
        # Handle Discord API errors
        raise HTTPException(status_code=response.status_code, detail=response.json())


@router.get("/api/scholarships")
async def get_scholarships(db: AsyncSession = Depends(get_db)):
    try:
        result = db.execute(select(models.Scholarship))
        scholarships = result.scalars().all()
        return scholarships
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/api/feedbacks")
async def get_feedback(db: AsyncSession = Depends(get_db)):
    try:
        result = db.execute(select(models.Feedback))
        scholarships = result.scalars().all()
        return scholarships
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/api/scholarship/filters")
async def get_scholarships_by_filters(
    location: str = None,
    field_of_study: str = None,
    funding_type: str = None,
    db: AsyncSession = Depends(get_db)
):
    query = select(models.Scholarship)
    if location:
        query = query.filter(models.Scholarship.location == location)
    if field_of_study:
        query = query.filter(models.Scholarship.field_of_study == field_of_study)
    if funding_type:
        query = query.filter(models.Scholarship.funding_type == funding_type)
    
    scholarships =  db.execute(query)
    return scholarships.scalars().all()

@router.get("/api/scholarship/{id}")
async def get_scholarship(id: UUID4, db: AsyncSession = Depends(get_db)):
    scholarship =  db.execute(select(models.Scholarship).filter(models.Scholarship.id == id))
    scholarship = scholarship.scalars().first()
    if not scholarship:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scholarship not found")
    return scholarship

@router.get("/api/feedback/{id}")
async def get_feedback(id: UUID4, db: AsyncSession = Depends(get_db)):
    feedback =  db.execute(select(models.Feedback).filter(models.Feedback.id == id))
    feedback = feedback.scalars().first()
    if not feedback:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scholarship not found")
    return feedback

@router.get("/api/reviews/top-feedback")
async def get_feedback_with_highest_likes(db: AsyncSession = Depends(get_db)):
    # Query to get the feedback with the highest like_count
    feedback_query = db.execute(
        select(models.Feedback)
        .order_by(models.Feedback.likes_count.desc())  # Order by like_count in descending order
    )
    
    # Fetch the feedback with the highest like count
    feedback = feedback_query.scalars().first()
    
    if not feedback:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No feedback found")
    
    # Return the feedback
    return feedback

@router.delete("/api/deletefeedback/{id}")
async def delete_feedback(id: UUID4, db: AsyncSession = Depends(get_db)):
    # Fetch the feedback record by id
    feedback = db.execute(select(models.Feedback).filter(models.Feedback.id == id))
    feedback = feedback.scalars().first()
    
    if not feedback:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Feedback not found")

    # Delete the associated likes first if necessary
    db.execute(delete(models.Likes).filter(models.Likes.feedback_id == id))
    
    # Delete the feedback record
    db.delete(feedback)
    db.commit()  # Commit the transaction
    
    return {"message": "Feedback deleted successfully"}


@router.put("/api/scholarship/{id}", response_model=schemas.ScholarshipCreate)
async def update_scholarship(
    id: UUID4,
    scholarship_data: schemas.ScholarshipCreate,
    db: AsyncSession = Depends(get_db),
    current_user: TokenData = Depends(get_current_user)
):
    scholarship =  db.execute(select(models.Scholarship).filter(models.Scholarship.id == id))
    scholarship = scholarship.scalars().first()
    if not scholarship:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scholarship not found")

    if current_user.user_type != 'partner' :
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="You do not have permission to update this scholarship")

    for key, value in scholarship_data.dict(exclude_unset=True).items():
        setattr(scholarship, key, value)

    db.commit()
    db.refresh(scholarship)
    return scholarship