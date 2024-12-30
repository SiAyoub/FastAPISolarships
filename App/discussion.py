from sqlalchemy.orm import Session
from . import models, schemas

# Create a new discussion
def create_discussion(db: Session, discussion_data: schemas.DiscussionCreate):
    db_discussion = models.Discussion(
        discussion_link=discussion_data.discussion_link,
        scholarship_id=discussion_data.scholarship_id
    )
    db.add(db_discussion)
    db.commit()
    db.refresh(db_discussion)
    return db_discussion

# Get all discussions by scholarship
def get_discussions_by_scholarship(db: Session, scholarship_id: int):
    return db.query(models.Discussion).filter(models.Discussion.scholarship_id == scholarship_id).all()

# Get a scholarship by ID
def get_scholarship(db: Session, scholarship_id: int):
    return db.query(models.Scholarship).filter(models.Scholarship.id == scholarship_id).first()
