from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import psycopg2
from psycopg2.extras import RealDictCursor
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from app.database import Base, SessionLocal
from app.models import User
from app.routers import router
# Initialize FastAPI app
app = FastAPI()

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Adjust for your frontend's URL in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Try to connect to the database
try:
    conn = psycopg2.connect(
        host='localhost',
        database='apisc',  # Ensure this matches the actual database name
        user='postgres',
        password='toor',
        cursor_factory=RealDictCursor
    )
    cursor = conn.cursor()
    print("Database connection was successful!")
except Exception as error:
    print("Connecting to the database failed.")
    print("Error:", error)

# Database URL and engine setup
DATABASE_URL = "postgresql://postgres:toor@localhost/te"
engine = create_engine(DATABASE_URL, echo=True)

# Ensure models are created
Base.metadata.create_all(bind=engine)  # This should create tables if they don't exist

# Dependency to get the database session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Include authentication routes
app.include_router(router)

# Health check route
@app.get("/health")
async def health_check():
    return {"status": "OK"}
