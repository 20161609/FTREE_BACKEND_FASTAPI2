# app/main.py

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.db.init import database
from app.route import auth, db
from fastapi.staticfiles import StaticFiles
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

FRONT_URL = os.getenv("FRONT_URL")
UPLOAD_DIRECTORY= os.getenv("UPLOAD_DIRECTORY")
# Create FastAPI instance
app = FastAPI()

# Set up uploads directory for image storage
if not os.path.exists(UPLOAD_DIRECTORY):
    os.makedirs(UPLOAD_DIRECTORY)

# CORS configuration to allow the specified frontend URL
app.add_middleware(
    CORSMiddleware,
    allow_origins=[FRONT_URL],  # Specify client domain
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Connect to the database on startup
@app.on_event("startup")
async def startup():
    print("Connecting to the database")
    await database.connect()

# Disconnect from the database on shutdown
@app.on_event("shutdown")
async def shutdown():
    print("Disconnecting from the database")
    await database.disconnect()

# Serve files from the "uploads" directory
app.mount("/uploads", StaticFiles(directory=UPLOAD_DIRECTORY), name="uploads")

# Register routes
app.include_router(db.router, prefix="/db")
app.include_router(auth.router, prefix="/auth")

@app.get("/")
async def root():
    return {"message": "Welcome to my FastAPI project (New version). Updated for JWT!"}
