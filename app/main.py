# app/main.py

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.db.init import database
from app.route import auth, db
from app.route import test
from app.firebase.init import initialize_firebase
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

FRONT_URL = os.getenv("FRONT_URL")
BACK_URL = os.getenv("BACK_URL")

# Create FastAPI instance
app = FastAPI()

# CORS configuration (Bearer Token + Header -> No neccesary for credentials)
ALLOWED_ORIGINS = [
    FRONT_URL if FRONT_URL else "https://finance-tree.vercel.app",
    "http://localhost:3000",  # For local development
]

# Remove None & Duplication
ALLOWED_ORIGINS = list({o for o in ALLOWED_ORIGINS if o})

app.add_middleware(
    CORSMiddleware,
    allow_origins=['*'],
    allow_credentials=False,  # No cookie..
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize Firebase
initialize_firebase()

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

# Register routes
app.include_router(db.router, prefix="/db")
app.include_router(auth.router, prefix="/auth")
app.include_router(test.router, prefix="/test")

@app.get("/")
async def root():
    return {
        "message": "Version Code - 34",
        "FRONT": FRONT_URL,
        "BACK": BACK_URL,
    }
