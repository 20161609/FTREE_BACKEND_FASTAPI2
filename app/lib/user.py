# app/lib/user.py

from fastapi import HTTPException, status
from passlib.context import CryptContext
from datetime import datetime, timedelta
from jose import ExpiredSignatureError, JWTError, jwt
from dotenv import load_dotenv
import os

# Load environment variables from .env file
load_dotenv()

# JWT configuration
JWT_KEY = os.getenv('JWT_KEY')  # Secret key, managed via .env in production
ALGORITHM = "HS256"  # JWT signing algorithm
ACCESS_TOKEN_EXPIRE_MINUTES = 60  # Token expiration time (60 minutes)

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Hash the password
def hash_password(password: str) -> str:
    """Hashes the given password."""
    return pwd_context.hash(password)

# Verify the password
def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verifies the given password with the hashed password."""
    return pwd_context.verify(plain_password, hashed_password)

# Create access token with expiration
def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()  # Copy the input data to prepare it for the token
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)  

    # Set default expiration to 60 minutes
    to_encode.update({"exp": expire})  # Add expiration time to token
    encoded_jwt = jwt.encode(to_encode, JWT_KEY, algorithm=ALGORITHM)  # Generate the token
    return encoded_jwt

# Create refresh token with expiration
def create_refresh_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(days=7)  # Refresh token is valid for 7 days
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, JWT_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# Decode access token
def decode_access_token(token: str):
    try:
        # Decode the token and validate expiration
        payload = jwt.decode(token, JWT_KEY, algorithms=[ALGORITHM])
        
        # Extract user ID (sub) from the payload
        uid: str = payload.get("sub")
        
        # Raise error if sub is missing
        if uid is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token",
                headers={"WWW-Authenticate": "Bearer"},
            )
        
        # Return UID as integer
        return int(uid)
    
    # Handle expired token
    except ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Handle other JWT-related errors
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
            headers={"WWW-Authenticate": "Bearer"},
        )

# Decode refresh token
def decode_refresh_token(token: str):
    try:
        payload = jwt.decode(token, JWT_KEY, algorithms=[ALGORITHM])
        uid: str = payload.get("sub")
        if uid is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token",
                headers={"WWW-Authenticate": "Bearer"},
            )
        return int(uid)
    except ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
            headers={"WWW-Authenticate": "Bearer"},
        )

# Refresh access token using refresh token
def refresh_access_token(refresh_token: str):
    uid = decode_refresh_token(refresh_token)
    access_token = create_access_token(data={"sub": uid})
    return access_token
