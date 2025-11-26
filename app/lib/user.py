# app/lib/user.py

import random
import string
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

# Is Valid Password?
def is_valid_password(password: str):
    """Checks if the password meets the minimum requirements."""
    # Condition1. Password must be at least 8 characters long
    condition1 = len(password) >= 8
    if not condition1:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password must be at least 8 characters long",
        )
    
    # Condition 2. Password must contain at least one lowercase letter
    condition2 = any(char.islower() for char in password)
    if not condition2:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password must contain at least one lowercase letter",
        )
    
    # Condition 3. Special Symbol Check -> !@#$%^&*()-+ (Valid Symbols)
    # Any sympol other than the valid symbols will raise an error
    # But Digit and Alphabet are allowed
    valid_simbols = "!@#$%^&*-+"
    condition3 = all(char.isalnum() or char in valid_simbols for char in password)
    if not condition3:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password must contain only valid special symbols: !@#$%^&*-+",
        )

    # Condition4. Password must contain at least one number
    condition4 = any(char.isdigit() for char in password)
    if not condition4:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password must contain at least one number",
        )

# Generate a valid password
def generate_valid_password(length=8):
    # ASCII lowercase + digits
    if length < 8:
        raise ValueError("Password length must be at least 8 characters")
    
    lowercase = string.ascii_lowercase
    digits = string.digits

    password = [
        random.choice(lowercase),
        random.choice(digits)
    ]

    all_valid_characters = lowercase + digits
    password += random.choices(all_valid_characters, k=length - len(password))

    random.shuffle(password)
    return ''.join(password)
