# app/route/auth.py

from typing import Optional
from datetime import datetime, timedelta
import os
import secrets
import smtplib

from email.mime.text import MIMEText
from fastapi import APIRouter, Body, Depends, Form, HTTPException, Query, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.dialects.postgresql import insert
from dotenv import load_dotenv

from app.db.init import database
from app.db.model import Auth, Branch, EmailVerification, Token, Transaction
from app.firebase.storage import delete_directory
from app.lib.user import (
    create_access_token,
    create_refresh_token,
    decode_access_token,
    generate_valid_password,
    hash_password,
    is_valid_password,
    verify_password,
)

# Load environment variables
load_dotenv()

MAIN_EMAIL = os.getenv("MAIN_EMAIL")
MAIN_EMAIL_PASSWORD = os.getenv("MAIN_EMAIL_PASSWORD")
ACCESS_TOKEN_EXPIRE_MINUTES = 60

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/signin/")
router = APIRouter()

# Get uid(Public)
async def get_current_uid(token: str = Depends(oauth2_scheme)) -> int:
    return decode_access_token(token)

# Send email verification code
@router.post("/verify-email/")
async def verify_email(data: dict = Body(...)):
    email = data.get('email')
    if not email:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email is required.")

    # Check for duplicate email
    user = await database.fetch_one(Auth.__table__.select().where(Auth.email == email))
    if user:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Email is already in use.")

    # Generate verification code
    code = secrets.token_hex(3)
    current_time = datetime.utcnow()

    # Insert or update code and timestamp in EmailVerification table
    query = insert(EmailVerification).values(
        code=code,
        email=email,
        created_at=current_time
    ).on_conflict_do_update(
        index_elements=['email'],
        set_={'code': code, 'created_at': current_time}
    )

    await database.execute(query)

    # Send verification email
    try:
        msg = MIMEText(f'Your verification code is: {code}')
        msg['Subject'] = 'Verification Code'
        msg['From'] = MAIN_EMAIL
        msg['To'] = email

        with smtplib.SMTP('smtp.gmail.com', 587) as server:
            server.starttls()
            server.login(MAIN_EMAIL, MAIN_EMAIL_PASSWORD)
            server.sendmail(MAIN_EMAIL, email, msg.as_string())
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to send verification email.")


# Verify the provided email and code
@router.get("/verify-email/")
async def check_verification_code(email: str = Query(...), code: str = Query(...)):
    # Bad Request
    if not email or not code:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email and verification code are required.")

    # Verification
    verification = await database.fetch_one(
        EmailVerification.__table__.select().where(EmailVerification.email == email)
    )
    if not verification:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No verification information found for this email.",
        )
    if verification["code"] != code:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Verification code does not match.",
        )
    created_at = verification["created_at"]

    # Send Email
    current_time = datetime.utcnow()
    if current_time - created_at > timedelta(minutes=15):
        query = EmailVerification.__table__.delete().where(EmailVerification.email == email)
        await database.execute(query)
        raise HTTPException(
            status_code=status.HTTP_410_GONE,
            detail="Verification code has expired.",
        )

    # Update DB.
    query = EmailVerification.__table__.update().where(
        EmailVerification.email == email
    ).values(verified=datetime.utcnow())
    await database.execute(query)

    return {"message": "Email verification successful."}


# Signup API
@router.post("/signup/")
async def signup(data: dict = Body(...)):
    # Get User's info
    email = data.get("email")
    password = data.get("password")
    username = data.get("username")
    if not email or not password or not username:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email, password, and username are required.",
        )
    try:
        is_valid_password(password)
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    user = await database.fetch_one(Auth.__table__.select().where(Auth.email == email))
    if user:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Email is already in use.")

    # Check if it can be signed up.
    verification = await database.fetch_one(
        EmailVerification.__table__.select().where(EmailVerification.email == email)
    )
    if not verification or not verification["verified"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Email verification is required.",
        )

    
    # Update DB and create account
    hashed_password = hash_password(password)
    query = Auth.__table__.insert().values(
        username=username,
        email=email,
        password=hashed_password,
        create_time=datetime.utcnow(),
    )
    await database.execute(query)
    user = await database.fetch_one(Auth.__table__.select().where(Auth.email == email))
    uid = user["uid"]
    query = Branch.__table__.insert().values(uid=uid, path="Home")
    await database.execute(query)
    query = EmailVerification.__table__.delete().where(EmailVerification.email == email)
    await database.execute(query)

    return {"message": "Signup successful."}


# Signin API
@router.post("/signin/")
async def signin(data: dict = Body(...)):
    # Get User input datas [EMAIL], [PW].
    email = data.get("email")
    password = data.get("password")
    if not email or not password:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email and password are required.",
        )
    
    # Check the validation of user inputed.
    user = await database.fetch_one(Auth.__table__.select().where(Auth.email == email))
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User does not exist.")

    if not verify_password(password, user["password"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect password.",
        )

    # DB update: get token
    access_token = create_access_token(data={"sub": str(user["uid"])})
    refresh_token = create_refresh_token(data={"sub": str(user["uid"])})
    existing_token = await database.fetch_one(
        Token.__table__.select().where(Token.uid == user["uid"])
    )
    if existing_token:
        query = Token.__table__.update().where(Token.uid == user["uid"]).values(
            access_token=access_token,
            created_at=datetime.utcnow(),
            expires_at=datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),
        )
    else:
        query = Token.__table__.insert().values(
            uid=user["uid"],
            access_token=access_token,
            refresh_token=refresh_token,
            created_at=datetime.utcnow(),
            expires_at=datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),
        )
    await database.execute(query)

    # Success
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "email": user["email"],
        "username": user["username"],
    }


# Get user information API with token
@router.get("/get-user/")
async def get_user(uid: int = Depends(get_current_uid)):
    query = Auth.__table__.select().where(Auth.uid == uid)
    user_info = await database.fetch_one(query)
    if not user_info:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, 
            detail="User information not found.")
    return {"message": user_info}


# Delete account API
@router.delete("/delete-account/")
async def delete_account(uid: int = Depends(get_current_uid)):
    # Delete user token from Token table
    try:
        delete_token_query = Token.__table__.delete().where(Token.uid == uid)
        await database.execute(delete_token_query)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to delete user token: {str(e)}",
        )

    # Delete user-related transactions and images
    try:
        delete_transactions_query = Transaction.__table__.delete().where(Transaction.uid == uid)
        await database.execute(delete_transactions_query)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to delete user transactions: {str(e)}",
        )

    try:
        await delete_directory(uid)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to delete user images: {str(e)}",
        )

    try:
        delete_branches_query = Branch.__table__.delete().where(Branch.uid == uid)
        await database.execute(delete_branches_query)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to delete user branches: {str(e)}",
        )

    try:
        delete_user_query = Auth.__table__.delete().where(Auth.uid == uid)
        await database.execute(delete_user_query)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to delete user account: {str(e)}",
        )

    return {"status": "success", "message": "Your account and associated data have been deleted successfully."}


# Signout API
@router.post("/signout/")
async def signout(uid: int = Depends(get_current_uid)):
    # DB delete: remove token from current user.
    try:
        delete_token_query = Token.__table__.delete().where(Token.uid == uid)
        await database.execute(delete_token_query)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to delete the user's token: {str(e)}",
        )

    # make the localStorage empty
    return {"status": "success", "message": "You have been signed out successfully."}


# Modify Password API
@router.put("/modify-password/")
async def modify_password(
    uid: int = Depends(get_current_uid),
    password: Optional[str] = Form(None),
):
    try:
        is_valid_password(password)
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

    if not password:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password is required.",
        )

    hashed_password = hash_password(password)

    try:
        update_query = Auth.__table__.update().where(Auth.uid == uid).values(password=hashed_password)
        await database.execute(update_query)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to update the password: {str(e)}",
        )

    return {"status": "success", "message": "Password updated successfully."}


# Update User Info
@router.put("/update-userinfo/")
async def update_user(
    uid: int = Depends(get_current_uid),
    username: Optional[str] = Form(None),
    useai: Optional[bool] = Form(None),
):
    try:
        update_query = Auth.__table__.update().where(Auth.uid == uid).values(
            username=username,
            useai=useai,
        )
        await database.execute(update_query)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to update user information: {str(e)}",
        )

    return {"status": "success", "message": "User information updated successfully."}


# Forget Password? -> Update Temporary Password and Send Email
@router.post("/forget-password/")
async def forget_password(data: dict = Body(...)):
    email = data.get("email")
    if not email:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email is required.")

    user = await database.fetch_one(Auth.__table__.select().where(Auth.email == email))
    # if not user:
    #     raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User does not exist.")

    # Generate temporary password
    temp_password = generate_valid_password(8)
    hashed_password = hash_password(temp_password)

    # Update the password in the Auth table
    try:
        update_query = Auth.__table__.update().where(Auth.email == email).values(password=hashed_password)
        await database.execute(update_query)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to update the password: {str(e)}",
        )

    # Send temporary password via email
    try:
        msg = MIMEText(f'Your temporary password is: "{temp_password}"')
        msg["Subject"] = "Temporary Password"
        msg["From"] = MAIN_EMAIL
        msg["To"] = email

        with smtplib.SMTP("smtp.gmail.com", 587) as server:
            server.starttls()
            server.login(MAIN_EMAIL, MAIN_EMAIL_PASSWORD)
            server.sendmail(MAIN_EMAIL, email, msg.as_string())
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to send temporary password email.",
        )

    return {"status": "success", "message": "Temporary password sent to your email."}
