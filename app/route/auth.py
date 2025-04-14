# app/route/auth.py

from typing import Optional
from app.db.model import Branch, Transaction
from app.db.model import Auth, EmailVerification, Token
from app.firebase.storage import delete_directory
from app.lib.user import generate_valid_password, refresh_access_token, create_refresh_token, decode_access_token, hash_password, verify_password, create_access_token, is_valid_password
from app.db.init import database
from datetime import datetime, timedelta
from fastapi import Form, Response, APIRouter, Body, HTTPException, Query, logger, status, Request, Response
from fastapi.security import OAuth2PasswordBearer
from email.mime.text import MIMEText
import secrets
import smtplib
from jose import ExpiredSignatureError, JWTError
from sqlalchemy.dialects.postgresql import insert
from dotenv import load_dotenv
import os

# Load environment variables
load_dotenv()

# Directory where images are stored on the server
MAIN_EMAIL = os.getenv("MAIN_EMAIL")
MAIN_EMAIL_PASSWORD = os.getenv("MAIN_EMAIL_PASSWORD")
AZURE_DOMAIN = "ftree-app-g9f2acaraya3dpay.canadacentral-01.azurewebsites.net"
AZURE_DOMAIN = os.getenv("AZURE_DOMAIN")
ACCESS_TOKEN_EXPIRE_MINUTES = 60

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="signin")
router = APIRouter()

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
    if not email or not code:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email and verification code are required.")

    verification = await database.fetch_one(EmailVerification.__table__.select().where(EmailVerification.email == email))

    if not verification:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No verification information found for this email.")
    
    if verification['code'] != code:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Verification code does not match.")
    
    created_at = verification['created_at']
    current_time = datetime.utcnow()
    if current_time - created_at > timedelta(minutes=15):
        query = EmailVerification.__table__.delete().where(EmailVerification.email == email)
        await database.execute(query)
        raise HTTPException(status_code=status.HTTP_410_GONE, detail="Verification code has expired.")

    query = EmailVerification.__table__.update().where(
        EmailVerification.email == email
    ).values(verified=datetime.utcnow())

    await database.execute(query)

    return {"message": "Email verification successful."}

# Signup API
@router.post("/signup/")
async def signup(data: dict = Body(...)):
    email = data.get('email')
    password = data.get('password')
    username = data.get('username')

    if not email or not password or not username:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email, password, and username are required.")
    
    try:
        is_valid_password(password)
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

    user = await database.fetch_one(Auth.__table__.select().where(Auth.email == email))
    if user:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Email is already in use.")

    verification = await database.fetch_one(EmailVerification.__table__.select().where(EmailVerification.email == email))
    if not verification or not verification['verified']:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Email verification is required.")
    
    hashed_password = hash_password(password)

    query = Auth.__table__.insert().values(
        username=username,
        email=email,
        password=hashed_password,
        create_time=datetime.utcnow(),
    )
    await database.execute(query)

    user = await database.fetch_one(Auth.__table__.select().where(Auth.email == email))
    uid = user['uid']

    query = Branch.__table__.insert().values(uid=uid, path='Home')
    await database.execute(query)

    query = EmailVerification.__table__.delete().where(EmailVerification.email == email)
    await database.execute(query)

    return {"message": "Signup successful."}

# Signin API
@router.post("/signin/")
async def signin(response: Response, data: dict = Body(...)):
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email and password are required.")

    user = await database.fetch_one(Auth.__table__.select().where(Auth.email == email))
    
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User does not exist.")

    if not verify_password(password, user['password']):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect password.")

    access_token = create_access_token(data={"sub": str(user['uid'])})
    refresh_token = create_refresh_token(data={"sub": str(user['uid'])})

    existing_token = await database.fetch_one(Token.__table__.select().where(Token.uid == user['uid']))

    if existing_token:
        query = Token.__table__.update().where(Token.uid == user['uid']).values(
            access_token=access_token,
            created_at=datetime.utcnow(),
            expires_at=datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        )
    else:
        query = Token.__table__.insert().values(
            uid=user['uid'],
            access_token=access_token,
            refresh_token=refresh_token,
            created_at=datetime.utcnow(),
            expires_at=datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        )
    await database.execute(query)

    response.set_cookie(
        key="refresh_token",
        value=refresh_token,
        httponly=True,
        secure=True,
        samesite="None",
        max_age=7 * 24 * 60 * 60,
        path="/",
        domain=AZURE_DOMAIN
    )

    response.set_cookie(
        key="access_token",
        value=access_token,
        httponly=True,
        secure=True,
        samesite="None",
        max_age=60 * 60,
        path="/",
        domain=AZURE_DOMAIN
    )

    return {
        'message': {
            'access_token': access_token,
            'email': user['email'],
            'username': user['username']
        }
    }

# Get user information API
@router.get("/get-user/")
async def get_user(request: Request):
    try:
        access_token = request.cookies.get("access_token")
        if not access_token:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Access token not found in cookies.")
    except ExpiredSignatureError:
        refresh_token = request.cookies.get("refresh_token")
        if not refresh_token:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Access token expired. Refresh token not found in cookies.")
        new_access_token = await refresh_access_token(refresh_token)
        access_token = new_access_token
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Access token not found in cookies.")

    try:
        uid = decode_access_token(access_token)
    except ExpiredSignatureError:
        refresh_token = request.cookies.get("refresh_token")
        if not refresh_token:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Access token expired. Refresh token not found in cookies.")
        new_access_token = await refresh_access_token(refresh_token)
        uid = decode_access_token(new_access_token)

    try:
        query = Auth.__table__.select().where(Auth.uid == uid)
        user_info = await database.fetch_one(query)

        if not user_info:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User information not found.")

        return {'message': user_info}

    except JWTError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token.",
            headers={"WWW-Authenticate": "Bearer"},
        ) from e

    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid request format: {str(e)}"
        ) from e

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Internal server error: {str(e)}"
        ) from e

# Delete account API
@router.delete("/delete-account/")
async def delete_account(request: Request):
    # Extract access token from cookies
    access_token = request.cookies.get("access_token")
    if not access_token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Access token not found")

    # Decode access token to get user ID
    try:
        uid = decode_access_token(access_token)
    except Exception:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication failed")

    # Delete user token from Token table
    try:
        delete_token_query = Token.__table__.delete().where(Token.uid == uid)
        await database.execute(delete_token_query)
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Failed to delete user token: {str(e)}")

    # Delete user-related transactions and images
    try:
        delete_transactions_query = Transaction.__table__.delete().where(Transaction.uid == uid)
        await database.execute(delete_transactions_query)
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Failed to delete user transactions: {str(e)}")

    # Delete 'uid' Directory from firebase storage
    try:
        await delete_directory(uid)
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Failed to delete user images: {str(e)}")

    # Delete user-related branches
    try:
        delete_branches_query = Branch.__table__.delete().where(Branch.uid == uid)
        await database.execute(delete_branches_query)
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Failed to delete user branches: {str(e)}")

    # Delete user from Auth table
    try:
        delete_user_query = Auth.__table__.delete().where(Auth.uid == uid)
        await database.execute(delete_user_query)
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Failed to delete user account: {str(e)}")

    return {"status": "success", "message": "Your account and associated data have been deleted successfully."}

# Signout API
@router.post("/signout/")
async def signout(request: Request, response: Response):
    # Extract access token from cookies
    access_token = request.cookies.get("access_token")
    if not access_token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Access token not found. Please log in.")

    # Decode access token to get user ID
    try:
        uid = decode_access_token(access_token)
    except HTTPException as e:
        raise HTTPException(status_code=e.status_code, detail=f"Error in token decoding: {e.detail}")
    except Exception:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to decode the access token.")

    # Delete user's token from Token table
    try:
        delete_token_query = Token.__table__.delete().where(Token.uid == uid)
        await database.execute(delete_token_query)
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Failed to delete the user's token: {str(e)}")

    # Delete access token and refresh token from cookies
    response.delete_cookie(key="access_token", path="/", domain="localhost")
    response.delete_cookie(key="refresh_token", path="/", domain="localhost")

    return {"status": "success", "message": "You have been signed out successfully."}

# Modify Password API
@router.put("/modify-password/")
async def modify_password(
    request: Request, 
    password: Optional[str] = Form(None)):

    # Extract access token from cookies
    access_token = request.cookies.get("access_token")
    if not access_token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Access token not found. Please log in.")

    # Decode access token to get user ID
    try:
        uid = decode_access_token(access_token)
    except HTTPException as e:
        raise HTTPException(status_code=e.status_code, detail=f"Error in token decoding: {e.detail}")
    except Exception:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to decode the access token.")

    # Extract password from request body
    try:
        is_valid_password(password)
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

    if not password:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Password is required.")

    # Hash the new password
    hashed_password = hash_password(password)

    # Update the password in the Auth table
    try:
        update_query = Auth.__table__.update().where(Auth.uid == uid).values(password=hashed_password)
        await database.execute(update_query)
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Failed to update the password: {str(e)}")

    return {"status": "success", "message": "Password updated successfully."}

# Update User Info
@router.put("/update-userinfo/")
async def update_user(
    request: Request, 
    username: Optional[str] = Form(None),
    useai: Optional[bool] = Form(None)):

    # Extract access token from cookies
    access_token = request.cookies.get("access_token")

    if not access_token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Access token not found. Please log in.")
    
    # Decode access token to get user ID
    try:
        uid = decode_access_token(access_token)
    except HTTPException as e:
        raise HTTPException(status_code=e.status_code, detail=f"Error in token decoding: {e.detail}")
    except Exception:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to decode the access token.")
    
    # Update user information
    try:
        update_query = Auth.__table__.update().where(Auth.uid == uid).values(
            username=username,
            useai=useai
        )
        await database.execute(update_query)
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Failed to update user information: {str(e)}")
    
    return {"status": "success", "message": "User information updated successfully."}

# Forget Password? -> Update Temporary Password and Send Email
@router.post("/forget-password/")
async def forget_password(data: dict = Body(...)):
    email = data.get('email')
    if not email:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email is required.")

    user = await database.fetch_one(Auth.__table__.select().where(Auth.email == email))
    # if not user: raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User does not exist.")

    # Generate temporary password
    temp_password = generate_valid_password(8)
    hashed_password = hash_password(temp_password)

    # Update the password in the Auth table
    try:
        update_query = Auth.__table__.update().where(Auth.email == email).values(password=hashed_password)
        await database.execute(update_query)
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Failed to update the password: {str(e)}")

    # Send temporary password via email
    try:
        msg = MIMEText(f'Your temporary password is: "{temp_password}"')
        msg['Subject'] = 'Temporary Password'
        msg['From'] = MAIN_EMAIL
        msg['To'] = email

        with smtplib.SMTP('smtp.gmail.com', 587) as server:
            server.starttls()
            server.login(MAIN_EMAIL, MAIN_EMAIL_PASSWORD)
            server.sendmail(MAIN_EMAIL, email, msg.as_string())
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to send temporary password email.")

    return {"status": "success", "message": "Temporary password sent to your email."}
