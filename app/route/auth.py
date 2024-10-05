from app.db.model import Branch, Transaction
from app.db.model import Auth, EmailVerification, Token
from app.lib.user import refresh_access_token, create_refresh_token, decode_access_token, hash_password, verify_password, create_access_token
from app.db.init import database
from datetime import datetime, timedelta
from fastapi import Response, APIRouter, Body, HTTPException, Query, status, Request, Response
from fastapi.security import OAuth2PasswordBearer
from email.mime.text import MIMEText
import secrets
import smtplib
from jose import ExpiredSignatureError, JWTError
from sqlalchemy.dialects.postgresql import insert
from dotenv import load_dotenv
import os

# 환경 변수 로드
load_dotenv()

# 서버에서 이미지가 저장되는 경로
MAIN_EMAIL = os.getenv("MAIN_EMAIL")
MAIN_EMAIL_PASSWORD = os.getenv("MAIN_EMAIL_PASSWORD")
UPLOAD_DIRECTORY = os.getenv("UPLOAD_DIRECTORY")
ACCESS_TOKEN_EXPIRE_MINUTES = 60

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="signin")
router = APIRouter()

# 이메일 인증 코드 발송
@router.post("/verify-email/")
async def verify_email(data: dict = Body(...)):
    email = data.get('email')
    if not email:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email is required.")

    # 이메일 중복 확인
    user = await database.fetch_one(Auth.__table__.select().where(Auth.email == email))
    if user:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Email is already in use.")

    # 인증 코드 생성
    code = secrets.token_hex(3)
    current_time = datetime.utcnow()

    # EmailVerification 테이블에 코드와 타임스탬프 삽입 또는 업데이트
    query = insert(EmailVerification).values(
        code=code,
        email=email,
        created_at=current_time
    ).on_conflict_do_update(
        index_elements=['email'],
        set_={'code': code, 'created_at': current_time}
    )

    await database.execute(query)

    # 인증 이메일 발송
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

# 제공된 이메일과 코드 검증
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

# 회원가입 API
@router.post("/signup/")
async def signup(data: dict = Body(...)):
    email = data.get('email')
    password = data.get('password')
    username = data.get('username')

    if not email or not password or not username:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email, password, and username are required.")
    
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

    query = Branch.__table__.insert().values(
        uid=uid,
        path='Home'
    )
    await database.execute(query)

    query = EmailVerification.__table__.delete().where(EmailVerification.email == email)
    await database.execute(query)

    return {"message": "Signup successful."}

# 로그인 API
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
        secure=False,
        samesite="Lax",
        max_age=7 * 24 * 60 * 60,
        path="/",
        domain="localhost"
    )

    response.set_cookie(
        key="access_token",
        value=access_token,
        httponly=True,
        secure=False,
        samesite="Lax",
        max_age=60 * 60,
        path="/",
        domain="localhost"
    )

    return {
        'message': {
            'access_token': access_token,
            'email': user['email'],
            'username': user['username']
        }
    }

# 사용자 정보 가져오기 API
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

# 계정 삭제 API
@router.delete("/delete-account/")
async def delete_account(request: Request):
    # 쿠키에서 액세스 토큰 추출
    access_token = request.cookies.get("access_token")
    if not access_token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Access token not found")

    # 액세스 토큰을 디코드하여 사용자 ID 가져오기
    try:
        uid = decode_access_token(access_token)
    except Exception:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication failed")

    # 사용자 관련 거래 및 이미지 삭제
    try:
        transaction_query = Transaction.__table__.select().where(Transaction.uid == uid)
        transactions = await database.fetch_all(transaction_query)
        
        for transaction in transactions:
            if transaction["receipt"]:
                receipt_path = os.path.join(UPLOAD_DIRECTORY, transaction["receipt"])
                if os.path.exists(receipt_path):
                    os.remove(receipt_path)
        
        delete_transactions_query = Transaction.__table__.delete().where(Transaction.uid == uid)
        await database.execute(delete_transactions_query)
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Failed to delete user transactions: {str(e)}")

    # 사용자 관련 브랜치 삭제
    try:
        delete_branches_query = Branch.__table__.delete().where(Branch.uid == uid)
        await database.execute(delete_branches_query)
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Failed to delete user branches: {str(e)}")

    # Auth 테이블에서 사용자 삭제
    try:
        delete_user_query = Auth.__table__.delete().where(Auth.uid == uid)
        await database.execute(delete_user_query)
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Failed to delete user account: {str(e)}")

    return {"status": "success", "message": "Your account and associated data have been deleted successfully."}

# 로그아웃 API
@router.post("/signout/")
async def signout(request: Request, response: Response):
    # 쿠키에서 액세스 토큰 추출
    access_token = request.cookies.get("access_token")
    if not access_token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Access token not found. Please log in.")

    # 액세스 토큰을 디코드하여 사용자 ID 가져오기
    try:
        uid = decode_access_token(access_token)
    except HTTPException as e:
        raise HTTPException(status_code=e.status_code, detail=f"Error in token decoding: {e.detail}")
    except Exception:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to decode the access token.")

    # 토큰 테이블에서 사용자 토큰 삭제
    try:
        delete_token_query = Token.__table__.delete().where(Token.uid == uid)
        await database.execute(delete_token_query)
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Failed to delete the user's token: {str(e)}")

    # 쿠키에서 액세스 토큰 및 리프레시 토큰 삭제
    response.delete_cookie(key="access_token", path="/", domain="localhost")
    response.delete_cookie(key="refresh_token", path="/", domain="localhost")

    return {"status": "success", "message": "You have been signed out successfully."}
