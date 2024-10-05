import os
import zipfile
from io import BytesIO
from datetime import datetime
from typing import List, Optional
from operator import or_

from jose import ExpiredSignatureError
from fastapi import APIRouter, Depends, HTTPException, Request, Form, File, UploadFile, Query, Body, status
from fastapi.responses import StreamingResponse, FileResponse
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session

from app.lib.branch import delete_branch_bid
from app.lib.transaction import delete_image, execute_del_tr, save_image
from app.lib.user import refresh_access_token, decode_access_token
from app.db.crud import is_exist_branch
from app.db.model import Transaction, Branch
from app.db.init import database

router = APIRouter()
UPLOAD_DIRECTORY = "uploads/"  # 서버에서 이미지를 저장할 디렉토리 경로

# OAuth2PasswordBearer는 토큰을 받을 엔드포인트를 정의합니다.
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="signin")

# SECRET_KEY와 ALGORITHM 설정
JWT_KEY = os.getenv("JWT_KEY")
ALGORITHM = "HS256"

# 사용자의 브랜치 정보를 가져오는 API
@router.get("/get-tree/")
async def get_user_branches(request: Request):
    # 액세스 토큰 추출 (쿠키에서)
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
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to retrieve access token.")

    # 액세스 토큰에서 uid 추출
    try:
        uid = decode_access_token(access_token)
    except ExpiredSignatureError:
        refresh_token = request.cookies.get("refresh_token")
        if not refresh_token:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Access token expired. Refresh token not found in cookies.")
        new_access_token = await refresh_access_token(refresh_token)
        uid = decode_access_token(new_access_token)

    # uid와 연관된 브랜치 정보 가져오기
    query = Branch.__table__.select().where(Branch.uid == int(uid))
    branches = await database.fetch_all(query)
    
    if not branches:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No branches found for this user.")
    
    return {"message": branches}

# 새로운 브랜치를 생성하는 API
@router.post("/create-branch/")
async def create_branch(
    request: Request,
    body: dict = Body(...)
):
    # 액세스 토큰 추출 (쿠키에서)
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
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to retrieve access token.")

    # 액세스 토큰에서 uid 추출
    try:
        uid = decode_access_token(access_token)
    except ExpiredSignatureError:
        refresh_token = request.cookies.get("refresh_token")
        if not refresh_token:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Access token expired. Refresh token not found in cookies.")
        new_access_token = await refresh_access_token(refresh_token)
        uid = decode_access_token(new_access_token)

    parent = body.get("parent")
    child = body.get("child")
    is_exist = await is_exist_branch(uid, parent)
    if not is_exist:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Invalid parent path - {parent}")

    path = parent + '/' + child
    already_exist = await is_exist_branch(uid, path)
    if already_exist:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=f"Branch already exists - {path}")
    
    query = Branch.__table__.insert().values(
        uid=uid,
        path=path
    )
    await database.execute(query)
    return {"message": "Branch created successfully"}

# 브랜치를 삭제하는 API
@router.delete('/delete-branch/')
async def delete_branch(
    request: Request,
    branch: str = Query(...)
):
    # 액세스 토큰 추출 (쿠키에서)
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
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to retrieve access token.")
    
    # 액세스 토큰에서 uid 추출
    try:
        uid = decode_access_token(access_token)
    except ExpiredSignatureError:
        refresh_token = request.cookies.get("refresh_token")
        if not refresh_token:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Access token expired. Refresh token not found in cookies.")
        new_access_token = await refresh_access_token(refresh_token)
        uid = decode_access_token(new_access_token)

    is_exist = await is_exist_branch(uid, branch)
    if not is_exist:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Branch not found - {branch}")

    # 삭제할 bid 목록 가져오기
    query = Branch.__table__.select().where(Branch.uid == uid).where(
        or_(Branch.path == branch, Branch.path.like(f'{branch + '/'}%'))
    )
    temp = await database.fetch_all(query)
    branch_list = [x['path'] for x in temp]
    bid_list = [x['bid'] for x in temp]
    print('branch_list:', branch_list)

    # 삭제할 tid 목록 가져오기
    query = Transaction.__table__.select().where(Transaction.uid == uid).where(Transaction.branch.in_(branch_list))
    temp = await database.fetch_all(query)
    tid_list = [x['tid'] for x in temp]
    
    # 거래 삭제
    await execute_del_tr(uid, tid_list)

    # 브랜치 삭제
    await delete_branch_bid(uid, bid_list)
    
    return {"message": "Branch deleted successfully"}

# 브랜치 내의 일일 거래를 조회하는 API
@router.get("/refer-daily-transaction/")
async def refer_daily_transaction(
    request: Request,
    begin_date: str = Query(...),
    end_date: str = Query(...),
    branch: str = Query(...),
):
    # 액세스 토큰 추출 (쿠키에서)
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
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to retrieve access token.")

    # 액세스 토큰에서 uid 추출
    try:
        uid = decode_access_token(access_token)
    except ExpiredSignatureError:
        refresh_token = request.cookies.get("refresh_token")
        if not refresh_token:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Access token expired. Refresh token not found in cookies.")
        new_access_token = await refresh_access_token(refresh_token)
        uid = decode_access_token(new_access_token)

    # begin_date와 end_date를 datetime 객체로 변환
    try:
        begin_date_obj = datetime.strptime(begin_date, "%Y-%m-%d")
        end_date_obj = datetime.strptime(end_date, "%Y-%m-%d")
    except ValueError:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid date format. Must be in YYYY-MM-DD format.")

    # 지정된 날짜 범위와 브랜치 내의 거래 조회
    query = Transaction.__table__.select().where(
        (Transaction.uid == uid) &
        (or_(Transaction.branch == branch, Transaction.branch.like(f'{branch + '/'}%'))) &
        (Transaction.t_date >= begin_date_obj) &
        (Transaction.t_date <= end_date_obj)
    ).order_by(Transaction.t_date)
    transactions = await database.fetch_all(query)

    if not transactions:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No transactions found for the given criteria.")

    return {"message": transactions}

# 거래 데이터 업로드 API (이미지 옵션 포함)
@router.post("/upload-transaction/")
async def upload_transaction(
    request: Request,
    t_date: str = Form(...),
    branch: str = Form(...),
    cashflow: int = Form(...),
    description: Optional[str] = Form(None),
    receipt: Optional[UploadFile] = File(None),
):
    # 액세스 토큰 추출 (쿠키에서)
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
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to retrieve access token.")
    
    # 액세스 토큰에서 uid 추출
    try:
        uid = decode_access_token(access_token)
    except ExpiredSignatureError:
        refresh_token = request.cookies.get("refresh_token")
        if not refresh_token:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Access token expired. Refresh token not found in cookies.")
        new_access_token = await refresh_access_token(refresh_token)
        uid = decode_access_token(new_access_token)

    # 날짜 문자열을 datetime 객체로 변환
    try:
        t_date_obj = datetime.strptime(t_date, "%Y-%m-%d")
    except ValueError:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid date format. Must be in YYYY-MM-DD format.")

    # 이미지 파일 저장
    receipt_path = None
    if receipt:
        try:
            receipt_path = await save_image(receipt, uid)
        except Exception as e:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to save the image.")

    # 새로운 거래 삽입
    query = Transaction.__table__.insert().values(
        t_date=t_date_obj,
        branch=branch,
        cashflow=cashflow,
        description=description,
        receipt=receipt_path,
        c_date=datetime.utcnow(),
        uid=uid
    ).returning(Transaction.__table__.c.tid)
    
    await database.execute(query)

    return {"message": "Transaction uploaded successfully."}

# 거래 ID(tid)로 이미지 파일을 가져오는 API
@router.get("/get-receipt/")
async def get_receipt(request: Request, tid: int = Query(...)):
    # 액세스 토큰 추출 (쿠키에서)
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

    # 액세스 토큰에서 uid 추출
    try:
        uid = decode_access_token(access_token)
    except ExpiredSignatureError:
        refresh_token = request.cookies.get("refresh_token")
        if not refresh_token:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Access token expired. Refresh token not found in cookies.")
        new_access_token = await refresh_access_token(refresh_token)
        uid = decode_access_token(new_access_token)

    # tid로 거래 조회
    query = Transaction.__table__.select().where((Transaction.tid == tid) & (Transaction.uid == uid))
    transaction = await database.fetch_one(query)
    if not transaction:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Transaction not found.")

    # 거래에 영수증 경로가 있는지 확인
    receipt_path = transaction.receipt

    if not receipt_path:
        return {"receipt": None}

    # 이미지의 파일 경로 생성
    file_path = os.path.join(UPLOAD_DIRECTORY, os.path.basename(receipt_path))

    # 파일이 존재하지 않는 경우
    if not os.path.exists(file_path):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Image file not found.")

    # 이미지 파일 응답 반환
    return FileResponse(file_path)

# 여러 이미지를 ZIP으로 압축하여 반환하는 API
@router.get("/get-receipt-multiple/")
async def get_receipt_multiple(
    request: Request,
    tid_list: List[int] = Query(...),
):
    # 액세스 토큰 추출 (쿠키에서)
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
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to retrieve access token.")

    # 액세스 토큰에서 uid 추출
    try:
        uid = decode_access_token(access_token)
    except ExpiredSignatureError:
        refresh_token = request.cookies.get("refresh_token")
        if not refresh_token:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Access token expired. Refresh token not found in cookies.")
        new_access_token = await refresh_access_token(refresh_token)
        uid = decode_access_token(new_access_token)

    # tid_list와 uid에 해당하는 거래 조회
    query = Transaction.__table__.select().where(Transaction.tid.in_(tid_list)).where(Transaction.uid == uid)
    transactions = await database.fetch_all(query)

    if not transactions:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Transactions not found.")

    # 메모리에 ZIP 파일 생성
    zip_buffer = BytesIO()
    with zipfile.ZipFile(zip_buffer, "w") as zip_file:
        for transaction in transactions:
            receipt_path = transaction.receipt

            # 이미지가 없는 경우 건너뜀
            if not receipt_path:
                continue

            # 이미지의 파일 경로 생성
            tid = transaction.tid
            file_path = os.path.join(UPLOAD_DIRECTORY, os.path.basename(receipt_path))

            # 파일이 존재하지 않는 경우 건너뜀
            if not os.path.exists(file_path):
                continue

            # 파일을 읽어 ZIP에 추가
            with open(file_path, "rb") as f:
                # 파일을 tid_filename.jpg 형식으로 저장
                zip_file.writestr(f"{tid}_{os.path.basename(file_path)}", f.read())

    # ZIP 파일 반환
    zip_buffer.seek(0)
    return StreamingResponse(zip_buffer, media_type="application/x-zip-compressed", headers={
        "Content-Disposition": "attachment; filename=receipts.zip"
    })

# 거래를 수정하는 API
@router.put("/modify-transaction/")
async def modify_transaction(
    request: Request,
    tid: int = Form(...),
    t_date: Optional[str] = Form(None),
    branch: Optional[str] = Form(None),
    cashflow: Optional[int] = Form(None),
    description: Optional[str] = Form(None),
    receipt: Optional[UploadFile] = File(None),
):
    # 액세스 토큰 추출 (쿠키에서)
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
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to retrieve access token.")
    
    # 액세스 토큰에서 uid 추출
    try:
        uid = decode_access_token(access_token)
    except ExpiredSignatureError:
        refresh_token = request.cookies.get("refresh_token")
        if not refresh_token:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Access token expired. Refresh token not found in cookies.")
        new_access_token = await refresh_access_token(refresh_token)
        uid = decode_access_token(new_access_token)

    # tid와 uid에 해당하는 거래가 존재하는지 확인
    query = Transaction.__table__.select().where((Transaction.tid == tid) & (Transaction.uid == uid))
    transaction = await database.fetch_one(query)
    if not transaction:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Transaction not found.")

    # 제공된 필드만 업데이트
    update_data = {}
    if t_date:
        try:
            update_data['t_date'] = datetime.strptime(t_date, "%Y-%m-%d")
        except ValueError:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid date format. Must be in YYYY-MM-DD format.")
    if branch:
        update_data['branch'] = branch
    if cashflow is not None:
        update_data['cashflow'] = cashflow
    if description:
        update_data['description'] = description

    # 이미지 파일이 제공된 경우 업데이트
    if receipt:
        if transaction.receipt:
            await delete_image(transaction.receipt)
        try:
            receipt_path = await save_image(receipt, uid)
            update_data['receipt'] = receipt_path
        except Exception as e:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to save the image.")

    # 데이터베이스 업데이트
    query = Transaction.__table__.update().where(Transaction.tid == tid).values(**update_data)
    await database.execute(query)

    return {"message": "Transaction successfully updated."}

# 거래를 삭제하는 API
@router.delete("/delete-transaction/")
async def delete_transaction(
    request: Request,
    tid: int = Query(...),
):
    # 액세스 토큰 추출 (쿠키에서)
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
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to retrieve access token.")

    # 액세스 토큰에서 uid 추출
    try:
        uid = decode_access_token(access_token)
    except ExpiredSignatureError:
        refresh_token = request.cookies.get("refresh_token")
        if not refresh_token:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Access token expired. Refresh token not found in cookies.")
        new_access_token = await refresh_access_token(refresh_token)
        uid = decode_access_token(new_access_token)

    # tid와 uid에 해당하는 거래가 존재하는지 확인
    query = Transaction.__table__.select().where((Transaction.tid == tid) & (Transaction.uid == uid))
    transaction = await database.fetch_one(query)
    if not transaction:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Transaction not found.")

    tid = transaction.tid
    await execute_del_tr(uid, [tid])
    return {"message": "Transaction successfully deleted."}
