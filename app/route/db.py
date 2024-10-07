# app/route/db.py

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
from dotenv import load_dotenv


router = APIRouter()

load_dotenv()
UPLOAD_DIRECTORY= os.getenv("UPLOAD_DIRECTORY")

# OAuth2PasswordBearer defines the endpoint to receive tokens.
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="signin")

# SECRET_KEY and ALGORITHM settings
JWT_KEY = os.getenv("JWT_KEY")
ALGORITHM = "HS256"

# API to get user's branch information
@router.get("/get-tree/")
async def get_user_branches(request: Request):
    # Extract access token from cookies
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

    # Extract uid from access token
    try:
        uid = decode_access_token(access_token)
    except ExpiredSignatureError:
        refresh_token = request.cookies.get("refresh_token")
        if not refresh_token:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Access token expired. Refresh token not found in cookies.")
        new_access_token = await refresh_access_token(refresh_token)
        uid = decode_access_token(new_access_token)

    # Retrieve branch information associated with the uid
    query = Branch.__table__.select().where(Branch.uid == int(uid))
    branches = await database.fetch_all(query)
    
    # If no branches are found, create Home Branch
    if not branches:
        query = Branch.__table__.insert().values(uid=uid, path='Home').returning(Branch.__table__.c.bid)
        bid = await database.execute(query)
        path = 'Home'
        return {"message": [{bid, path, uid}]}
    if not branches:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No branches found for this user.")
    
    return {"message": branches}

# API to create a new branch
@router.post("/create-branch/")
async def create_branch(
    request: Request,
    body: dict = Body(...)
):
    # Extract access token from cookies
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

    # Extract uid from access token
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

# API to delete a branch
@router.delete('/delete-branch/')
async def delete_branch(
    request: Request,
    branch: str = Query(...)
):
    # Extract access token from cookies
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
    
    # Extract uid from access token
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

    # Retrieve list of bids to be deleted
    query = Branch.__table__.select().where(Branch.uid == uid).where(
        or_(Branch.path == branch, Branch.path.like(f'{branch + '/'}%'))
    )
    temp = await database.fetch_all(query)
    branch_list = [x['path'] for x in temp]
    bid_list = [x['bid'] for x in temp]
    print('branch_list:', branch_list)

    # Retrieve list of tids to be deleted
    query = Transaction.__table__.select().where(Transaction.uid == uid).where(Transaction.branch.in_(branch_list))
    temp = await database.fetch_all(query)
    tid_list = [x['tid'] for x in temp]
    
    # Delete transactions
    await execute_del_tr(uid, tid_list)

    # Delete branches
    await delete_branch_bid(uid, bid_list)
    
    return {"message": "Branch deleted successfully"}

# API to view daily transactions within a branch
@router.get("/refer-daily-transaction/")
async def refer_daily_transaction(
    request: Request,
    begin_date: str = Query(...),
    end_date: str = Query(...),
    branch: str = Query(...)
):
    # Extract access token from cookies
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

    # Extract uid from access token
    try:
        uid = decode_access_token(access_token)
    except ExpiredSignatureError:
        refresh_token = request.cookies.get("refresh_token")
        if not refresh_token:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Access token expired. Refresh token not found in cookies.")
        new_access_token = await refresh_access_token(refresh_token)
        uid = decode_access_token(new_access_token)

    # Convert begin_date and end_date to datetime objects
    try:
        begin_date_obj = datetime.strptime(begin_date, "%Y-%m-%d")
        end_date_obj = datetime.strptime(end_date, "%Y-%m-%d")
    except ValueError:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid date format. Must be in YYYY-MM-DD format.")

    # Retrieve transactions within the specified date range and branch
    query = Transaction.__table__.select().where(
        (Transaction.uid == uid) &
        (or_(Transaction.branch == branch, Transaction.branch.like(f'{branch + '/'}%'))) &
        (Transaction.t_date >= begin_date_obj) &
        (Transaction.t_date <= end_date_obj)
    ).order_by(Transaction.t_date)
    transactions = await database.fetch_all(query)
    return {"message": transactions}

# API to upload transaction data (with optional image)
@router.post("/upload-transaction/")
async def upload_transaction(
    request: Request,
    t_date: str = Form(...),
    branch: str = Form(...),
    cashflow: int = Form(...),
    description: Optional[str] = Form(None),
    receipt: Optional[UploadFile] = File(None),
):
    # Extract access token from cookies
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
    
    # Extract uid from access token
    try:
        uid = decode_access_token(access_token)
    except ExpiredSignatureError:
        refresh_token = request.cookies.get("refresh_token")
        if not refresh_token:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Access token expired. Refresh token not found in cookies.")
        new_access_token = await refresh_access_token(refresh_token)
        uid = decode_access_token(new_access_token)

    # Convert date string to datetime object
    try:
        t_date_obj = datetime.strptime(t_date, "%Y-%m-%d")
    except ValueError:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid date format. Must be in YYYY-MM-DD format.")

    # Save image file
    receipt_path = None
    if receipt:
        try:
            receipt_path = await save_image(receipt, uid)
        except Exception as e:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to save the image.")

    # Insert new transaction
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

# API to retrieve image file by transaction ID (tid)
@router.get("/get-receipt/")
async def get_receipt(request: Request, tid: int = Query(...)):
    # Extract access token from cookies
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

    # Extract uid from access token
    try:
        uid = decode_access_token(access_token)
    except ExpiredSignatureError:
        refresh_token = request.cookies.get("refresh_token")
        if not refresh_token:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Access token expired. Refresh token not found in cookies.")
        new_access_token = await refresh_access_token(refresh_token)
        uid = decode_access_token(new_access_token)

    # Retrieve transaction by tid and uid
    query = Transaction.__table__.select().where((Transaction.tid == tid) & (Transaction.uid == uid))
    transaction = await database.fetch_one(query)
    if not transaction:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Transaction not found.")

    # Check if receipt path exists
    file_name = transaction.receipt

    if not file_name:
        return {"receipt": None}

    # Generate file path for the image
    dir_path = UPLOAD_DIRECTORY + str(uid)
    file_path = os.path.join(dir_path, file_name)

    # If the file does not exist
    if not os.path.exists(file_path):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Image file not found.")

    # Return the image file response
    return FileResponse(file_path)

# API to return multiple images compressed into a ZIP
@router.get("/get-receipt-multiple/")
async def get_receipt_multiple(
    request: Request,
    tid_list: List[int] = Query(...),
):
    # Extract access token from cookies
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

    # Extract uid from access token
    try:
        uid = decode_access_token(access_token)
    except ExpiredSignatureError:
        refresh_token = request.cookies.get("refresh_token")
        if not refresh_token:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Access token expired. Refresh token not found in cookies.")
        new_access_token = await refresh_access_token(refresh_token)
        uid = decode_access_token(new_access_token)

    # Retrieve transactions for tid_list and uid
    query = Transaction.__table__.select().where(Transaction.tid.in_(tid_list)).where(Transaction.uid == uid)
    transactions = await database.fetch_all(query)

    if not transactions:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Transactions not found.")

    # Create a ZIP file in memory
    zip_buffer = BytesIO()
    with zipfile.ZipFile(zip_buffer, "w") as zip_file:
        for transaction in transactions:
            file_name = transaction.receipt

            # Skip if no image is present
            if not file_name:
                continue

            # Generate file path for the image
            tid = transaction.tid

            dir_path = UPLOAD_DIRECTORY + str(uid)
            file_path = os.path.join(dir_path, file_name)
            # file_path = os.path.join(UPLOAD_DIRECTORY, os.path.basename(receipt_path))

            # Skip if the file does not exist
            if not os.path.exists(file_path):
                continue

            # Read the file and add it to the ZIP
            with open(file_path, "rb") as f:
                # Save the file as tid_filename.jpg
                zip_file.writestr(f"{tid}_{os.path.basename(file_path)}", f.read())

    # Return the ZIP file
    zip_buffer.seek(0)
    return StreamingResponse(zip_buffer, media_type="application/x-zip-compressed", headers={
        "Content-Disposition": "attachment; filename=receipts.zip"
    })

# API to modify a transaction
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
    # Extract access token from cookies
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
    
    # Extract uid from access token
    try:
        uid = decode_access_token(access_token)
    except ExpiredSignatureError:
        refresh_token = request.cookies.get("refresh_token")
        if not refresh_token:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Access token expired. Refresh token not found in cookies.")
        new_access_token = await refresh_access_token(refresh_token)
        uid = decode_access_token(new_access_token)

    # Check if the transaction exists for the given tid and uid
    query = Transaction.__table__.select().where((Transaction.tid == tid) & (Transaction.uid == uid))
    transaction = await database.fetch_one(query)
    if not transaction:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Transaction not found.")

    # Only update provided fields
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

    # Update image file if provided
    if receipt:
        if transaction.receipt:
            file_name = transaction.receipt
            file_path = os.path.join(UPLOAD_DIRECTORY + str(uid), file_name)
            await delete_image(file_path)

        try:
            receipt_path = await save_image(receipt, uid)
            update_data['receipt'] = receipt_path
        except Exception as e:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to save the image.")

    # Update the database
    query = Transaction.__table__.update().where(Transaction.tid == tid).values(**update_data)
    await database.execute(query)

    return {"message": "Transaction successfully updated."}

# API to delete a transaction
@router.delete("/delete-transaction/")
async def delete_transaction(
    request: Request,
    tid: int = Query(...),
):
    # Extract access token from cookies
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

    # Extract uid from access token
    try:
        uid = decode_access_token(access_token)
    except ExpiredSignatureError:
        refresh_token = request.cookies.get("refresh_token")
        if not refresh_token:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Access token expired. Refresh token not found in cookies.")
        new_access_token = await refresh_access_token(refresh_token)
        uid = decode_access_token(new_access_token)

    # Check if the transaction exists for the given tid and uid
    query = Transaction.__table__.select().where((Transaction.tid == tid) & (Transaction.uid == uid))
    transaction = await database.fetch_one(query)

    if not transaction:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Transaction not found.")

    tid = transaction.tid
    await execute_del_tr(uid, [tid])
    return {"message": "Transaction successfully deleted."}
