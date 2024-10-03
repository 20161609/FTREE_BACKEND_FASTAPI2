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

router = APIRouter()
UPLOAD_DIRECTORY = "uploads/"  # Directory path to store images on the server

# OAuth2PasswordBearer defines the endpoint to receive the token
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="signin")

# Setting the SECRET_KEY and ALGORITHM
JWT_KEY = os.getenv("JWT_KEY")
ALGORITHM = "HS256"

# API to retrieve the user's branch information
@router.get("/get-tree/")
async def get_user_branches(request: Request):
    # Extract access token (from cookies)
    try:
        access_token = request.cookies.get("access_token")
        if not access_token:
            raise HTTPException(status_code=401, detail="Access token not found in cookies.")
    except ExpiredSignatureError:
        refresh_token = request.cookies.get("refresh_token")        
        if not refresh_token:
            raise HTTPException(status_code=401, detail="Access token expired. Refresh token not found in cookies.")
        new_access_token = await refresh_access_token(refresh_token)
        access_token = new_access_token
    except Exception as e:
        raise HTTPException(status_code=401, detail="Access token not found in cookies.")

    # Extract uid from the access token
    try:
        uid = decode_access_token(access_token)    
    except ExpiredSignatureError:
        refresh_token = request.cookies.get("refresh_token")        
        if not refresh_token:
            raise HTTPException(status_code=401, detail="Access token expired. Refresh token not found in cookies.")
        new_access_token = await refresh_access_token(refresh_token)
        uid = decode_access_token(new_access_token)

    # Fetch branch information associated with the uid
    query = Branch.__table__.select().where(Branch.uid == int(uid))
    branches = await database.fetch_all(query)
    
    if not branches:
        raise HTTPException(status_code=404, detail="No branches found for this user.")
    
    return {"message": branches}

# API to create a new branch
@router.post("/create-branch/")
async def create_branch(
    request: Request,  # Using Request object to read refresh token from cookies
    body: dict=Body(...)
    ):
    # Extract access token (from cookies)
    try:
        access_token = request.cookies.get("access_token")
        if not access_token:
            raise HTTPException(status_code=401, detail="Access token not found in cookies.")
    except ExpiredSignatureError:
        refresh_token = request.cookies.get("refresh_token")        
        if not refresh_token:
            raise HTTPException(status_code=401, detail="Access token expired. Refresh token not found in cookies.")
        new_access_token = await refresh_access_token(refresh_token)
        access_token = new_access_token
    except Exception as e:
        raise HTTPException(status_code=401, detail="Access token not found in cookies.")

    # Extract uid from the access token
    try:
        uid = decode_access_token(access_token)    
    except ExpiredSignatureError:
        refresh_token = request.cookies.get("refresh_token")        
        if not refresh_token:
            raise HTTPException(status_code=401, detail="Access token expired. Refresh token not found in cookies.")
        new_access_token = await refresh_access_token(refresh_token)
        uid = decode_access_token(new_access_token)

    parent = body.get("parent")
    child = body.get("child")
    is_exist = await is_exist_branch(uid, parent)
    if not is_exist:
        raise HTTPException(status_code=400, detail=f"not valid path - {parent}")

    path = parent + '/' + child
    already_exist = await is_exist_branch(uid, path)
    if already_exist:
        raise HTTPException(status_code=400, detail=f"already exist - {path}")
    
    query = Branch.__table__.insert().values(
        uid=uid,
        path=path
    )
    await database.execute(query)
    return {"message": "Branch created successfully"}

# API to delete a branch
@router.delete('/delete-branch/')
async def delete_branch(
    request: Request,  # Using Request object to read refresh token from cookies
    branch: str=Query(...)
    ):
    # Extract access token (from cookies)
    try:
        access_token = request.cookies.get("access_token")
        if not access_token:
            raise HTTPException(status_code=401, detail="Access token not found in cookies.")
    except ExpiredSignatureError:
        refresh_token = request.cookies.get("refresh_token")        
        if not refresh_token:
            raise HTTPException(status_code=401, detail="Access token expired. Refresh token not found in cookies.")
        new_access_token = await refresh_access_token(refresh_token)
        access_token = new_access_token
    except Exception as e:
        raise HTTPException(status_code=401, detail="Access token not found in cookies.")
    
    # Extract uid from the access token
    try:
        uid = decode_access_token(access_token)    
    except ExpiredSignatureError:
        refresh_token = request.cookies.get("refresh_token")        
        if not refresh_token:
            raise HTTPException(status_code=401, detail="Access token expired. Refresh token not found in cookies.")
        new_access_token = await refresh_access_token(refresh_token)
        uid = decode_access_token(new_access_token)

    is_exist = await is_exist_branch(uid, branch)
    if not is_exist:
        raise HTTPException(status_code=400, detail=f"not valid path - {branch}")

    # Get bid list to be removed
    query = Branch.__table__.select().where(Branch.uid == uid).where(
        or_(Branch.path == branch, Branch.path.like(f'{branch + '/'}%'))
    )
    temp = await database.fetch_all(query)
    branch_list = [x['path'] for x in temp]
    bid_list = [x['bid'] for x in temp]
    print('branch_list:', branch_list)

    # Get tid list to be removed
    query = Transaction.__table__.select().where(Transaction.uid == uid).where(Transaction.branch.in_(branch_list))
    temp = await database.fetch_all(query)
    tid_list = [x['tid'] for x in temp]
    
    # Delete transactions
    await execute_del_tr(uid, tid_list)

    # Delete branches
    await delete_branch_bid(uid, bid_list)
    
    return {"message": "Branch deleted successfully"}

# API to refer daily transactions within a branch
@router.get("/refer-daily-transaction/")
async def refer_daily_transaction(
    request: Request,  # Using Request object to read refresh token from cookies
    begin_date: str = Query(...),  # Start date as a query parameter
    end_date: str = Query(...),    # End date as a query parameter
    branch: str = Query(...),
):
    # Extract access token (from cookies)
    try:
        access_token = request.cookies.get("access_token")
        if not access_token:
            raise HTTPException(status_code=401, detail="Access token not found in cookies.")
    except ExpiredSignatureError:
        refresh_token = request.cookies.get("refresh_token")
        if not refresh_token:
            raise HTTPException(status_code=401, detail="Access token expired. Refresh token not found in cookies.")
        new_access_token = await refresh_access_token(refresh_token)
        access_token = new_access_token
    except Exception as e:
        raise HTTPException(status_code=401, detail="Access token not found in cookies.")

    # Extract uid from the access token
    try:
        uid = decode_access_token(access_token)
    except ExpiredSignatureError:
        refresh_token = request.cookies.get("refresh_token")
        if not refresh_token:
            raise HTTPException(status_code=401, detail="Access token expired. Refresh token not found in cookies.")
        new_access_token = await refresh_access_token(refresh_token)
        uid = decode_access_token(new_access_token)

    # Convert begin_date and end_date to datetime objects
    try:
        begin_date_obj = datetime.strptime(begin_date, "%Y-%m-%d")
        end_date_obj = datetime.strptime(end_date, "%Y-%m-%d")
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid date format. Must be in YYYY-MM-DD format.")

    # Query transactions within the date range and branch
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
    request: Request,  # Using Request object to read refresh token from cookies
    t_date: str = Form(...),              # Transaction date as string (e.g. '2024-10-02')
    branch: str = Form(...),              # Branch name
    cashflow: int = Form(...),            # Cashflow (positive for income, negative for outcome)
    description: Optional[str] = Form(None),  # Description (optional)
    receipt: Optional[UploadFile] = File(None),  # Image file (optional)
):
    # Extract access token (from cookies)
    try:
        access_token = request.cookies.get("access_token")
        if not access_token:
            raise HTTPException(status_code=401, detail="Access token not found in cookies.")
    except ExpiredSignatureError:
        refresh_token = request.cookies.get("refresh_token")        
        if not refresh_token:
            raise HTTPException(status_code=401, detail="Access token expired. Refresh token not found in cookies.")
        new_access_token = await refresh_access_token(refresh_token)
        access_token = new_access_token
    except Exception as e:
        raise HTTPException(status_code=401, detail="Access token not found in cookies.")
    
    # Extract uid from the access token
    try:
        uid = decode_access_token(access_token)    
    except ExpiredSignatureError:
        refresh_token = request.cookies.get("refresh_token")        
        if not refresh_token:
            raise HTTPException(status_code=401, detail="Access token expired. Refresh token not found in cookies.")
        new_access_token = await refresh_access_token(refresh_token)
        uid = decode_access_token(new_access_token)

    # Convert date string to datetime object
    t_date_obj = datetime.strptime(t_date, "%Y-%m-%d")

    # Save the image file
    receipt_path = None
    if receipt:
        receipt_path = await save_image(receipt, uid)  # Save the image file on the server and return its path

    # Insert a new transaction
    query = Transaction.__table__.insert().values(
        t_date=t_date_obj,
        branch=branch,
        cashflow=cashflow,
        description=description,
        receipt=receipt_path,  # Store the file path
        c_date=datetime.utcnow(),
        uid=uid
    ).returning(Transaction.__table__.c.tid)
    
    await database.execute(query)

    return {"message": "Transaction uploaded successfully."}

# API to retrieve an image file by transaction ID (tid)
@router.get("/get-receipt/")
async def get_receipt(request: Request, tid: int = Query(...)):
    # Extract access token (from cookies)
    try:
        access_token = request.cookies.get("access_token")
        if not access_token:
            raise HTTPException(status_code=401, detail="Access token not found in cookies.")
    except ExpiredSignatureError:
        refresh_token = request.cookies.get("refresh_token")        
        if not refresh_token:
            raise HTTPException(status_code=401, detail="Access token expired. Refresh token not found in cookies.")
        new_access_token = await refresh_access_token(refresh_token)
        access_token = new_access_token

    # Extract uid from the access token
    try:
        uid = decode_access_token(access_token)    
    except ExpiredSignatureError:
        refresh_token = request.cookies.get("refresh_token")        
        if not refresh_token:
            raise HTTPException(status_code=401, detail="Access token expired. Refresh token not found in cookies.")
        new_access_token = await refresh_access_token(refresh_token)
        uid = decode_access_token(new_access_token)

    # Retrieve the transaction by tid
    query = Transaction.__table__.select().where((Transaction.tid == tid) & (Transaction.uid == uid))
    transaction = await database.fetch_one(query)
    if not transaction:
        raise HTTPException(status_code=404, detail="Transaction not found.")

    # Check if the transaction has a receipt path
    receipt_path = transaction.receipt

    if not receipt_path:
        return {"receipt": None}

    # Generate the file path for the image
    file_path = os.path.join(UPLOAD_DIRECTORY, os.path.basename(receipt_path))

    # If the file doesn't exist, return 404
    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="Image file not found.")

    # Return the image file response
    return FileResponse(file_path)

# API to compress multiple images into a ZIP and return it
@router.get("/get-receipt-multiple/")
async def get_receipt_multiple(
    request: Request,  # Using Request object to read refresh token from cookies
    tid_list: List[int] = Query(...),     # List of transaction IDs (tid)
):
    # Extract access token (from cookies)
    try:
        access_token = request.cookies.get("access_token")
        if not access_token:
            raise HTTPException(status_code=401, detail="Access token not found in cookies.")
    except ExpiredSignatureError:
        refresh_token = request.cookies.get("refresh_token")        
        if not refresh_token:
            raise HTTPException(status_code=401, detail="Access token expired. Refresh token not found in cookies.")
        new_access_token = await refresh_access_token(refresh_token)
        access_token = new_access_token
    except Exception as e:
        raise HTTPException(status_code=401, detail="Access token not found in cookies.")
    

    # Extract uid from the access token
    try:
        uid = decode_access_token(access_token)
    except ExpiredSignatureError:
        refresh_token = request.cookies.get("refresh_token")        
        if not refresh_token:
            raise HTTPException(status_code=401, detail="Access token expired. Refresh token not found in cookies.")
        new_access_token = await refresh_access_token(refresh_token)
        uid = decode_access_token(new_access_token)


    # Fetch transactions matching the tid_list and uid
    query = Transaction.__table__.select().where(Transaction.tid.in_(tid_list)).where(Transaction.uid == uid)
    transactions = await database.fetch_all(query)

    if not transactions:
        raise HTTPException(status_code=404, detail="Transactions not found.")

    # Create ZIP file in memory
    zip_buffer = BytesIO()
    with zipfile.ZipFile(zip_buffer, "w") as zip_file:
        for transaction in transactions:
            receipt_path = transaction.receipt

            # Skip if no image exists
            if not receipt_path:
                continue

            # Generate the file path for the image
            tid = transaction.tid
            file_path = os.path.join(UPLOAD_DIRECTORY, os.path.basename(receipt_path))

            # Skip if the file doesn't exist
            if not os.path.exists(file_path):
                continue

            # Read the file and add it to the ZIP
            with open(file_path, "rb") as f:
                # Store the file with the format tid_filename.jpg
                zip_file.writestr(f"{tid}_{os.path.basename(file_path)}", f.read())

    # Return the ZIP file
    zip_buffer.seek(0)
    return StreamingResponse(zip_buffer, media_type="application/x-zip-compressed", headers={
        "Content-Disposition": "attachment; filename=receipts.zip"
    })

# API to modify a transaction
@router.put("/modify-transaction/")
async def modify_transaction(
    request: Request,  # Using Request object to read refresh token from cookies
    tid: int = Form(...),                 # Transaction ID to modify
    t_date: Optional[str] = Form(None),   # Optional field: Date
    branch: Optional[str] = Form(None),   # Optional field: Branch
    cashflow: Optional[int] = Form(None), # Optional field: Cashflow
    description: Optional[str] = Form(None), # Optional field: Description
    receipt: Optional[UploadFile] = File(None),  # Optional field: Image file
):
    # Extract access token (from cookies)
    try:
        access_token = request.cookies.get("access_token")
        if not access_token:
            raise HTTPException(status_code=401, detail="Access token not found in cookies.")
    except ExpiredSignatureError:
        refresh_token = request.cookies.get("refresh_token")        
        if not refresh_token:
            raise HTTPException(status_code=401, detail="Access token expired. Refresh token not found in cookies.")
        new_access_token = await refresh_access_token(refresh_token)
        access_token = new_access_token
    except Exception as e:
        raise HTTPException(status_code=401, detail="Access token not found in cookies.")
    
    # Extract uid from the access token
    try:
        uid = decode_access_token(access_token)    
    except ExpiredSignatureError:
        refresh_token = request.cookies.get("refresh_token")        
        if not refresh_token:
            raise HTTPException(status_code=401, detail="Access token expired. Refresh token not found in cookies.")
        new_access_token = await refresh_access_token(refresh_token)
        uid = decode_access_token(new_access_token)

    # Check if the transaction exists for the given tid and uid
    query = Transaction.__table__.select().where((Transaction.tid == tid) & (Transaction.uid == uid))
    transaction = await database.fetch_one(query)
    if not transaction:
        raise HTTPException(status_code=404, detail="Transaction not found.")

    # Update only the fields that are provided
    if t_date:
        try:
            transaction.t_date = datetime.strptime(t_date, "%Y-%m-%d")
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid date format. Must be in YYYY-MM-DD format.")
    
    if branch:
        transaction.branch = branch
    
    if cashflow is not None:
        transaction.cashflow = cashflow
    
    if description:
        transaction.description = description

    # Update the database
    query = Transaction.__table__.update().where(Transaction.tid == tid).values(
        t_date=transaction.t_date,
        branch=transaction.branch,
        cashflow=transaction.cashflow,
        description=transaction.description
    ).returning(Transaction.__table__.c)

    # If an image file is provided, update it
    if receipt:
        if transaction.receipt:
            await delete_image(transaction.receipt)
        receipt_path = await save_image(receipt, uid)
        transaction.receipt = receipt_path
        query = query.values(receipt=receipt_path)
        print("receipt updated")

    await database.execute(query)

    return {"message": "Transaction successfully updated.", "transaction": transaction}

# API to delete a transaction
@router.delete("/delete-transaction/")
async def delete_transaction(
    request: Request,  # Using Request object to read refresh token from cookies
    tid: int = Query(...),                 # Transaction ID to delete
):
    # Extract access token (from cookies)
    try:
        access_token = request.cookies.get("access_token")
        if not access_token:
            raise HTTPException(status_code=401, detail="Access token not found in cookies.")
    except ExpiredSignatureError:
        refresh_token = request.cookies.get("refresh_token")
        if not refresh_token:
            raise HTTPException(status_code=401, detail="Access token expired. Refresh token not found in cookies.")
        new_access_token = await refresh_access_token(refresh_token)
        access_token = new_access_token
    except Exception as e:
        raise HTTPException(status_code=401, detail="Access token not found in cookies.")

    # Extract uid from the access token
    try:
        uid = decode_access_token(access_token)    
    except ExpiredSignatureError:
        refresh_token = request.cookies.get("refresh_token")        
        if not refresh_token:
            raise HTTPException(status_code=401, detail="Access token expired. Refresh token not found in cookies.")
        new_access_token = await refresh_access_token(refresh_token)
        uid = decode_access_token(new_access_token)

    # Check if the transaction exists for the given tid and uid
    query = Transaction.__table__.select().where((Transaction.tid == tid) & (Transaction.uid == uid))
    transaction = await database.fetch_one(query)
    if not transaction:
        raise HTTPException(status_code=404, detail="Transaction not found.")

    tid = transaction.tid
    await execute_del_tr(uid, [tid])
    return {"message": "Transaction successfully deleted."}
