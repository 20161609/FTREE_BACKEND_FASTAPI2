# app/route/db.py

from datetime import datetime
from operator import or_
from typing import List, Optional

from fastapi import APIRouter, Body, Depends, File, Form, HTTPException, Query, UploadFile, status

from app.firebase.storage import delete_image, get_image, get_image_url, save_image
from app.lib.branch import delete_branch_bid
from app.lib.transaction import execute_del_transaction
from app.db.crud import is_exist_branch
from app.db.model import Branch, Transaction
from app.db.init import database
from app.route.auth import get_current_uid

router = APIRouter()


# API to get user's branch information
@router.get("/get-tree/")
async def get_user_branches(uid: int = Depends(get_current_uid)):
    query = Branch.__table__.select().where(Branch.uid == int(uid))
    branches = await database.fetch_all(query)

    if not branches:
        query = (
            Branch.__table__
            .insert()
            .values(uid=uid, path="Home")
            .returning(Branch.__table__.c.bid)
        )
        bid = await database.execute(query)
        path = "Home"
        return {"message": [{"bid": bid, "path": path, "uid": uid}]}

    return {"message": branches}


# API to create a new branch
@router.post("/create-branch/")
async def create_branch(
    uid: int = Depends(get_current_uid),
    body: dict = Body(...),
):
    parent = body.get("parent")
    child = body.get("child")

    is_exist = await is_exist_branch(uid, parent)
    if not is_exist:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid parent path - {parent}",
        )

    path = parent + "/" + child
    already_exist = await is_exist_branch(uid, path)
    if already_exist:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Branch already exists - {path}",
        )

    query = Branch.__table__.insert().values(
        uid=uid,
        path=path,
    )
    await database.execute(query)
    return {"message": "Branch created successfully"}


# API to delete a branch
@router.delete("/delete-branch/")
async def delete_branch(
    uid: int = Depends(get_current_uid),
    branch: str = Query(...),
):
    is_exist = await is_exist_branch(uid, branch)
    if not is_exist:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Branch not found - {branch}",
        )

    # Retrieve list of bids to be deleted
    query = (
        Branch.__table__
        .select()
        .where(Branch.uid == uid)
        .where(or_(Branch.path == branch, Branch.path.like(f"{branch + '/'}%")))
    )
    temp = await database.fetch_all(query)
    branch_list = [x["path"] for x in temp]
    bid_list = [x["bid"] for x in temp]

    # Retrieve list of tids to be deleted
    query = (
        Transaction.__table__
        .select()
        .where(Transaction.uid == uid)
        .where(Transaction.branch.in_(branch_list))
    )
    temp = await database.fetch_all(query)
    tid_list = [x["tid"] for x in temp]

    # Delete transactions
    await execute_del_transaction(uid, tid_list)

    # Delete branches
    await delete_branch_bid(uid, bid_list)

    return {"message": "Branch deleted successfully"}


# API to view daily transactions within a branch
@router.get("/refer-daily-transaction/")
async def refer_daily_transaction(
    uid: int = Depends(get_current_uid),
    begin_date: str = Query(...),
    end_date: str = Query(...),
    branch: str = Query(...),
):
    try:
        begin_date_obj = datetime.strptime(begin_date, "%Y-%m-%d")
        end_date_obj = datetime.strptime(end_date, "%Y-%m-%d")
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid date format. Must be in YYYY-MM-DD format.",
        )

    query = (
        Transaction.__table__
        .select()
        .where(
            (Transaction.uid == uid)
            & (or_(Transaction.branch == branch, Transaction.branch.like(f"{branch + '/'}%")))
            & (Transaction.t_date >= begin_date_obj)
            & (Transaction.t_date <= end_date_obj)
        )
        .order_by(Transaction.t_date)
    )
    transactions = await database.fetch_all(query)
    return {"message": transactions}


# API to upload transaction data (with optional image)
@router.post("/upload-transaction/")
async def upload_transaction(
    uid: int = Depends(get_current_uid),
    t_date: str = Form(...),
    branch: str = Form(...),
    cashflow: int = Form(...),
    description: Optional[str] = Form(None),
    receipt: Optional[UploadFile] = File(None),
):
    try:
        t_date_obj = datetime.strptime(t_date, "%Y-%m-%d")
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid date format. Must be in YYYY-MM-DD format.",
        )

    receipt_path = None
    if receipt:
        try:
            receipt_path = await save_image(uid, receipt)
        except Exception:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to save the image.",
            )

    try:
        query = (
            Transaction.__table__
            .insert()
            .values(
                t_date=t_date_obj,
                branch=branch,
                cashflow=cashflow,
                description=description,
                receipt=receipt_path,
                c_date=datetime.utcnow(),
                uid=uid,
            )
            .returning(Transaction.__table__.c.tid)
        )
        await database.execute(query)
    except Exception as e:
        if receipt_path:
            try:
                await delete_image(uid, receipt_path)
            except Exception as e2:
                print("Error deleting image", e2)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to insert transaction." + str(e),
        )

    return {"message": "Transaction uploaded successfully."}


# API to retrieve image file by transaction ID (tid)
@router.get("/get-receipt/")
async def get_receipt(
    uid: int = Depends(get_current_uid),
    tid: int = Query(...),
):
    query = (
        Transaction.__table__
        .select()
        .where((Transaction.tid == tid) & (Transaction.uid == uid))
    )
    transaction = await database.fetch_one(query)
    if not transaction:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Transaction not found.")

    file_name = transaction.receipt
    if not file_name:
        return {"receipt": None}

    image_path = await get_image_url(uid, file_name)
    return image_path


# API to return multiple images compressed into a ZIP (현재는 URL 매핑 반환)
@router.get("/get-receipt-multiple/")
async def get_receipt_multiple(
    uid: int = Depends(get_current_uid),
    tid_list: List[int] = Query(...),
):
    query = (
        Transaction.__table__
        .select()
        .where(Transaction.tid.in_(tid_list))
        .where(Transaction.uid == uid)
    )
    transactions = await database.fetch_all(query)

    if not transactions:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Transactions not found.",
        )

    image_urls = {}
    for transaction in transactions:
        file_name = transaction.receipt
        if not file_name:
            continue

        try:
            image_url = await get_image(uid, file_name)
            if image_url:
                image_urls[transaction.tid] = image_url
        except Exception as e:
            print(f"Failed to get image from Firebase Storage\n{str(e)}")
            continue

    return image_urls


# API to modify a transaction
@router.put("/modify-transaction/")
async def modify_transaction(
    uid: int = Depends(get_current_uid),
    tid: int = Form(...),
    t_date: Optional[str] = Form(None),
    branch: Optional[str] = Form(None),
    cashflow: Optional[int] = Form(None),
    description: Optional[str] = Form(None),
    receipt: Optional[UploadFile] = File(None),
):
    query = (
        Transaction.__table__
        .select()
        .where((Transaction.tid == tid) & (Transaction.uid == uid))
    )
    transaction = await database.fetch_one(query)
    if not transaction:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Transaction not found.")

    update_data = {}
    if t_date:
        try:
            update_data["t_date"] = datetime.strptime(t_date, "%Y-%m-%d")
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid date format. Must be in YYYY-MM-DD format.",
            )
    if branch:
        update_data["branch"] = branch
    if cashflow is not None:
        update_data["cashflow"] = cashflow
    if description:
        update_data["description"] = description

    if receipt:
        if transaction.receipt:
            try:
                await delete_image(uid, transaction.receipt)
            except Exception as e:
                print("error deleting image", e)
        try:
            receipt_path = await save_image(uid, receipt)
            update_data["receipt"] = receipt_path
        except Exception:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to save the image.",
            )

    query = Transaction.__table__.update().where(Transaction.tid == tid).values(**update_data)
    await database.execute(query)

    return {"message": "Transaction successfully updated."}


# API to delete a transaction
@router.delete("/delete-transaction/")
async def delete_transaction(
    uid: int = Depends(get_current_uid),
    tid: int = Query(...),
):
    query = (
        Transaction.__table__
        .select()
        .where((Transaction.tid == tid) & (Transaction.uid == uid))
    )
    transaction = await database.fetch_one(query)

    if not transaction:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Transaction not found.")

    tid_value = transaction.tid
    await execute_del_transaction(uid, [tid_value])

    return {"message": "Transaction successfully deleted."}
