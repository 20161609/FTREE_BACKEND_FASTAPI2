# app/lib/transaction.py

import os
from fastapi import UploadFile, HTTPException
from uuid import uuid4
from pathlib import Path
from app.db.init import database
from app.db.model import Transaction
from dotenv import load_dotenv
import os

from app.firebase.storage import delete_image

load_dotenv()

# Delete transactions and associated receipt images
async def execute_del_transaction(uid: str, tid_list: list):
    try:
        delete_query = Transaction.__table__.delete().where(
            (Transaction.uid == uid) & 
            (Transaction.tid.in_(tid_list))
        ).returning(Transaction.__table__.c)
        
        delete_data = await database.fetch_all(delete_query)
        for data in delete_data:
            file_name = data['receipt']
            if not file_name:
                continue

            # file_path = f'{uid}/{file_name}'
            await delete_image(uid, file_name)
            

    except Exception as e:
        print("Failed to delete transaction from PostgreSQL\n" + str(e))
