# app/lib/transaction.py

import os
from fastapi import UploadFile, HTTPException
from uuid import uuid4
from pathlib import Path
from app.db.init import database
from app.db.model import Transaction
from dotenv import load_dotenv
import os

load_dotenv()
UPLOAD_DIRECTORY = os.getenv("UPLOAD_DIRECTORY")

# Delete transactions and associated receipt images
async def execute_del_tr(uid: str, tid_list: list):
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

            file_path = os.path.join(UPLOAD_DIRECTORY, str(uid), file_name)
            if os.path.exists(file_path):
                os.remove(file_path)

    except Exception as e:
        print("Failed to delete transaction from PostgreSQL\n" + str(e))

# Save uploaded image to the server and return the file path
async def save_image(file: UploadFile, uid: str) -> str:
    # Extract file extension
    file_extension = Path(file.filename).suffix
    
    if file_extension not in [".jpg", ".jpeg", ".png"]:
        raise HTTPException(status_code=400, detail="Unsupported file format.")
    
    # Generate a unique file name using UUID
    file_name = f"{uuid4()}{file_extension}"
    dir_path = UPLOAD_DIRECTORY + str(uid)
    file_path = os.path.join(dir_path, file_name)

    # Create the directory if it doesn't exist
    os.makedirs(UPLOAD_DIRECTORY, exist_ok=True)

    # Save the file
    with open(file_path, "wb") as buffer:
        buffer.write(await file.read())

    return file_name  # This path should be stored in the database

# Delete the image file from the server
async def delete_image(file_path: str):
    if os.path.exists(file_path):
        os.remove(file_path)
        return {"status": True, "message": "Image deleted successfully."}

    return {"status": False, "message": "Image not found."}
