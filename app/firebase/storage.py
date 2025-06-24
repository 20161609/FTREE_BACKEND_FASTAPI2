# app/firebase/storage.py

import base64
import hashlib
from pathlib import Path
import secrets
from uuid import uuid4

from fastapi import UploadFile
from firebase_admin import storage
from datetime import datetime

def get_hashed_uid(uid: str) -> str:
    # Hash UID with SHA256 to make it unique and not exposed
    hash_object = hashlib.sha256(uid.encode())
    return hash_object.hexdigest()

async def delete_storage_uid(uid: str):
    # Get File Name Format
    hashed_uid = get_hashed_uid(uid)
    basic_file_format = f'{hashed_uid}_'

    # Delete All files from firebase storage, which has name like 'basic_file_format%'
    bucket = storage.bucket()
    blobs = bucket.list_blobs()
    for blob in blobs:
        if basic_file_format in blob.name:
            blob.delete()
            print(f'File {blob.name} deleted')

async def save_image(uid: str, receipt: UploadFile) -> str:
    # Extract file extension
    file_extension = Path(receipt.filename).suffix
    file_name = f"{uuid4()}{file_extension}"
    dir_path = f"{uid}/{file_name}"

    try:
        bucket = storage.bucket()
        blob = bucket.blob(dir_path)
        blob.upload_from_string(receipt.file.read(), content_type='image/png')
        return file_name
    except Exception as e:
        print(f"Failed to upload image to Firebase Storage\n{str(e)}")
        return None

async def delete_image(uid: str, file_name: str) -> str:
    try:
        bucket = storage.bucket()
        blob = bucket.blob(f"{uid}/{file_name}")
        blob.delete()
        return {"status": True, "message": "Image deleted successfully."}
    except Exception as e:
        print(f"Failed to delete image from Firebase Storage\n{str(e)}")
        return None

async def get_image_url(uid: str, file_name: str) -> str:
    try:
        bucket = storage.bucket()
        blob = bucket.blob(f"{uid}/{file_name}")
        blob.make_public()
        return blob.public_url
    except Exception as e:
        print(f"Failed to get image from Firebase Storage\n{str(e)}")
        return None
    
async def get_image(uid: str, file_name: str) -> str:
    file_path = f"{uid}/{file_name}"
    bucket = storage.bucket()
    blob = bucket.blob(file_path)
    image = blob.download_as_bytes()
    return base64.b64encode(image).decode('utf-8')

async def delete_directory(uid: str):
    directory_path = f"{uid}/"
    bucket = storage.bucket()
    blobs = bucket.list_blobs(prefix=directory_path)

    for blob in blobs:
        print(f'Deleting file: {blob.name}')
        blob.delete()

    print(f'Directory {directory_path} and its contents have been deleted.')
