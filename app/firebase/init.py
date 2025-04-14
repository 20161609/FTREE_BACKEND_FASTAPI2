# app/firebase/init.py

import firebase_admin
from firebase_admin import credentials, auth, db, storage
from dotenv import load_dotenv
import os

# Environment variables
load_dotenv()
# SERVICE_ACCOUNT_KEY_PATH = os.getenv("SERVICE_ACCOUNT_KEY_PATH")
FIREBASE_DATABASE_URL=os.getenv("FIREBASE_DATABASE_URL")
FIREBASE_STORAGE_URL=os.getenv("FIREBASE_STORAGE_URL")
FIREBASE_STORAGE_BUCKET = os.getenv("FIREBASE_STORAGE_BUCKET")
FIREBASE_TYPE = os.getenv("FIREBASE_TYPE")
FIREBASE_PROJECT_ID = os.getenv("FIREBASE_PROJECT_ID")
FIREBASE_PRIVATE_KEY_ID = os.getenv("FIREBASE_PRIVATE_KEY_ID")
FIREBASE_PRIVATE_KEY = os.getenv("FIREBASE_PRIVATE_KEY").replace('\\n', '\n')
FIREBASE_CLIENT_EMAIL = os.getenv("FIREBASE_CLIENT_EMAIL")
FIREBASE_CLIENT_ID = os.getenv("FIREBASE_CLIENT_ID")
FIREBASE_AUTH_URI = os.getenv("FIREBASE_AUTH_URI")
FIREBASE_TOKEN_URI = os.getenv("FIREBASE_TOKEN_URI")
FIREBASE_AUTH_PROVIDER_X509_CERT_URL = os.getenv("FIREBASE_AUTH_PROVIDER_X509_CERT_URL")
FIREBASE_CLIENT_X509_CERT_URL = os.getenv("FIREBASE_CLIENT_X509_CERT_URL")
FIREBASE_UNIVERSE_DOMAIN = os.getenv("FIREBASE_UNIVERSE_DOMAIN")


# Firebase App initialization
def initialize_firebase():
    if not firebase_admin._apps:
        serviceAccountKey = {
            "type": FIREBASE_TYPE,
            "project_id": FIREBASE_PROJECT_ID,
            "private_key_id": FIREBASE_PRIVATE_KEY_ID,
            "private_key": FIREBASE_PRIVATE_KEY,
            "client_email": FIREBASE_CLIENT_EMAIL,
            "client_id": FIREBASE_CLIENT_ID,
            "auth_uri": FIREBASE_AUTH_URI,
            "token_uri": FIREBASE_TOKEN_URI,
            "auth_provider_x509_cert_url": FIREBASE_AUTH_PROVIDER_X509_CERT_URL,
            "client_x509_cert_url": FIREBASE_CLIENT_X509_CERT_URL,
            "universe_domain": FIREBASE_UNIVERSE_DOMAIN
        }

        cred = credentials.Certificate(serviceAccountKey)
        firebase_admin.initialize_app(cred, {
            "storageBucket": FIREBASE_STORAGE_BUCKET # os.getenv("FIREBASE_STORAGE_BUCKET")
        })
