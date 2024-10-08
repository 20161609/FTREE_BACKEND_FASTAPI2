import firebase_admin
from firebase_admin import credentials, auth, db, storage
from dotenv import load_dotenv
import os

# Environment variables
load_dotenv()
SERVICE_ACCOUNT_KEY_PATH = os.getenv("SERVICE_ACCOUNT_KEY_PATH")
FIREBASE_DATABASE_URL=os.getenv("FIREBASE_DATABASE_URL")
FIREBASE_STORAGE_URL=os.getenv("FIREBASE_STORAGE_URL")

# Firebase App initialization
def initialize_firebase():
    if not firebase_admin._apps:
        serviceAccountKey = {
            "type": os.getenv("FIREBASE_TYPE"),
            "project_id": os.getenv("FIREBASE_PROJECT_ID"),
            "private_key_id": os.getenv("FIREBASE_PRIVATE_KEY_ID"),
            "private_key": os.getenv("FIREBASE_PRIVATE_KEY").replace('\\n', '\n'),
            "client_email": os.getenv("FIREBASE_CLIENT_EMAIL"),
            "client_id": os.getenv("FIREBASE_CLIENT_ID"),
            "auth_uri": os.getenv("FIREBASE_AUTH_URI"),
            "token_uri": os.getenv("FIREBASE_TOKEN_URI"),
            "auth_provider_x509_cert_url": os.getenv("FIREBASE_AUTH_PROVIDER_X509_CERT_URL"),
            "client_x509_cert_url": os.getenv("FIREBASE_CLIENT_X509_CERT_URL"),
            "universe_domain": os.getenv("FIREBASE_UNIVERSE_DOMAIN")
        }

        cred = credentials.Certificate(serviceAccountKey)
        firebase_admin.initialize_app(cred, {
            "databaseURL": os.getenv("FIREBASE_DATABASE_URL"),
            "storageBucket": os.getenv("FIREBASE_STORAGE_BUCKET")
        })
