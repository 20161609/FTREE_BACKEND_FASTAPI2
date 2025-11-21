from sqlalchemy import create_engine
from app.db.model import Base

# sync 드라이버 사용 (중요!!)
DATABASE_URL = "postgresql+psycopg2://ftree_user:Jsky4987!!@/postgres?host=/cloudsql/finance-tree:northamerica-northeast1:ftree-db"

engine = create_engine(DATABASE_URL)

print("Creating tables...")
Base.metadata.create_all(bind=engine)
print("DONE")


# app/db/init.py

# import os
# from sqlalchemy import create_engine, MetaData
# from sqlalchemy.ext.declarative import declarative_base
# from sqlalchemy.orm import sessionmaker
# from databases import Database
# from dotenv import load_dotenv

# # Load environment variables from .env file
# load_dotenv()

# # Read the database URL from environment variables
# # DATABASE_URL = os.getenv("DATABASE_URL")
# DATABASE_URL="postgresql+asyncpg://ftree_user:Jsky4987!!@/postgres?host=/cloudsql/finance-tree:northamerica-northeast1:ftree-db"	


# # Set up SQLAlchemy engine and metadata
# engine = create_engine(DATABASE_URL)
# metadata = MetaData()
# Base = declarative_base()

# # Create a Database object for async operations
# database = Database(DATABASE_URL, ssl=True)

# # SQLAlchemy session setup for synchronous database interactions
# SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# # Create all database tables if they don't exist
# Base.metadata.create_all(bind=engine)
