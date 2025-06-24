# app/db/model.py

from datetime import datetime
from sqlalchemy import Column, String, Integer, Date, Text, ForeignKey, TIMESTAMP, Boolean, LargeBinary
from app.db.init import Base

# Transaction model
class Transaction(Base):
    __tablename__ = 'transaction'
    tid = Column(Integer, primary_key=True, autoincrement=True)
    t_date = Column(Date, nullable=False)  # Transaction date
    branch = Column(String(255), nullable=False)  # Branch information
    cashflow = Column(Integer, nullable=False)  # Cashflow amount
    description = Column(Text, nullable=True)  # Optional description
    c_date = Column(TIMESTAMP, default=datetime.utcnow)  # Creation timestamp
    uid = Column(Integer, ForeignKey('auth.uid'), nullable=False)  # Foreign key to user ID
    receipt = Column(String(255), nullable=True)  # Receipt image directory path in Firebase Storage
    
# Email verification model
class EmailVerification(Base):
    __tablename__ = 'email_verification'
    code = Column(String(255), primary_key=True)  # Verification code
    email = Column(String(255), nullable=False, unique=True)  # Prevent duplicate email
    verified = Column(TIMESTAMP, default=None)  # Verification timestamp (optional)
    created_at = Column(TIMESTAMP, default=datetime.utcnow)  # Creation timestamp

# Auth model for user authentication
class Auth(Base):
    __tablename__ = 'auth'
    uid = Column(Integer, primary_key=True, autoincrement=True)  # User ID
    username = Column(String(255), nullable=False)  # Username
    email = Column(String(255), nullable=False)  # User email
    password = Column(String(255), nullable=False)  # Hashed password
    is_active = Column(Boolean, default=True)  # User active status
    create_time = Column(TIMESTAMP, default=datetime.utcnow)  # Account creation time
    update_time = Column(TIMESTAMP, default=datetime.utcnow)  # Last update time
    useai = Column(Boolean, default=False)  # Use AI for transaction categorization

# Branch model for organizing branches
class Branch(Base):
    __tablename__ = 'branch'
    bid = Column(Integer, primary_key=True, autoincrement=True)  # Branch ID
    uid = Column(Integer, ForeignKey('auth.uid'), nullable=False)  # Foreign key to user ID
    path = Column(String(255), nullable=False)  # Path for branch (e.g., directory structure)

# Role model for user roles (e.g., admin, user)
class Role(Base):
    __tablename__ = 'role'
    role_id = Column(Integer, primary_key=True, autoincrement=True)  # Role ID
    role_name = Column(String(50), unique=True, nullable=False)  # Role name (e.g., admin, user)

# UserRole model for many-to-many relationship between users and roles
class UserRole(Base):
    __tablename__ = 'user_role'
    user_role_id = Column(Integer, primary_key=True, autoincrement=True)  # UserRole ID
    uid = Column(Integer, ForeignKey('auth.uid'), nullable=False)  # Foreign key to user ID
    role_id = Column(Integer, ForeignKey('role.role_id'), nullable=False)  # Foreign key to role IDs

# Token model for managing JWT tokens
class Token(Base):
    __tablename__ = 'token'
    token_id = Column(Integer, primary_key=True, autoincrement=True)  # Token ID
    uid = Column(Integer, ForeignKey('auth.uid'), nullable=False)  # Foreign key to user ID
    access_token = Column(Text, nullable=False)  # JWT access token
    refresh_token = Column(Text, nullable=True)  # Optional refresh token
    created_at = Column(TIMESTAMP, default=datetime.utcnow)  # Token creation timestamp
    expires_at = Column(TIMESTAMP, nullable=False)  # Token expiration timestamp
