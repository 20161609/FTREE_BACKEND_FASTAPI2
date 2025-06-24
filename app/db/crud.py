# app/db/crud.py
from datetime import datetime
from sqlalchemy import select, func, case, and_, or_
from app.db.model import Auth, Branch, Transaction
from app.db.init import database

# Create a new user in the Auth table
async def create_user(email, username, password):
    try:
        query = Auth.__table__.insert().values(
            email=email,
            username=username,
            password=password
        )
        await database.execute(query)
        return {"status": True, "message": "User registered successfully"}
    except Exception as e:
        return {"status": False, "message": f"Failed to register user into PostgreSQL\n{str(e)}"}

# Create a branch for the user
async def upload_branch(uid: str, path: str):
    try:
        query = Branch.__table__.insert().values(
            uid=uid,
            path=path
        )
        await database.execute(query)
        return {"status": True, "message": "Branch uploaded successfully"}
    except Exception as e:
        return {"status": False, "message": f"Failed to upload branch\n{str(e)}"}

# Retrieve user information from the Auth table
async def get_auth_postgre(uid: str):
    query = Auth.__table__.select().where(Auth.uid == uid)
    return await database.fetch_one(query)

# Retrieve all branches for the given user
async def get_tree_postgre(uid: str):
    query = Branch.__table__.select().where(Branch.uid == uid)
    return await database.fetch_all(query)

# Check if a branch exists for the user
async def is_exist_branch(uid: str, branch: str):
    query = Branch.__table__.select().where(Branch.uid == uid).where(Branch.path == branch)
    return await database.fetch_one(query) is not None

# Add a new branch for the user
async def add_branch(uid: str, branch: str):
    query = Branch.__table__.insert().values(uid=uid, path=branch)
    await database.execute(query)

# Add a new transaction
async def add_transaction_postgre(transaction: dict):
    query = Transaction.__table__.insert().values(
        t_date=transaction['t_date'],
        branch=transaction['branch'],
        cashflow=transaction['cashflow'],
        description=transaction['description'],
        receipt=transaction['receipt'],
        c_date=transaction['c_date'],
        uid=transaction['uid']
    ).returning(Transaction.__table__.c.tid)
    return await database.execute(query)

# Delete a transaction by user ID and transaction ID
async def delete_transaction_postgre(uid: str, tid: int):
    try:
        query = Transaction.__table__.delete().where(
            Transaction.uid == uid
        ).where(
            Transaction.tid == tid
        ).returning(Transaction.receipt)
        return await database.fetch_one(query)
    except Exception as e:
        print(f"Failed to delete transaction from PostgreSQL\n{str(e)}")

# Delete all transactions for a branch
async def delete_branch_transaction_postgre(uid: str, branch: str):
    try:
        query = Transaction.__table__.delete().where(
            (Transaction.uid == uid) & 
            (or_(Transaction.branch == branch, Transaction.branch.like(f'{branch}/%')))
        ).returning(Transaction.__table__.c)
        return await database.fetch_all(query)
    except Exception as e:
        raise Exception(f"Failed to delete branch from PostgreSQL: {str(e)}")

# Delete a branch by user ID and branch ID
async def delete_branch_postgre(uid: str, bid: int):
    try:
        query = Branch.__table__.delete().where(
            Branch.uid == uid
        ).where(
            Branch.bid == bid
        ).returning(Branch.__table__.c)
        return await database.execute(query)
    except Exception as e:
        raise Exception(f"Failed to delete branch from PostgreSQL: {str(e)}")

# Retrieve all sub-branches for a branch
async def get_children_postgre(uid: str, branch: str):
    query = Branch.__table__.select().where(
        (Branch.uid == uid) & 
        (or_(Branch.path.like(f'{branch}/%'), Branch.path == branch))
    )
    return await database.fetch_all(query)

# Retrieve daily transactions within a date range
async def get_daily_postgre(uid: str, branch: str, begin_date: str, end_date: str):
    begin_date = datetime.strptime(begin_date, '%Y-%m-%d').date()
    end_date = datetime.strptime(end_date, '%Y-%m-%d').date()

    query = Transaction.__table__.select().where(
        (Transaction.uid == uid) &
        (or_(Transaction.branch == branch, Transaction.branch.like(f"{branch + '/'}%"))) &
        (Transaction.t_date.between(begin_date, end_date))
    ).order_by(Transaction.t_date)

    results = await database.fetch_all(query)

    return [
        {key: item[key] for key in ['tid', 't_date', 'branch', 'cashflow', 'description', 'receipt', 'c_date']}
        for item in results
    ]

# Retrieve monthly transactions grouped by month
async def get_monthly_postgre(uid: str, branch: str, begin_date: str, end_date: str):
    begin_date = datetime.strptime(begin_date, '%Y-%m-%d').date()
    end_date = datetime.strptime(end_date, '%Y-%m-%d').date()

    monthly_label = func.to_char(Transaction.t_date, 'YYYY-MM')
    query = (
        select(
            monthly_label.label('monthly'),
            func.sum(case((Transaction.cashflow > 0, Transaction.cashflow), else_=0)).label('income'),
            func.sum(case((Transaction.cashflow < 0, Transaction.cashflow), else_=0)).label('expenditure')
        )
        .where(
            (Transaction.uid == uid) &
            (Transaction.branch.like(f'{branch}%')) &
            (Transaction.t_date.between(begin_date, end_date))
        )
        .group_by(monthly_label)
        .order_by(monthly_label)
    )
    results = await database.fetch_all(query)

    monthly_box = []
    for row in results:
        monthly_box.append({
            'monthly': row['monthly'],
            'income': row['income'],
            'expenditure': abs(row['expenditure'])
        })

    return monthly_box

# Delete all transactions for a user
async def delete_all_transaction_postgre(uid: str):
    try:
        query = Transaction.__table__.delete().where(
            Transaction.uid == uid
        ).returning(Transaction.receipt)
        return await database.fetch_all(query)
    except Exception as e:
        raise Exception(f"Failed to delete all transactions from PostgreSQL: {str(e)}")

# Delete all branches for a user
async def delete_all_branch_postgre(uid: str):
    try:
        query = Branch.__table__.delete().where(
            Branch.uid == uid
        ).returning(Branch.path)
        return await database.fetch_all(query)
    except Exception as e:
        raise Exception(f"Failed to delete all branches from PostgreSQL: {str(e)}")

# Delete a user by user ID 
async def delete_user_postgre(uid: str):
    try:
        query = Auth.__table__.delete().where(
            Auth.uid == uid
        ).returning(Auth.uid)
        return await database.fetch_one(query)
    except Exception as e:
        raise Exception(f"Failed to delete user from PostgreSQL: {str(e)}")
