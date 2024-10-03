# app/lib/branch.py

from app.db.init import database
from app.db.model import Branch

# Check if the branch exists
async def is_exist_branch(uid: str, branch: str):
    query = Branch.__table__.select().where(Branch.uid == uid).where(Branch.path == branch)
    return await database.fetch_one(query) is not None

# Delete branch by branch ID (bid)
async def delete_branch_bid(uid: str, bid_list: list):
    try:
        delete_query = Branch.__table__.delete().where(
            (Branch.uid == uid) & 
            (Branch.bid.in_(bid_list))
        ).returning(Branch.__table__.c)
        
        return await database.fetch_all(delete_query)
    except Exception as e:
        raise Exception(f"Failed to delete branch from PostgreSQL: {str(e)}")
