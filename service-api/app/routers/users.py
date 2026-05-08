from fastapi import APIRouter, Depends
from .. import schemas, auth

router = APIRouter(prefix="/api/users", tags=["users"])

@router.get("/me", response_model=schemas.User)
async def read_users_me(current_user = Depends(auth.get_current_user)):
    return current_user
