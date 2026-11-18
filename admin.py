from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from audit import verify_chain
from authz import Role, get_db, require_roles
from models import User

router = APIRouter(prefix="/admin", tags=["admin"])


@router.get("/audit/verify")
def verify_audit_log(
    admin: User = Depends(require_roles(Role.ADMIN)),
    db: Session = Depends(get_db),
):
    return verify_chain(db)