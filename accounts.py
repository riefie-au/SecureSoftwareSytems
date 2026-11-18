from fastapi import APIRouter, Depends, Request
from sqlalchemy import ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, Session, mapped_column

from audit import client_ip, log_event
from authz import Role, get_db, require_roles
from database import Base
from errors import forbidden
from models import User


class Account(Base):
    __tablename__ = "accounts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    owner_id: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False)
    account_number: Mapped[str] = mapped_column(String(20), unique=True, nullable=False)
    balance_sen: Mapped[int] = mapped_column(Integer, nullable=False, default=0)  


router = APIRouter(prefix="/accounts", tags=["accounts"])


@router.get("/{account_id}")
def get_account(
    account_id: int,
    request: Request,
    user: User = Depends(require_roles(Role.CUSTOMER)),    
    db: Session = Depends(get_db),
):
    account = db.get(Account, account_id)
    if account is None or account.owner_id != user.id:      
        log_event("access_denied", user.id, "failure", client_ip(request), {"account_id": account_id})
        raise forbidden()

    return {
        "id": account.id,
        "account_number": account.account_number,
        "balance": f"{account.balance_sen / 100:.2f}",
        "currency": "MYR",
    }