from datetime import datetime, timezone

from fastapi import APIRouter, Request, Response
from sqlalchemy import DateTime, String
from sqlalchemy.orm import Mapped, Session, mapped_column

from audit import client_ip, log_event
from cookies import ACCESS_COOKIE, clear_access_cookie, set_access_cookie
from database import Base, SessionLocal
from tokens import InvalidToken, decode_token, issue_access_token


class RevokedToken(Base):
    __tablename__ = "revoked_tokens"

    jti: Mapped[str] = mapped_column(String(36), primary_key=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


def issue_session(response: Response, user, ip: str | None = None) -> None:
    set_access_cookie(response, issue_access_token(user))
    log_event("session_issued", user.id, "success", ip)


def is_revoked(db: Session, jti: str) -> bool:
    return db.get(RevokedToken, jti) is not None


router = APIRouter(prefix="/auth", tags=["session"])


@router.post("/logout", status_code=204)
def logout(request: Request):
    try:
        claims = decode_token(request.cookies.get(ACCESS_COOKIE))
    except InvalidToken:
        claims = None  

    if claims:
        with SessionLocal() as db:
            if not is_revoked(db, claims["jti"]):
                expires_at = datetime.fromtimestamp(claims["exp"], timezone.utc)
                db.add(RevokedToken(jti=claims["jti"], expires_at=expires_at))
                db.commit()
        log_event("logout", int(claims["sub"]), "success", client_ip(request))

    response = Response(status_code=204)
    clear_access_cookie(response)
    return response