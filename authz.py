from datetime import datetime, timezone

from fastapi import Depends, Request
from sqlalchemy.orm import Session

from audit import client_ip, log_event
from cookies import ACCESS_COOKIE
from database import SessionLocal
from errors import forbidden, logger, unauthorized
from models import User
from sessions import is_revoked
from tokens import InvalidToken, decode_token


class Role:
    CUSTOMER = "Customer"
    AUDITOR = "Auditor"
    ADMIN = "SystemAdministrator"


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def get_current_user(request: Request, db: Session = Depends(get_db)) -> User:
    try:
        claims = decode_token(request.cookies.get(ACCESS_COOKIE))
    except InvalidToken as exc:
        logger.info("token rejected (%s) on %s", exc, request.url.path)  
        raise unauthorized()                                             

    if is_revoked(db, claims["jti"]):
        raise unauthorized()

    user = db.get(User, int(claims["sub"]))
    if user is None:
        raise unauthorized()
    if user.locked_until and user.locked_until.replace(tzinfo=timezone.utc) > datetime.now(timezone.utc):
        raise unauthorized()
    return user


def require_roles(*allowed_roles: str):
    def checker(request: Request, user: User = Depends(get_current_user)) -> User:
        if user.role not in allowed_roles:
            log_event("access_denied", user.id, "failure", client_ip(request),
                      {"path": request.url.path, "role": user.role})
            raise forbidden()
        return user
    return checker