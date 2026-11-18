import hashlib
import json
from datetime import datetime, timezone

from sqlalchemy import DDL, Integer, String, Text, event, select
from sqlalchemy.orm import Mapped, Session, mapped_column

from database import Base, SessionLocal

GENESIS_HASH = "0" * 64                               
NEVER_LOG = {"password", "code", "totp_code", "token", "secret"}


class AuditLog(Base):
    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    created_at: Mapped[str] = mapped_column(String(40), nullable=False)
    event: Mapped[str] = mapped_column(String(64), nullable=False)
    actor_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    outcome: Mapped[str] = mapped_column(String(16), nullable=False)
    ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    details: Mapped[str] = mapped_column(Text, nullable=False)
    prev_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    entry_hash: Mapped[str] = mapped_column(String(64), nullable=False)


for action in ("UPDATE", "DELETE"):
    event.listen(AuditLog.__table__, "after_create", DDL(
        f"CREATE TRIGGER audit_log_no_{action.lower()} BEFORE {action} ON audit_log "
        f"BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;"
    ))


def _hash(prev_hash, created_at, event_name, actor_id, outcome, ip, details) -> str:
    data = f"{prev_hash}|{created_at}|{event_name}|{actor_id}|{outcome}|{ip}|{details}"
    return hashlib.sha256(data.encode()).hexdigest()


def client_ip(request) -> str:
    return request.client.host if request.client else "unknown"


def log_event(event_name: str, actor_id=None, outcome="success", ip=None, details=None) -> None:
    safe_details = {k: v for k, v in (details or {}).items() if k.lower() not in NEVER_LOG}
    details_json = json.dumps(safe_details, sort_keys=True, default=str)
    created_at = datetime.now(timezone.utc).isoformat()

    with SessionLocal() as db:
        last_hash = db.scalar(select(AuditLog.entry_hash).order_by(AuditLog.id.desc()).limit(1))
        prev_hash = last_hash or GENESIS_HASH
        db.add(AuditLog(
            created_at=created_at, event=event_name, actor_id=actor_id, outcome=outcome,
            ip=ip, details=details_json, prev_hash=prev_hash,
            entry_hash=_hash(prev_hash, created_at, event_name, actor_id, outcome, ip, details_json),
        ))
        db.commit()


def verify_chain(db: Session) -> dict:
    prev_hash = GENESIS_HASH
    checked = 0
    for row in db.scalars(select(AuditLog).order_by(AuditLog.id)):
        expected = _hash(prev_hash, row.created_at, row.event, row.actor_id, row.outcome, row.ip, row.details)
        if row.prev_hash != prev_hash or row.entry_hash != expected:
            return {"valid": False, "entries_checked": checked, "first_invalid_id": row.id}
        prev_hash = row.entry_hash
        checked += 1
    return {"valid": True, "entries_checked": checked, "first_invalid_id": None}