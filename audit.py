import hashlib
import hmac
import json
import os
import threading
from datetime import datetime, timezone

from dotenv import load_dotenv
from sqlalchemy import DDL, Integer, String, Text, event, select
from sqlalchemy.orm import Mapped, Session, mapped_column

from database import Base, SessionLocal
from errors import logger, sanitize_details

load_dotenv()
_key = os.getenv("AUDIT_HMAC_KEY")
if not _key or len(_key) < 32:
    raise RuntimeError("AUDIT_HMAC_KEY is missing from .env or shorter than 32 characters")
AUDIT_KEY = _key.encode("utf-8")
GENESIS_HASH = "0" * 64


class AuditLog(Base):
    __tablename__ = "audit_log"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    created_at: Mapped[str] = mapped_column(String(40), nullable=False)  
    event: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    actor_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    outcome: Mapped[str] = mapped_column(String(16), nullable=False)
    ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    details: Mapped[str] = mapped_column(Text, nullable=False)            
    prev_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    entry_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)



for _action in ("UPDATE", "DELETE"):
    event.listen(
        AuditLog.__table__, "after_create",
        DDL(f"CREATE TRIGGER IF NOT EXISTS audit_log_no_{_action.lower()} "
            f"BEFORE {_action} ON audit_log "
            f"BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;").execute_if(dialect="sqlite"),
    )


def _compute_hash(prev_hash, created_at, event_name, actor_id, outcome, ip, details_json):
    payload = json.dumps([prev_hash, created_at, event_name, actor_id, outcome, ip, details_json],
                         separators=(",", ":"), ensure_ascii=False)
    return hmac.new(AUDIT_KEY, payload.encode("utf-8"), hashlib.sha256).hexdigest()


def client_ip(request) -> str:
    return request.client.host if request.client else "unknown"


_chain_lock = threading.Lock()


def log_event(event_name, actor_id=None, outcome="success", ip=None, details=None) -> None:
    details_json = json.dumps(sanitize_details(details or {}), sort_keys=True,
                              separators=(",", ":"), default=str)
    created_at = datetime.now(timezone.utc).isoformat(timespec="microseconds")
    with _chain_lock, SessionLocal() as db:
        last_hash = db.scalar(select(AuditLog.entry_hash).order_by(AuditLog.id.desc()).limit(1))
        prev_hash = last_hash or GENESIS_HASH
        db.add(AuditLog(
            created_at=created_at, event=event_name, actor_id=actor_id, outcome=outcome, ip=ip,
            details=details_json, prev_hash=prev_hash,
            entry_hash=_compute_hash(prev_hash, created_at, event_name, actor_id, outcome, ip, details_json),
        ))
        db.commit()
    logger.info("audit event=%s actor=%s outcome=%s", event_name, actor_id, outcome)


def verify_chain(db: Session) -> dict:
    prev_hash = GENESIS_HASH
    checked = 0
    for row in db.scalars(select(AuditLog).order_by(AuditLog.id)):
        expected = _compute_hash(prev_hash, row.created_at, row.event, row.actor_id,
                                 row.outcome, row.ip, row.details)
        if row.prev_hash != prev_hash or not hmac.compare_digest(row.entry_hash, expected):
            return {"valid": False, "entries_checked": checked, "first_invalid_id": row.id}
        prev_hash = row.entry_hash
        checked += 1
    return {"valid": True, "entries_checked": checked, "first_invalid_id": None, "head_hash": prev_hash}