# scratch_audit.py
from sqlalchemy import text
from database import Base, engine, SessionLocal
from audit import log_event, verify_chain

Base.metadata.create_all(engine)
log_event("scratch_test", None, "success", "127.0.0.1", {"password": "should-not-appear"})

with SessionLocal() as db:
    print(verify_chain(db))
    print(db.execute(text("SELECT details FROM audit_log ORDER BY id DESC LIMIT 1")).scalar())
    try:
        db.execute(text("DELETE FROM audit_log"))
    except Exception as exc:
        print("blocked:", exc.orig)