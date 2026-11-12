import logging
import re
import uuid
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

BASE_DIR = Path(__file__).resolve().parent
LOG_FILE = BASE_DIR / "logs" / "securefin.log"
logger = logging.getLogger("securefin")

UNAUTHORIZED_MSG = "Invalid or expired session"
FORBIDDEN_MSG = "Forbidden"


def unauthorized() -> HTTPException:
    return HTTPException(status_code=401, detail=UNAUTHORIZED_MSG)


def forbidden() -> HTTPException:
    return HTTPException(status_code=403, detail=FORBIDDEN_MSG)

SENSITIVE_KEYS = {
    "password", "new_password", "old_password", "password_hash",
    "code", "totp", "totp_code", "totp_secret", "totp_secret_encrypted",
    "secret", "token", "access_token", "refresh_token", "mfa_token",
    "authorization", "cookie", "set-cookie", "passphrase",
}

_JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+")
_BEARER_RE = re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]+")
_KEY_VALUE_RE = re.compile(
    r"""(?ix)
    (["']?\b(?:%s)\b["']?\s*[:=]\s*)   
    ("[^"]*"|'[^']*'|[^\s,;&}]+)         
    """ % "|".join(re.escape(k) for k in sorted(SENSITIVE_KEYS, key=len, reverse=True))
)


def redact_text(text: str) -> str:
    text = _JWT_RE.sub("[REDACTED_JWT]", text)
    text = _BEARER_RE.sub("Bearer [REDACTED]", text)
    return _KEY_VALUE_RE.sub(r"\1[REDACTED]", text)


def sanitize_details(value):
    if isinstance(value, dict):
        return {k: ("[REDACTED]" if str(k).lower() in SENSITIVE_KEYS else sanitize_details(v))
                for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [sanitize_details(v) for v in value]
    if isinstance(value, str):
        return redact_text(value)
    return value


class RedactingFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, str):
            record.msg = redact_text(record.msg)
        if isinstance(record.args, tuple):
            record.args = tuple(redact_text(a) if isinstance(a, str) else a for a in record.args)
        elif isinstance(record.args, dict):
            record.args = {k: redact_text(v) if isinstance(v, str) else v for k, v in record.args.items()}
        if record.exc_info and not record.exc_text:
            record.exc_text = redact_text(logging.Formatter().formatException(record.exc_info))
        return True


_logging_ready = False


def setup_logging() -> None:
    global _logging_ready
    if _logging_ready:
        return
    _logging_ready = True

    redactor = RedactingFilter()
    LOG_FILE.parent.mkdir(exist_ok=True)
    formatter = logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s")
    for handler in (logging.FileHandler(LOG_FILE, encoding="utf-8"), logging.StreamHandler()):
        handler.setFormatter(formatter)
        handler.addFilter(redactor)
        logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    logger.propagate = False

    # Also redact uvicorn's own handlers.
    for name in ("", "uvicorn", "uvicorn.error", "uvicorn.access"):
        for handler in logging.getLogger(name).handlers:
            handler.addFilter(redactor)

async def _validation_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
    safe_errors = [{"loc": list(err.get("loc", [])), "msg": err.get("msg", "Invalid value")}
                   for err in exc.errors()]
    return JSONResponse(status_code=422, content={"detail": safe_errors})


async def _unhandled_handler(request: Request, exc: Exception) -> JSONResponse:
    error_id = uuid.uuid4().hex[:12]
    logger.error("Unhandled error id=%s on %s %s", error_id, request.method,
                 request.url.path, exc_info=exc)
    return JSONResponse(status_code=500,
                        content={"detail": "Internal server error", "error_id": error_id})


def register_error_handlers(app: FastAPI) -> None:
    app.add_exception_handler(RequestValidationError, _validation_handler)
    app.add_exception_handler(Exception, _unhandled_handler)