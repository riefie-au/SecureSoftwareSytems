import logging
import uuid
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

LOG_FILE = Path(__file__).resolve().parent / "logs" / "securefin.log"
LOG_FILE.parent.mkdir(exist_ok=True)

logger = logging.getLogger("securefin")
if not logger.handlers:
    handler = logging.FileHandler(LOG_FILE, encoding="utf-8")
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s: %(message)s"))
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)


def unauthorized() -> HTTPException:
    return HTTPException(status_code=401, detail="Invalid or expired session")


def forbidden() -> HTTPException:
    return HTTPException(status_code=403, detail="Forbidden")


async def validation_error(request: Request, exc: RequestValidationError) -> JSONResponse:
    errors = [{"field": err["loc"][-1], "msg": err["msg"]} for err in exc.errors()]
    return JSONResponse(status_code=422, content={"detail": errors})


async def unexpected_error(request: Request, exc: Exception) -> JSONResponse:
    error_id = uuid.uuid4().hex[:12]
    logger.error("error_id=%s on %s %s", error_id, request.method, request.url.path, exc_info=exc)
    return JSONResponse(status_code=500, content={"detail": "Internal server error", "error_id": error_id})

def register_error_handlers(app: FastAPI) -> None:
    app.add_exception_handler(RequestValidationError, validation_error)
    app.add_exception_handler(Exception, unexpected_error)
