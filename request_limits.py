from fastapi import Request
from starlette.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware


class RequestSizeLimitMiddleware(BaseHTTPMiddleware):
    MAX_REQUEST_SIZE = 1024 * 1024  # 1 MB

    async def dispatch(self, request: Request, call_next):
        body = await request.body()

        if len(body) > self.MAX_REQUEST_SIZE:
            return JSONResponse(
                status_code=413,
                content={"detail": "Request body too large"}
            )

        return await call_next(request)