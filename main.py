from fastapi import FastAPI
from database import Base, engine
from auth import router
import models
from request_limits import RequestSizeLimitMiddleware


Base.metadata.create_all(bind=engine)

app = FastAPI(title="SecureFin API")
app.add_middleware(RequestSizeLimitMiddleware)

app.include_router(router)