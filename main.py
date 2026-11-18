from fastapi import FastAPI
from database import Base, engine
from auth import router
import models
from request_limits import RequestSizeLimitMiddleware
import audit, sessions, accounts 
from sessions import router as session_router
from accounts import router as accounts_router
from admin import router as admin_router
from errors import register_error_handlers
from security_headers import HSTSMiddleware

Base.metadata.create_all(bind=engine)

app = FastAPI(title="SecureFin API")
app.add_middleware(RequestSizeLimitMiddleware)
app.add_middleware(HSTSMiddleware)
register_error_handlers(app)  
app.include_router(router)
app.include_router(session_router)         
app.include_router(accounts_router)      
app.include_router(admin_router)     