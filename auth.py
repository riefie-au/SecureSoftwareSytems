from fastapi import APIRouter, HTTPException
from sqlalchemy import select
from database import SessionLocal
from models import User
from schemas import UserRegister, UserLogin
from security import hash_password, verify_password
from datetime import datetime, timedelta, timezone
from fastapi import Request
from ip_velocity import check_ip_velocity

router = APIRouter()
@router.post("/register", status_code=201)
def register(user_data: UserRegister):
    with SessionLocal() as session:
        statement = select(User).where(User.email == user_data.email)
        existing_user = session.scalar(statement)

        if existing_user is not None:
            raise HTTPException(
                status_code=409,
                detail="Email already registered"
            )

        hashed_password = hash_password(user_data.password)

        new_user = User(
            email=user_data.email,
            password_hash=hashed_password,
            role="user"
        )
        session.add(new_user)
        session.commit()
        session.refresh(new_user)
        return {
            "message": "Registration successful",
            "user_id": new_user.id,
            "email": new_user.email
        }

@router.post("/login")
def login(user_data: UserLogin, request: Request):
    # Simulated IP header for assignment testing only
    client_ip = request.headers.get("X-Forwarded-For")

    if client_ip:
       client_ip = client_ip.split(",")[0].strip()
    else:
       client_ip = request.client.host if request.client else "unknown"

    if not check_ip_velocity(client_ip):
        raise HTTPException(
            status_code=429,
            detail="Too many login attempts. Please try again later."
        )
    with SessionLocal() as session:
        statement = select(User).where(User.email == user_data.email)
        user = session.scalar(statement)

        if user is None:
            raise HTTPException(
                status_code=401,
                detail="Invalid email or password"
            )
        if user.locked_until is not None:
            locked_until = user.locked_until.replace(tzinfo=timezone.utc)

            if datetime.now(timezone.utc) < locked_until:
                raise HTTPException(
                    status_code=423,
                    detail="Account temporarily locked"
                )
        if not verify_password(user_data.password, user.password_hash):
           user.failed_login_attempts += 1
           if user.failed_login_attempts >= 5:
                user.locked_until = datetime.now(timezone.utc) + timedelta(minutes=15)

           session.commit()
            
           raise HTTPException(
                status_code=401,
                detail="Invalid email or password"

        )
        user.failed_login_attempts = 0
        user.locked_until = None
        
        session.commit()
        
        return {
            "message": "Login successful",
            "user_id": user.id
        }

    