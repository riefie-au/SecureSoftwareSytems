import secrets

from sqlalchemy import select

import main
from accounts import Account
from authz import Role
from database import SessionLocal
from models import User
from security import hash_password

DEMO_USERS = [
    ("alice@example.com", Role.CUSTOMER, "1000-0001-0001", 1250075),
    ("bob@example.com", Role.CUSTOMER, "1000-0002-0002", 380010),
    ("admin@example.com", Role.ADMIN, None, None),
]

with SessionLocal() as db:
    for email, role, account_number, balance_sen in DEMO_USERS:
        if db.scalar(select(User).where(User.email == email)):
            print("already exists:", email)
            continue
        password = secrets.token_urlsafe(12)
        user = User(email=email, password_hash=hash_password(password), role=role)
        db.add(user)
        db.flush()                              
        if account_number:
            db.add(Account(owner_id=user.id, account_number=account_number, balance_sen=balance_sen))
        print(f"{role:<20} id={user.id}  {email}  password: {password}")
    db.commit()