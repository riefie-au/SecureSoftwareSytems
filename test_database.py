from sqlalchemy import select
from database import SessionLocal
from models import User

with SessionLocal() as session:
    email_input = "' OR '1'='1"

    statement = select(User).where(User.email == email_input)
    print(statement.compile().params)
    user = session.scalar(statement)

    print(user)