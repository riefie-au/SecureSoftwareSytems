from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, DeclarativeBase
DATABASE_URL = "sqlite:///./securefin.db"
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(bind=engine)
class Base(DeclarativeBase):
    pass
