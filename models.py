from sqlalchemy import Integer, String, DateTime, Boolean, Column
from sqlalchemy.orm import Mapped, mapped_column
from database import Base
from datetime import datetime
class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[str] = mapped_column(
    String(20),
    nullable=False,
    default="user"
    )
    failed_login_attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    totp_secret_encrypted: Mapped[str | None] = mapped_column(String(512), nullable=True)
    totp_enabled = Column(Boolean, default=False, nullable=False)


    
