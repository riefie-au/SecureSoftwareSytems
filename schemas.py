from pydantic import BaseModel, EmailStr, Field

class UserRegister(BaseModel):
    email: EmailStr
    password: str = Field(min_length=12, max_length=128)
class UserLogin(BaseModel):
    email: EmailStr
    password: str
class TOTPVerify(BaseModel):
    code: str = Field(min_length=6, max_length=6, pattern=r"^\d{6}$")