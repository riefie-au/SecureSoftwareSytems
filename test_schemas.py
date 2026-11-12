from pydantic import ValidationError
from schemas import UserRegister

try:
    user = UserRegister(
    email="student@example.com",
    password="abc123"
)
    print("Validation successful!")

except ValidationError as error:
    print("Validation failed!")
    print(error)