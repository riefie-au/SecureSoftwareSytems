from security import hash_password, verify_password

password = "MySecurePassword123!"
hashed = hash_password(password)

print("Hash uses Argon2id:", hashed.startswith("$argon2id$"))
print("Correct password:", verify_password(password, hashed))
print("Wrong password:", verify_password("WrongPassword123!", hashed))