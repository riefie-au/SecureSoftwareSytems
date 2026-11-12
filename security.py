from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
import pyotp
import os
import base64
from dotenv import load_dotenv
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
load_dotenv()
import pyotp
key_string = os.getenv("TOTP_ENCRYPTION_KEY")

if not key_string:
    raise RuntimeError("TOTP_ENCRYPTION_KEY is missing from .env")

ENCRYPTION_KEY = base64.urlsafe_b64decode(key_string)

if len(ENCRYPTION_KEY) != 32:
    raise RuntimeError("Encryption key must be 32 bytes")

password_hasher = PasswordHasher()
def hash_password(password: str) -> str:
        return password_hasher.hash(password)
def verify_password(password: str, stored_hash: str) -> bool:
    try:
        return password_hasher.verify(stored_hash, password)
    except VerifyMismatchError:
        return False
def generate_totp_secret() -> str:
    return pyotp.random_base32()
def encrypt_totp_secret(secret: str) -> str:
    nonce = os.urandom(12)

    aesgcm = AESGCM(ENCRYPTION_KEY)

    encrypted = aesgcm.encrypt(
        nonce,
        secret.encode("utf-8"),
        None
    )

    return base64.urlsafe_b64encode(nonce + encrypted).decode("utf-8")
def decrypt_totp_secret(encrypted_secret: str) -> str:
    encrypted_data = base64.urlsafe_b64decode(encrypted_secret)

    nonce = encrypted_data[:12]
    ciphertext = encrypted_data[12:]

    aesgcm = AESGCM(ENCRYPTION_KEY)

    decrypted = aesgcm.decrypt(nonce, ciphertext, None)

    return decrypted.decode("utf-8")
def verify_totp_code(secret: str, code: str) -> bool:
    totp = pyotp.TOTP(secret)
    return totp.verify(code, valid_window=1)
def generate_totp_uri(secret: str, email: str) -> str:
    totp = pyotp.TOTP(secret)

    return totp.provisioning_uri(
        name=email,
        issuer_name="SecureFin"
    )
def prepare_totp_enrollment(email: str) -> tuple[str, str]:
    secret = generate_totp_secret()
    uri = generate_totp_uri(secret, email)

    return encrypt_totp_secret(secret), uri
def confirm_totp_enrollment(encrypted_secret: str, code: str) -> bool:
    secret = decrypt_totp_secret(encrypted_secret)
    return verify_totp_code(secret, code)