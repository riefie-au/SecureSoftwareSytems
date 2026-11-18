import os
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from dotenv import load_dotenv

load_dotenv()
BASE_DIR = Path(__file__).resolve().parent

private_path = BASE_DIR / os.getenv("JWT_PRIVATE_KEY_PATH", "keys/jwt_private.pem")
public_path = BASE_DIR / os.getenv("JWT_PUBLIC_KEY_PATH", "keys/jwt_public.pem")
passphrase = os.getenv("JWT_KEY_PASSPHRASE")

if not passphrase:
    sys.exit("JWT_KEY_PASSPHRASE is missing from .env")
if private_path.exists() and "--force" not in sys.argv:
    sys.exit(f"{private_path} already exists. Use --force to replace it.")

private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

private_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.BestAvailableEncryption(passphrase.encode()),
)
public_pem = private_key.public_key().public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo,
)

private_path.parent.mkdir(parents=True, exist_ok=True)
private_path.write_bytes(private_pem)
public_path.write_bytes(public_pem)
print("Created", private_path, "and", public_path)
