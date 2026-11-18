import os
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import jwt
from cryptography.hazmat.primitives import serialization
from dotenv import load_dotenv

load_dotenv()
BASE_DIR = Path(__file__).resolve().parent

ALGORITHM = "RS256"
ISSUER = "securefin-auth"
AUDIENCE = "securefin-api"
ACCESS_TOKEN_MINUTES = 15


class InvalidToken(Exception):
    pass

def _load_keys():
    private_path = BASE_DIR / os.getenv("JWT_PRIVATE_KEY_PATH", "keys/jwt_private.pem")
    public_path = BASE_DIR / os.getenv("JWT_PUBLIC_KEY_PATH", "keys/jwt_public.pem")
    passphrase = os.getenv("JWT_KEY_PASSPHRASE")
    if not passphrase or not private_path.exists() or not public_path.exists():
        raise RuntimeError("JWT keys or passphrase missing. Check .env and run: python generate_keys.py")
    private_key = serialization.load_pem_private_key(private_path.read_bytes(), password=passphrase.encode())
    public_key = serialization.load_pem_public_key(public_path.read_bytes())
    return private_key, public_key


PRIVATE_KEY, PUBLIC_KEY = _load_keys()


def issue_access_token(user) -> str:
    now = datetime.now(timezone.utc)
    claims = {
        "sub": str(user.id),              
        "role": user.role,                 
        "jti": str(uuid.uuid4()),         
        "iat": now,                       
        "exp": now + timedelta(minutes=ACCESS_TOKEN_MINUTES),
        "iss": ISSUER,
        "aud": AUDIENCE,
    }
    return jwt.encode(claims, PRIVATE_KEY, algorithm=ALGORITHM)


def decode_token(token: str | None) -> dict:
    if not token:
        raise InvalidToken("no token")
    try:
        return jwt.decode(
            token,
            PUBLIC_KEY,
            algorithms=[ALGORITHM],        
            audience=AUDIENCE,
            issuer=ISSUER,
            options={"require": ["exp", "iat", "sub", "jti", "iss", "aud"]},
        )
    except jwt.InvalidTokenError as exc:   # also covers expired tokens
        raise InvalidToken(type(exc).__name__) from exc