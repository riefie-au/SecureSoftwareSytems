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
MFA_PENDING_MINUTES = 5
TYPE_ACCESS = "access"
TYPE_MFA_PENDING = "mfa_pending"


class InvalidToken(Exception):
    """Any token problem. The reason is for server logs only."""


def _resolve(path_value):
    path = Path(path_value)
    return path if path.is_absolute() else BASE_DIR / path


def _load_keys():
    private_path = _resolve(os.getenv("JWT_PRIVATE_KEY_PATH", "keys/jwt_private.pem"))
    public_path = _resolve(os.getenv("JWT_PUBLIC_KEY_PATH", "keys/jwt_public.pem"))
    passphrase = os.getenv("JWT_KEY_PASSPHRASE")
    if not passphrase:
        raise RuntimeError("JWT_KEY_PASSPHRASE is missing from .env")
    if not private_path.exists() or not public_path.exists():
        raise RuntimeError("JWT keys not found. Run: python generate_keys.py")
    private_key = serialization.load_pem_private_key(
        private_path.read_bytes(), password=passphrase.encode("utf-8"))
    public_key = serialization.load_pem_public_key(public_path.read_bytes())
    return private_key, public_key


PRIVATE_KEY, PUBLIC_KEY = _load_keys()


def _issue(subject, token_type, lifetime, extra=None):
    now = datetime.now(timezone.utc)
    expires_at = now + lifetime
    jti = str(uuid.uuid4())
    claims = {"sub": subject, "typ": token_type, "jti": jti, "iat": now, "nbf": now,
              "exp": expires_at, "iss": ISSUER, "aud": AUDIENCE}
    if extra:
        claims.update(extra)
    return jwt.encode(claims, PRIVATE_KEY, algorithm=ALGORITHM), jti, expires_at


def issue_access_token(user):
    return _issue(str(user.id), TYPE_ACCESS, timedelta(minutes=ACCESS_TOKEN_MINUTES),
                  {"role": user.role})


def issue_mfa_pending_token(user):
    token, _, _ = _issue(str(user.id), TYPE_MFA_PENDING, timedelta(minutes=MFA_PENDING_MINUTES))
    return token


def decode_token(token, expected_type):
    if not token:
        raise InvalidToken("no token")
    try:
        claims = jwt.decode(
            token, PUBLIC_KEY,
            algorithms=[ALGORITHM],               
            audience=AUDIENCE, issuer=ISSUER,
            options={"require": ["exp", "iat", "nbf", "sub", "jti", "iss", "aud", "typ"]},
            leeway=10,                         
        )
    except jwt.ExpiredSignatureError as exc:
        raise InvalidToken("expired") from exc
    except jwt.InvalidTokenError as exc:
        raise InvalidToken(type(exc).__name__) from exc
    if claims.get("typ") != expected_type:
        raise InvalidToken(f"wrong token type: {claims.get('typ')}")
    return claims
