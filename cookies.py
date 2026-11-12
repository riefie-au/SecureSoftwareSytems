from fastapi import Response

from tokens import ACCESS_TOKEN_MINUTES, MFA_PENDING_MINUTES

ACCESS_COOKIE = "access_token"
REFRESH_COOKIE = "refresh_token"
MFA_COOKIE = "mfa_token"

ACCESS_COOKIE_PATH = "/"
REFRESH_COOKIE_PATH = "/auth"    
MFA_COOKIE_PATH = "/"

REFRESH_TOKEN_DAYS = 7         

_FLAGS = {"httponly": True, "secure": True, "samesite": "strict"}


def set_auth_cookies(response: Response, access_token: str, refresh_token: str) -> None:
    response.set_cookie(ACCESS_COOKIE, access_token,
                        max_age=ACCESS_TOKEN_MINUTES * 60, path=ACCESS_COOKIE_PATH, **_FLAGS)
    response.set_cookie(REFRESH_COOKIE, refresh_token,
                        max_age=REFRESH_TOKEN_DAYS * 24 * 3600, path=REFRESH_COOKIE_PATH, **_FLAGS)


def clear_auth_cookies(response: Response) -> None:
    response.delete_cookie(ACCESS_COOKIE, path=ACCESS_COOKIE_PATH, **_FLAGS)
    response.delete_cookie(REFRESH_COOKIE, path=REFRESH_COOKIE_PATH, **_FLAGS)


def set_mfa_cookie(response: Response, mfa_token: str) -> None:
    response.set_cookie(MFA_COOKIE, mfa_token,
                        max_age=MFA_PENDING_MINUTES * 60, path=MFA_COOKIE_PATH, **_FLAGS)


def clear_mfa_cookie(response: Response) -> None:
    response.delete_cookie(MFA_COOKIE, path=MFA_COOKIE_PATH, **_FLAGS)