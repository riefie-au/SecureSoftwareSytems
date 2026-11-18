from fastapi import Response

from tokens import ACCESS_TOKEN_MINUTES

ACCESS_COOKIE = "access_token"


def set_access_cookie(response: Response, token: str) -> None:
    response.set_cookie(
        ACCESS_COOKIE,
        token,
        max_age=ACCESS_TOKEN_MINUTES * 60,  
        path="/",
        httponly=True,                      
        secure=True,                       
        samesite="strict",                
    )


def clear_access_cookie(response: Response) -> None:
    response.delete_cookie(ACCESS_COOKIE, path="/", httponly=True, secure=True, samesite="strict")
