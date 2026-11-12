# scratch_tokens.py (delete afterwards)
from tokens import issue_access_token, decode_token, TYPE_ACCESS, InvalidToken

class U: id = 1; role = "Customer"

token, jti, exp = issue_access_token(U)
print("access token:", token)
print(decode_token(token, TYPE_ACCESS)["sub"])      # prints 1
try:
    decode_token(token[:-5] + "AAAAA", TYPE_ACCESS)  # damaged signature
except InvalidToken as e:
    print("rejected:", e)