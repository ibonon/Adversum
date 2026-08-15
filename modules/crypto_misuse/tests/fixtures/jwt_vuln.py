import jwt
def vulnerable_jwt():
    return jwt.encode({"some": "payload"}, key="secret", algorithm="none")
