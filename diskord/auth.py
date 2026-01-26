from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
import bcrypt
import hashlib
import secrets

def _pw_digest(password: str) -> bytes:
    return hashlib.sha256(password.encode("utf-8")).digest()

def hash_password(password: str) -> str:
    salt = bcrypt.gensalt(rounds=12)
    return bcrypt.hashpw(_pw_digest(password), salt).decode("utf-8")

def verify_password(password: str, stored_hash: str) -> bool:
    try:
        return bcrypt.checkpw(_pw_digest(password), stored_hash.encode("utf-8"))
    except Exception:
        return False

def new_csrf() -> str:
    return secrets.token_urlsafe(24)

class SessionSigner:
    def __init__(self, secret: str):
        self.s = URLSafeTimedSerializer(secret, salt="pycord-session")

    def sign(self, user_id: str, csrf: str) -> str:
        return self.s.dumps({"uid": user_id, "csrf": csrf})

    def verify(self, token: str, max_age_seconds: int = 60 * 60 * 24 * 7) -> dict | None:
        try:
            data = self.s.loads(token, max_age=max_age_seconds)
            if not isinstance(data, dict):
                return None
            if "uid" not in data or "csrf" not in data:
                return None
            return data
        except (BadSignature, SignatureExpired):
            return None
