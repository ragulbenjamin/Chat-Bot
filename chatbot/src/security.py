import base64
import hashlib
import hmac
import secrets
from datetime import datetime, timedelta, timezone

import jwt

from config import settings

SECRET_KEY = settings.secret_key.get_secret_value()
JWT_ALGORITHM = "HS256"

# Same scheme and storage format as Django's default hasher:
# pbkdf2_sha256$<iterations>$<salt>$<base64 hash>
ALGORITHM = "pbkdf2_sha256"
ITERATIONS = 600_000


def _pbkdf2(password: str, salt: str, iterations: int) -> str:
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), iterations)
    return base64.b64encode(digest).decode()


def hash_password(password: str) -> str:
    salt = secrets.token_urlsafe(16)
    return f"{ALGORITHM}${ITERATIONS}${salt}${_pbkdf2(password, salt, ITERATIONS)}"


def verify_password(password: str, hashed: str | None) -> bool:
    if not hashed:
        return False
    try:
        algorithm, iterations, salt, expected = hashed.split("$", 3)
    except ValueError:
        return False
    if algorithm != ALGORITHM:
        return False
    return hmac.compare_digest(_pbkdf2(password, salt, int(iterations)), expected)


# Checked against when the email is unknown, so a login takes the same time
# whether or not the account exists.
DUMMY_HASH = hash_password(secrets.token_urlsafe(16))


def password_fingerprint(hashed_password: str | None) -> str:
    """Changes whenever the password does, so sessions and tokens issued before a change stop working."""
    return hmac.new(SECRET_KEY.encode(), (hashed_password or "").encode(), hashlib.sha256).hexdigest()


def create_access_token(user_id: int, hashed_password: str | None) -> str:
    now = datetime.now(timezone.utc)
    claims = {
        "sub": str(user_id),
        "pwd": password_fingerprint(hashed_password)[:16],
        "iat": now,
        "exp": now + timedelta(minutes=settings.access_token_expire_minutes),
    }
    return jwt.encode(claims, SECRET_KEY, algorithm=JWT_ALGORITHM)


def decode_access_token(token: str) -> dict | None:
    """The token's claims, or None if it is malformed, tampered with or expired."""
    try:
        return jwt.decode(
            token, SECRET_KEY, algorithms=[JWT_ALGORITHM], options={"require": ["sub", "pwd", "exp"]}
        )
    except jwt.InvalidTokenError:
        return None
