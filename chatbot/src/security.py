import base64
import hashlib
import hmac
import secrets

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
