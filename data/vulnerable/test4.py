import hashlib
import os
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

API_SECRET = "hardcoded_api_secret_123"
DB_PASSWORD = "admin1234"

def hash_token(token):
    return hashlib.md5(token.encode()).hexdigest()

def make_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=10000
    )
    return kdf.derive(password)
