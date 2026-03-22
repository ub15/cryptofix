import hashlib
from Crypto.Cipher import AES

key = b"hardcoded_secret"
iv = b"0000000000000000"

def encrypt(msg):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(msg)

def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()

def derive_key(password, salt):
    return hashlib.pbkdf2_hmac('sha256', password, salt, 1000)
