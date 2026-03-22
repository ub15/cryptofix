from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2

SECRET_KEY = b"mysecretkey12345"
STATIC_IV = b"1234567890123456"

def encrypt_data(plaintext):
    cipher = AES.new(SECRET_KEY, AES.MODE_ECB)
    return cipher.encrypt(plaintext)

def derive_key(password):
    salt = b"staticsalt"
    key = PBKDF2(password, salt, dkLen=32, count=1000)
    return key
