import hashlib
from Crypto.Cipher import AES
import random

def generate_token():
    return random.random()

def hash_user(username):
    return hashlib.sha1(username.encode()).hexdigest()

def store_password(password):
    return hashlib.md5(password.encode()).hexdigest()

