"""
Cryptographic utilities for secure communication
"""
import base64
import secrets
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Generate a key for symmetric encryption
def generate_key():
    return Fernet.generate_key()

# Create a cipher using the generated key
def get_cipher(key):
    return Fernet(key)

# Encrypt data with Fernet
def encrypt_data(cipher, data):
    if isinstance(data, str):
        data = data.encode()
    return cipher.encrypt(data)

# Decrypt data with Fernet
def decrypt_data(cipher, encrypted_data):
    return cipher.decrypt(encrypted_data)

# Base64 URL-safe encoding
def base64_encode(data):
    if isinstance(data, str):
        data = data.encode()
    return base64.urlsafe_b64encode(data).decode()

# Base64 URL-safe decoding
def base64_decode(data):
    return base64.urlsafe_b64decode(data.encode()).decode()

# Generate a secure random token
def generate_token(length=16):
    return secrets.token_hex(length)

# Generate a secure nonce for challenge-response
def generate_nonce(length=8):
    return secrets.token_hex(length)

# Hash a challenge-response using a shared secret
def hash_challenge(challenge, shared_secret):
    digest = hashes.Hash(hashes.SHA256())
    digest.update(challenge.encode())
    digest.update(shared_secret.encode())
    return digest.finalize().hex()