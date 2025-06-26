# encryption.py

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import os

def generate_key_from_password(password):
    """Generate a Fernet key from a password using PBKDF2"""
    # Use a static salt (you could also store/transmit this with the message)
    salt = b'steganography_salt'
    
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key

def encrypt_message(message, password):
    """Encrypt a message using a password"""
    key = generate_key_from_password(password)
    f = Fernet(key)
    return f.encrypt(message.encode())

def decrypt_message(encrypted_message, password):
    """Decrypt a message using a password"""
    key = generate_key_from_password(password)
    f = Fernet(key)
    return f.decrypt(encrypted_message).decode()
