# crypto_utils.py

import hashlib
import os
import base64
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from Crypto.Cipher import AES
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import hmac

def generate_salt():
    return os.urandom(32)

def hash_password(password, salt):
    key = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt,
        100000
    )
    return key

def verify_password(stored_hash, stored_salt, provided_password):
    new_hash = hash_password(provided_password, stored_salt)
    return new_hash == stored_hash

def generate_rsa_keypair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

def save_private_key(private_key, password, filepath):
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(
            password.encode()
        )
    )
    with open(filepath, 'wb') as f:
        f.write(pem)

def save_public_key(public_key, filepath):
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open(filepath, 'wb') as f:
        f.write(pem)

def load_private_key(filepath, password):
    with open(filepath, 'rb') as f:
        private_key = serialization.load_pem_private_key(
            f.read(),
            password=password.encode(),
            backend=default_backend()
        )
    return private_key

def load_public_key(filepath):
    with open(filepath, 'rb') as f:
        public_key = serialization.load_pem_public_key(
            f.read(),
            backend=default_backend()
        )
    return public_key

def encrypt_data(data, key):
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(data.encode())
    
    return {
        'ciphertext': base64.b64encode(ciphertext).decode(),
        'nonce': base64.b64encode(cipher.nonce).decode(),
        'tag': base64.b64encode(tag).decode()
    }

def decrypt_data(encrypted_data, key):
    cipher = AES.new(
        key,
        AES.MODE_GCM,
        nonce=base64.b64decode(encrypted_data['nonce'])
    )
    
    plaintext = cipher.decrypt_and_verify(
        base64.b64decode(encrypted_data['ciphertext']),
        base64.b64decode(encrypted_data['tag'])
    )
    
    return plaintext.decode()


def encrypt_data(data, key):
    """Encrypt data using AES-GCM"""
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(data.encode())
    
    return {
        'ciphertext': base64.b64encode(ciphertext).decode(),
        'nonce': base64.b64encode(cipher.nonce).decode(),
        'tag': base64.b64encode(tag).decode()
    }

def decrypt_data(encrypted_data, key):
    """Decrypt data using AES-GCM"""
    cipher = AES.new(
        key,
        AES.MODE_GCM,
        nonce=base64.b64decode(encrypted_data['nonce'])
    )
    
    plaintext = cipher.decrypt_and_verify(
        base64.b64decode(encrypted_data['ciphertext']),
        base64.b64decode(encrypted_data['tag'])
    )
    
    return plaintext.decode()