import os
import json
import base64
import getpass
from crypto_utils import verify_password
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from crypto_utils import verify_password, hash_password

class UserSession:
    """Store session data in memory"""
    def __init__(self):
        self.email = None
        self.full_name = None
        self.private_key = None
        self.public_key = None
        self.master_key = None  # For encrypting contacts (Milestone 3)
    
    def clear(self):
        """Clear sensitive data from memory"""
        self.email = None
        self.full_name = None
        self.private_key = None
        self.public_key = None
        self.master_key = None

# Global session object
session = UserSession()

def login_user():
    """Handle user login"""
    max_attempts = 3
    attempts = 0
    
    while attempts < max_attempts:
        print("Enter Email Address:", end=" ")
        email = input().lower()
        #FIXME change I made for testing:
        #password = getpass.getpass("Enter Password: ")
        password = input("Enter Password: ")
        if authenticate_user(email, password):
            print("Welcome to SecureDrop.")
            print('Type "help" For Commands.')
            return True
        else:
            print("Email and Password Combination Invalid.")
            attempts += 1
    
    print("Too many failed attempts. Exiting.")
    return False

def authenticate_user(email, password):
    """Authenticate user and load session data"""
    # Load user data
    if not os.path.exists("data/users.json"):
        return False
    
    with open("data/users.json", 'r') as f:
        users = json.load(f)
    
    if email not in users:
        return False
    
    user_data = users[email]
    
    # Verify password
    stored_hash = base64.b64decode(user_data["password_hash"])
    stored_salt = base64.b64decode(user_data["salt"])
    
    if not verify_password(stored_hash, stored_salt, password):
        return False
    
    # Authentication successful - load session data
    session.email = email
    session.full_name = user_data["full_name"]
    
    # Load private key
    key_path = f"data/keys/{email}/private_key.pem"
    with open(key_path, 'rb') as f:
        session.private_key = serialization.load_pem_private_key(
            f.read(),
            password=password.encode(),
            backend=default_backend()
        )
    
    # Load public key
    with open(user_data["public_key_path"], 'rb') as f:
        session.public_key = serialization.load_pem_public_key(
            f.read(),
            backend=default_backend()
        )
    
    # Derive master key from password for encrypting local data
    session.master_key = hash_password(password, stored_salt)[:32]  # AES-256 key
    
    return True