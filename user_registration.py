import json
import os
import base64
from crypto_utils import *

def register_user():
    """Handle user registration"""
    print("Enter Full Name:", end=" ")
    full_name = input()
    
    print("Enter Email Address:", end=" ")
    email = input().lower()  # Use lowercase for consistency
    
    # Check if user already exists
    if user_exists(email):
        print("User already registered.")
        return False
    
    # Get password with confirmation
    while True:
        password = input("Enter Password: ")
        confirm_password = input("Re-enter Password: ")
        
        if password == confirm_password:
            print("Passwords Match.")
            break
        else:
            print("Passwords do not match. Try again.")
    
    # Generate salt and hash password
    salt = generate_salt()
    password_hash = hash_password(password, salt)
    
    # Generate RSA key pair for authentication
    private_key, public_key = generate_rsa_keypair()
    
    # Create user directory
    user_dir = f"data/keys/{email}"
    os.makedirs(user_dir, exist_ok=True)
    
    # Save keys
    save_private_key(private_key, password, f"{user_dir}/private_key.pem")
    save_public_key(public_key, f"{user_dir}/public_key.pem")
    
    ca_private_key = load_ca_private_key()
    user_cert = create_user_certificate(email, public_key, ca_private_key)
    os.makedirs("data/certificate", exist_ok=True)
    save_certificate(user_cert, f"data/certificate/{email}.crt")
    
    # Store user data
    user_data = {
        "full_name": full_name,
        "email": email,
        "password_hash": base64.b64encode(password_hash).decode(),
        "salt": base64.b64encode(salt).decode(),
        "public_key_path": f"{user_dir}/public_key.pem",
        "user_cert_path": f"data/certificate/{email}.crt"
    }
    
    save_user_data(user_data)
    print("User Registered.")
    return True

def user_exists(email):
    """Check if user already exists"""
    if not os.path.exists("data/users.json"):
        return False
    
    with open("data/users.json", 'r') as f:
        users = json.load(f)
        return email in users

def save_user_data(user_data):
    """Save user data to JSON file"""
    os.makedirs("data", exist_ok=True)
    
    users = {}
    if os.path.exists("data/users.json"):
        with open("data/users.json", 'r') as f:
            users = json.load(f)
    
    users[user_data["email"]] = user_data
    
    with open("data/users.json", 'w') as f:
        json.dump(users, f, indent=4)