import json
import os
from crypto_utils import encrypt_data, decrypt_data
from user_login import session

def add_contact():
    """Add a new contact"""
    if not session.email:
        print("Error: Not logged in.")
        return
    
    print("Enter Full Name:", end=" ")
    full_name = input()
    
    print("Enter Email Address:", end=" ")
    contact_email = input().lower()
    
    # Validate email
    if contact_email == session.email:
        print("Error: Cannot add yourself as a contact.")
        return
    
    # Load existing contacts
    contacts = load_contacts()
    
    # Add or update contact
    contacts[contact_email] = {
        'full_name': full_name,
        'email': contact_email
    }
    
    # Save contacts
    save_contacts(contacts)
    print("Contact Added.")

def load_contacts():
    """Load and decrypt contacts"""
    contacts_file = f"data/contacts/{session.email}.json"
    
    if not os.path.exists(contacts_file):
        return {}
    
    with open(contacts_file, 'r') as f:
        encrypted_data = json.load(f)
    
    # Decrypt contacts using session master key
    plaintext = decrypt_data(encrypted_data, session.master_key)
    return json.loads(plaintext)

def save_contacts(contacts):
    """Encrypt and save contacts"""
    os.makedirs(f"data/contacts", exist_ok=True)
    
    # Encrypt contacts using session master key
    plaintext = json.dumps(contacts)
    encrypted_data = encrypt_data(plaintext, session.master_key)
    
    contacts_file = f"data/contacts/{session.email}.json"
    with open(contacts_file, 'w') as f:
        json.dump(encrypted_data, f, indent=4)