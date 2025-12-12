import json
import os
from crypto_utils import encrypt_data, decrypt_data
from user_login import session

def load_contacts():
    contacts_file = f"data/contacts/{session.email}.json"
    if not os.path.exists(contacts_file):
        return {}
    with open(contacts_file, "r") as f:
        encrypted_data = json.load(f)
    plaintext = decrypt_data(encrypted_data, session.master_key)
    return json.loads(plaintext)

def save_contacts(contacts):
    os.makedirs("data/contacts", exist_ok=True)
    plaintext = json.dumps(contacts)
    encrypted_data = encrypt_data(plaintext, session.master_key)
    contacts_file = f"data/contacts/{session.email}.json"
    with open(contacts_file, "w") as f:
        json.dump(encrypted_data, f, indent=4)

def get_contact_list():
    contact_list = load_contacts()
    for contact in contact_list:
        print(contact)

def add_contact():
    if session.email is None: #session.email not initialized, not logged in
        print("Error: Not logged in.")
        return
    full_name = input("Enter Full Name: ").strip()
    contact_email = input("Enter Email Address: ").strip().lower()
    if contact_email == session.email:
        print("Error: Cannot add yourself as a contact.")
        return
    contacts = load_contacts()
    contacts[contact_email] = {"full_name": full_name, "email": contact_email}
    save_contacts(contacts)
    print("Contact Added.")