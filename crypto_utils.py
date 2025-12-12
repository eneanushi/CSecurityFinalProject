import os
import json
import base64
import hmac
import hashlib
from typing import Optional
from datetime import datetime, timezone, timedelta

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend

from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.x509 import BasicConstraints, KeyUsage, ExtendedKeyUsage, SubjectKeyIdentifier


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
    return hmac.compare_digest(new_hash, stored_hash)

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

def load_private_key(filepath: str, password: Optional[str]):
    with open(filepath, 'rb') as f:
        pem = f.read()
    pwd = None if password is None else password.encode()
    private_key = serialization.load_pem_private_key(

        pem,
        password=pwd,
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


# ========================
# RSA ENCRYPTION 
# ========================

def encrypt_using_rsa(data, public_key):
    encrypted = public_key.encrypt(
        data.encode(),
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return base64.b64encode(encrypted).decode()

def decrypt_using_rsa(encrypted_data, private_key):
    decrypted = private_key.decrypt(
        base64.b64decode(encrypted_data),
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted.decode()

def encrypt_using_rsa_bytes(data_bytes: bytes, public_key):
    encrypted = public_key.encrypt(
        data_bytes,
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted

def decrypt_using_rsa_bytes(encrypted_bytes: bytes, private_key):
    decrypted = private_key.decrypt(
        encrypted_bytes,
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted


# ========================
# SIGNING (PSS)
# ========================

def signing(data, private_key):
    signature = private_key.sign(
        data.encode(),
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )
    return base64.b64encode(signature).decode()

def verify_signature(data, signature, public_key):
    try:
        public_key.verify(
            base64.b64decode(signature),
            data.encode(),
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False
    
# ========================
# SIGNING AND VERIFYING (bytes)
# ========================

def sign_bytes(data_bytes: bytes, private_key) -> bytes:
    signature = private_key.sign(
        data_bytes,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )
    return signature

def verify_signature_bytes(data_bytes: bytes, signature_bytes: bytes, public_key)-> bool:
    try:
        public_key.verify(
            signature_bytes,
            data_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False

# -----------------------
# Certificates
# -----------------------
def load_public_key_cert(path):
    """Return public key from a certificate file (PEM)."""
    with open(path, "rb") as cert_file:
        cert = x509.load_pem_x509_certificate(cert_file.read(), default_backend())
    return cert.public_key()

def load_public_key_cert_from_text(cert_text):
    cert = x509.load_pem_x509_certificate(cert_text.encode(), default_backend())
    return cert.public_key()

def _load_ca_public_key_prefer_cert():
    """Prefer the CA certificate's public key (data/ca_certificate.pem). Fallback to data/ca_public_key.pem."""
    cert_path = "data/ca_certificate.pem"
    key_path = "data/ca_public_key.pem"
    try:
        if os.path.exists(cert_path):
            with open(cert_path, "rb") as f:
                cert = x509.load_pem_x509_certificate(f.read(), default_backend())
                return cert.public_key()
        if os.path.exists(key_path):
            return load_public_key(key_path)
    except Exception:
        pass
    raise FileNotFoundError("CA public key or certificate not found (expected data/ca_certificate.pem or data/ca_public_key.pem)")

def load_ca_private_key(password="ca_password"):
    return load_private_key("data/ca_private_key.pem", password)

def load_ca_public_key():
    return _load_ca_public_key_prefer_cert()

def create_user_certificate(email, user_public_key, ca_private_key, ca_cert_path="data/ca_certificate.pem"):

    if os.path.exists(ca_cert_path):
        with open(ca_cert_path, "rb") as f:
            ca_cert = x509.load_pem_x509_certificate(f.read(), default_backend())
        issuer = ca_cert.subject
    else:
        issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "SecureDrop CA")])

    subject = x509.Name([
        x509.NameAttribute(NameOID.EMAIL_ADDRESS, email),
        x509.NameAttribute(NameOID.COMMON_NAME, f"SecureDrop User {email}")
    ])

    now = datetime.now(timezone.utc)
    builder = x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(user_public_key).serial_number(
        x509.random_serial_number()
    ).not_valid_before(now - timedelta(minutes=1)).not_valid_after(now + timedelta(days=180))

    builder = builder.add_extension(BasicConstraints(ca=False, path_length=None), critical=True)
    builder = builder.add_extension(
        KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=True,
                 data_encipherment=False, key_agreement=False, key_cert_sign=False, crl_sign=False,
                 encipher_only=False, decipher_only=False),
        critical=True
    )
    builder = builder.add_extension(ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH, ExtendedKeyUsageOID.EMAIL_PROTECTION]), critical=False)
    builder = builder.add_extension(SubjectKeyIdentifier.from_public_key(user_public_key), critical=False)

    cert = builder.sign(private_key=ca_private_key, algorithm=hashes.SHA256(), backend=default_backend())
    return cert

def save_certificate(cert, path):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

def extract_email_from_cert(cert_data):
    try:
        if isinstance(cert_data, str):
            cert_bytes = cert_data.encode()
        else:
            cert_bytes = cert_data
        cert = x509.load_pem_x509_certificate(cert_bytes, default_backend())
        emails = cert.subject.get_attributes_for_oid(NameOID.EMAIL_ADDRESS)
        if not emails:
            return None
        return emails[0].value
    except Exception:
        return None

def verify_certificate_data(cert_data, ca_public_key):
   
    try:
        if isinstance(cert_data, str):
            cert_bytes = cert_data.encode()
        else:
            cert_bytes = cert_data

        cert = x509.load_pem_x509_certificate(cert_bytes, default_backend())

        ca_public_key.verify(cert.signature, cert.tbs_certificate_bytes, PKCS1v15(), cert.signature_hash_algorithm)

        now = datetime.now(timezone.utc)

        if hasattr(cert, "not_valid_before_utc"):
            not_before = cert.not_valid_before_utc
            not_after = cert.not_valid_after_utc
        else:
            naive_before = cert.not_valid_before
            naive_after = cert.not_valid_after

            not_before = naive_before.replace(tzinfo=timezone.utc)
            not_after = naive_after.replace(tzinfo=timezone.utc)

        if not (not_before <= now <= not_after):
            return False

        email = extract_email_from_cert(cert_bytes)
        if email is None or "@" not in email:
            return False

        return True
    except Exception:
        return False

def read_certificate_file(file_path):
    with open(file_path, "rb") as f:
        return f.read()

def save_certificate_from_data(cert_data, email):
    os.makedirs("data/certificates", exist_ok=True)
    cert_path = f"data/certificates/{email}.crt"
    if isinstance(cert_data, str):
        cert_data = cert_data.encode()
    with open(cert_path, "wb") as f:
        f.write(cert_data)
    return cert_path