import os
from datetime import datetime, timezone, timedelta
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa

def ca_setup():
    # Create directories
    os.makedirs("data", exist_ok=True)
    os.makedirs("data/ca", exist_ok=True)

    # Generate CA private key
    ca_private_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    ca_public_key = ca_private_key.public_key()

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "SecureDrop CA"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SecureDrop"),
    ])

    now = datetime.now(timezone.utc)
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(ca_public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=3650))  # 10 years
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                key_encipherment=False,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(private_key=ca_private_key, algorithm=hashes.SHA256())
    )

    # Save CA private key (encrypted with passphrase for convenience)
    with open("data/ca_private_key.pem", "wb") as f:
        f.write(
            ca_private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.BestAvailableEncryption(b"ca_password"),
            )
        )

    # Save CA public key
    with open("data/ca_public_key.pem", "wb") as f:
        f.write(
            ca_public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )

    # Save CA cert
    with open("data/ca_certificate.pem", "wb") as f:
        f.write(ca_cert.public_bytes(serialization.Encoding.PEM))

    print("Created CA key and certificate in data/ (files: ca_private_key.pem, ca_public_key.pem, ca_certificate.pem)")

if __name__ == "__main__":
    ca_setup()
