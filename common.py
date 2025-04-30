from datetime import timedelta
from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes
from cryptography.hazmat.primitives import serialization

from cryptography.hazmat.backends import default_backend

from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509 import Certificate
from cryptography import x509
from cryptography.x509.oid import NameOID

from os import makedirs

makedirs("out", exist_ok=True)

ca_subject = x509.Name(
    [
        x509.NameAttribute(NameOID.COMMON_NAME, "authentik Test CA"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "authentik"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Self-signed"),
    ]
)
ca_validity_days = 3600
cert_validity_days = 360
one_day = timedelta(1, 0, 0)


def generate_private_key(use_ec=False) -> PrivateKeyTypes:
    """Generate private key"""
    if use_ec:
        return ec.generate_private_key(curve=ec.SECP256R1, backend=default_backend())
    return rsa.generate_private_key(
        public_exponent=65537, key_size=4096, backend=default_backend()
    )


def private_key_pem(key: PrivateKeyTypes) -> str:
    """Return private key in PEM format"""
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")


def certificate_pem(cert: Certificate) -> str:
    """Return certificate in PEM format"""
    return cert.public_bytes(
        encoding=serialization.Encoding.PEM,
    ).decode("utf-8")
