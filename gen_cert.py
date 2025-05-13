import datetime
import sys

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.serialization.pkcs12 import (
    serialize_key_and_certificates,
)
from cryptography.x509.oid import NameOID

from common import (
    ca_subject,
    cert_validity_days,
    certificate_pem,
    generate_private_key,
    one_day,
    private_key_pem,
)

__private_key = generate_private_key()
with open("out/ca.key", "rb") as _ca_key:
    __root_key = load_pem_private_key(_ca_key.read(), None)

__builder = (
    x509.CertificateBuilder()
    .subject_name(
        x509.Name(
            [
                x509.NameAttribute(NameOID.COMMON_NAME, sys.argv[1]),
            ]
        )
    )
    .issuer_name(ca_subject)
    .not_valid_before(datetime.datetime.today() - one_day)
    .not_valid_after(
        datetime.datetime.today() + datetime.timedelta(days=cert_validity_days)
    )
    .serial_number(x509.random_serial_number())
    .public_key(__private_key.public_key())
    .add_extension(
        x509.ExtendedKeyUsage(
            [
                x509.ExtendedKeyUsageOID.CLIENT_AUTH,
                x509.ExtendedKeyUsageOID.SERVER_AUTH,
            ]
        ),
        critical=False,
    )
    .add_extension(
        x509.SubjectAlternativeName(
            [
                x509.DNSName(sys.argv[1]),
            ]
        ),
        critical=True,
    )
    .add_extension(
        x509.SubjectKeyIdentifier.from_public_key(__private_key.public_key()),
        critical=False,
    )
)
__certificate = __builder.sign(
    private_key=__root_key,
    algorithm=hashes.SHA256(),
    backend=default_backend(),
)

with open(f"out/cert_{sys.argv[1]}.pem", "w", encoding="utf-8") as _cert:
    _cert.write(certificate_pem(__certificate))

with open(f"out/cert_{sys.argv[1]}.key", "w", encoding="utf-8", mode=0o600) as _key:
    _key.write(private_key_pem(__private_key))

# Create .pfx for Windows
with open(f"out/cert_{sys.argv[1]}.pfx", "wb") as _pfx:
    _pfx.write(serialize_key_and_certificates(None, key=__private_key, cert=__certificate))
