import datetime
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes

from common import (
    generate_private_key,
    private_key_pem,
    certificate_pem,
    ca_subject,
    one_day,
    ca_validity_days,
)


__private_key = generate_private_key()

__builder = (
    x509.CertificateBuilder()
    .subject_name(ca_subject)
    .issuer_name(ca_subject)
    .not_valid_before(datetime.datetime.today() - one_day)
    .not_valid_after(
        datetime.datetime.today() + datetime.timedelta(days=ca_validity_days)
    )
    .serial_number(x509.random_serial_number())
    .public_key(__private_key.public_key())
    .add_extension(
        x509.BasicConstraints(ca=True, path_length=None),
        critical=True,
    )
    .add_extension(
        x509.KeyUsage(
            digital_signature=True,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=True,
            crl_sign=True,
            encipher_only=False,
            decipher_only=False,
        ),
        critical=True,
    )
    .add_extension(
        x509.SubjectKeyIdentifier.from_public_key(__private_key.public_key()),
        critical=False,
    )
)

__certificate = __builder.sign(
    private_key=__private_key,
    algorithm=hashes.SHA256(),
    backend=default_backend(),
)

with open("out/ca.pem", "w", encoding="utf-8") as _cert:
    _cert.write(certificate_pem(__certificate))

with open("out/ca.key", "w", encoding="utf-8") as _key:
    _key.write(private_key_pem(__private_key))
