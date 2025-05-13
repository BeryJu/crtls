import datetime
from http.server import SimpleHTTPRequestHandler
from os import chmod
from socketserver import TCPServer

import click
from common import (
    ca_subject,
    ca_validity_days,
    cert_validity_days,
    certificate_pem,
    generate_private_key,
    one_day,
    private_key_pem,
)
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import (
    BestAvailableEncryption,
    NoEncryption,
    load_pem_private_key,
)
from cryptography.hazmat.primitives.serialization.pkcs12 import (
    serialize_key_and_certificates,
)
from cryptography.x509.oid import NameOID

opt_out_dir = click.option(
    "--out-dir",
    default="out/",
    help="Directory to write output files to.",
)


@click.group("cli", help="Certificate generation helper")
def cli(): ...


@cli.group("ca", help="Commands related to Certificate Authority management.")
def ca(): ...


@ca.command("generate", help="Generate a new Certificate Authority.")
@click.option("--validity-days", default=ca_validity_days, type=int)
@opt_out_dir
def ca_generate(validity_days: int, out_dir: str):
    __private_key = generate_private_key()

    __builder = (
        x509.CertificateBuilder()
        .subject_name(ca_subject)
        .issuer_name(ca_subject)
        .not_valid_before(datetime.datetime.today() - one_day)
        .not_valid_after(
            datetime.datetime.today() + datetime.timedelta(days=validity_days)
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

    with open(f"{out_dir}/ca.pem", "w", encoding="utf-8") as _cert:
        _cert.write(certificate_pem(__certificate))

    with open(f"{out_dir}/ca.key", "w", encoding="utf-8") as _key:
        _key.write(private_key_pem(__private_key))
        chmod(_key.fileno(), 0o600)


@cli.group("cert", help="Commands related to Certificate management.")
def cert(): ...


@cert.command("generate", help="Generate a new Certificate.")
@click.option("--validity-days", default=cert_validity_days, type=int)
@click.option("--subject-alt-names", multiple=True, default=[])
@click.option("--pfx-password", type=str)
@opt_out_dir
@click.argument("subject")
def cert_generate(
    validity_days: int,
    out_dir: str,
    subject: str,
    subject_alt_names: list[str],
    pfx_password: str | None = None,
):
    __private_key = generate_private_key()
    with open(f"{out_dir}/ca.key", "rb") as _ca_key:
        __root_key = load_pem_private_key(_ca_key.read(), None)
    other_san = [x509.DNSName(x) for x in subject_alt_names]
    __builder = (
        x509.CertificateBuilder()
        .subject_name(
            x509.Name(
                [
                    x509.NameAttribute(NameOID.COMMON_NAME, subject),
                ]
            )
        )
        .issuer_name(ca_subject)
        .not_valid_before(datetime.datetime.today() - one_day)
        .not_valid_after(
            datetime.datetime.today() + datetime.timedelta(days=validity_days)
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
            x509.SubjectAlternativeName([x509.DNSName(subject), *other_san]),
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

    with open(f"{out_dir}/cert_{subject}.pem", "w", encoding="utf-8") as _cert:
        _cert.write(certificate_pem(__certificate))

    with open(
        f"{out_dir}/cert_{subject}.key", "w", encoding="utf-8"
    ) as _key:
        _key.write(private_key_pem(__private_key))
        chmod(_key.fileno(), 0o600)

    # Create .pfx for Windows
    with open(f"{out_dir}/cert_{subject}.pfx", "wb") as _pfx:
        _pfx.write(
            serialize_key_and_certificates(
                name=None,
                key=__private_key,
                cert=__certificate,
                cas=None,
                encryption_algorithm=(
                    BestAvailableEncryption(pfx_password.encode())
                    if pfx_password
                    else NoEncryption()
                ),
            )
        )


@cli.command("serve", help="Serve generated files on the network.")
@click.option("--port", default=8000, type=int)
@opt_out_dir
def serve(port: int, out_dir: str):
    class server(SimpleHTTPRequestHandler):

        def __init__(self, request, client_address, server):
            super().__init__(request, client_address, server, directory=out_dir)

    httpd = TCPServer(("", port), server)

    print("serving at port", port)
    try:
        httpd.serve_forever()
    finally:
        httpd.server_close()


if __name__ == "__main__":
    cli(prog_name="crtls")
