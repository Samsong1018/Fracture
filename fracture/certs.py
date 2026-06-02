"""
CA and per-domain certificate generation for HTTPS MITM.
"""

import datetime
import ipaddress
import os
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

CERT_DIR = Path.home() / ".fracture" / "certs"
CA_CERT_PATH = Path.home() / ".fracture" / "ca.crt"
CA_KEY_PATH = Path.home() / ".fracture" / "ca.key"


def _generate_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def ensure_ca() -> tuple[x509.Certificate, rsa.RSAPrivateKey]:
    """Load existing CA or generate a new one."""
    CA_CERT_PATH.parent.mkdir(parents=True, exist_ok=True)
    CERT_DIR.mkdir(parents=True, exist_ok=True)

    if CA_CERT_PATH.exists() and CA_KEY_PATH.exists():
        ca_cert = x509.load_pem_x509_certificate(CA_CERT_PATH.read_bytes())
        ca_key = serialization.load_pem_private_key(CA_KEY_PATH.read_bytes(), password=None)
        return ca_cert, ca_key

    ca_key = _generate_key()
    name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "Fracture CA"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Fracture"),
    ])
    now = datetime.datetime.utcnow()
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())
    )

    CA_CERT_PATH.write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))
    CA_KEY_PATH.write_bytes(
        ca_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )
    print(f"[certs] New CA generated. Install it in your browser:\n  {CA_CERT_PATH}")
    return ca_cert, ca_key


def get_domain_cert(hostname: str, ca_cert: x509.Certificate, ca_key) -> tuple[Path, Path]:
    """Return (cert_path, key_path) for hostname, generating if needed."""
    cert_path = CERT_DIR / f"{hostname}.crt"
    key_path = CERT_DIR / f"{hostname}.key"

    if cert_path.exists() and key_path.exists():
        return cert_path, key_path

    key = _generate_key()
    now = datetime.datetime.utcnow()

    san_list = [x509.DNSName(hostname)]
    try:
        san_list.append(x509.IPAddress(ipaddress.ip_address(hostname)))
    except ValueError:
        pass

    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)]))
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(x509.SubjectAlternativeName(san_list), critical=False)
        .sign(ca_key, hashes.SHA256())
    )

    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )
    return cert_path, key_path
