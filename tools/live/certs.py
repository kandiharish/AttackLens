"""Throwaway test CA + server certificate (SAN localhost / 127.0.0.1) for live vendor containers.

Written under data/live/<vendor>/tls/ (git-ignored), regenerated on every `up`. The key is unencrypted: it protects
a loopback-only container that is deleted after the test. Uses `cryptography` (already a dependency of the venv).
"""

from __future__ import annotations

import datetime as dt
import ipaddress
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


def _key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _pem_key(k: rsa.RSAPrivateKey) -> bytes:
    return k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
                           serialization.NoEncryption())


def make(out: Path, cn: str = "attacklens-live") -> dict[str, Path]:
    """-> {ca: ca.pem, cert: server.crt, key: server.key, bundle: server.pem (cert + key + CA, Splunk layout)}."""
    out.mkdir(parents=True, exist_ok=True)
    now = dt.datetime.now(dt.timezone.utc)
    ca_key = _key()
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, f"{cn} test CA")])
    ca = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name).public_key(ca_key.public_key())
          .serial_number(x509.random_serial_number()).not_valid_before(now - dt.timedelta(hours=1))
          .not_valid_after(now + dt.timedelta(days=2))
          .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
          .add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=True, crl_sign=True,
                                       content_commitment=False, key_encipherment=False, data_encipherment=False,
                                       key_agreement=False, encipher_only=False, decipher_only=False), critical=True)
          .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
          .sign(ca_key, hashes.SHA256()))
    srv_key = _key()
    srv = (x509.CertificateBuilder()
           .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")]))
           .issuer_name(ca_name).public_key(srv_key.public_key()).serial_number(x509.random_serial_number())
           .not_valid_before(now - dt.timedelta(hours=1)).not_valid_after(now + dt.timedelta(days=2))
           .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost"),
                                                       x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]),
                          critical=False)
           .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
           .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
           .sign(ca_key, hashes.SHA256()))
    ca_pem = ca.public_bytes(serialization.Encoding.PEM)
    crt_pem = srv.public_bytes(serialization.Encoding.PEM)
    key_pem = _pem_key(srv_key)
    paths = {"ca": out / "ca.pem", "cert": out / "server.crt", "key": out / "server.key", "bundle": out / "server.pem"}
    paths["ca"].write_bytes(ca_pem)
    paths["cert"].write_bytes(crt_pem)
    paths["key"].write_bytes(key_pem)
    paths["bundle"].write_bytes(crt_pem + key_pem + ca_pem)
    return paths
