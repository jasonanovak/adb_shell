# Copyright (c) 2026 adb_shell contributors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0

"""Generate the self-signed X.509 certificate used by ADB Wi-Fi pairing.

Matches the format produced by ``adb/crypto/x509_generator.cpp`` in the AOSP
``adb`` source. The Android pairing server does not validate the peer
certificate (the SPAKE2 PAKE provides authentication), but a valid TLS 1.3
handshake still requires a cert + key on the client side.

* :func:`generate_x509_certificate`
"""


from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


_CERT_LIFETIME = timedelta(days=10 * 365)
_NAME = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Android"),
    x509.NameAttribute(NameOID.COMMON_NAME, "Adb"),
])


def generate_x509_certificate(private_key):
    """Generate a self-signed X.509 certificate for ADB Wi-Fi pairing.

    Parameters
    ----------
    private_key : cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey
        The host's RSA 2048 ADB private key. The certificate's public key
        is derived from it and the cert is signed with it (self-signed).

    Returns
    -------
    cryptography.x509.Certificate
        A self-signed certificate. Use
        :func:`certificate_to_pem` or the standard ``cryptography``
        serialization API to encode it for ``pyOpenSSL``.
    """
    if not isinstance(private_key, rsa.RSAPrivateKey):
        raise TypeError("private_key must be an RSAPrivateKey")

    now = datetime.now(timezone.utc)
    public_key = private_key.public_key()

    builder = (
        x509.CertificateBuilder()
        .subject_name(_NAME)
        .issuer_name(_NAME)
        .public_key(public_key)
        .serial_number(1)
        .not_valid_before(now)
        .not_valid_after(now + _CERT_LIFETIME)
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
            x509.SubjectKeyIdentifier.from_public_key(public_key),
            critical=False,
        )
    )

    return builder.sign(private_key, hashes.SHA256())


def certificate_to_pem(cert):
    """Serialize an X.509 certificate to PEM bytes."""
    return cert.public_bytes(serialization.Encoding.PEM)


def load_rsa_private_key_pem(pem_bytes):
    """Load a PEM-encoded RSA private key as a ``cryptography`` key object.

    Helper for callers who have a PEM blob (e.g. the contents of an ADB
    private key file) and need to feed it through
    :func:`generate_x509_certificate`.
    """
    key = serialization.load_pem_private_key(pem_bytes, password=None)
    if not isinstance(key, rsa.RSAPrivateKey):
        raise ValueError("expected an RSA private key in PEM input")
    return key


def private_key_to_pem(private_key):
    """Serialize an RSA private key to PKCS#8 PEM bytes (no encryption)."""
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
