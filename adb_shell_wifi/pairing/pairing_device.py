# Copyright (c) 2026 adb_shell contributors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0

"""Synchronous ADB Wi-Fi pairing client.

The :func:`pair` function opens a TCP connection to a device's pairing
server, completes a TLS 1.3 handshake using a self-signed certificate
backed by the host's ADB RSA key, then runs the SPAKE2 + AES-128-GCM
pairing handshake.

* :func:`pair`
* :class:`_PyOpenSSLTransport`
"""


import select
import socket
import time

from ..auth.x509 import (
    certificate_to_pem,
    generate_x509_certificate,
    load_rsa_private_key_pem,
    private_key_to_pem,
)
from .connection import PairingConnection, PairingException, make_peer_info_from_pubkey


_DEFAULT_TIMEOUT_S = 30.0


def _remaining(deadline):
    """Seconds remaining until ``deadline``, or ``None`` if no deadline."""
    if deadline is None:
        return None
    return max(0.0, deadline - time.monotonic())


def _retry_on_want(operation, sock, deadline):
    """Run a pyOpenSSL ``operation`` callable, retrying on WantRead/WantWrite.

    pyOpenSSL doesn't auto-loop on these even with a blocking socket. We
    select on the underlying socket and retry until the operation succeeds
    or the deadline passes.
    """
    from OpenSSL import SSL  # pylint: disable=import-outside-toplevel

    while True:
        try:
            return operation()
        except SSL.WantReadError:
            timeout = _remaining(deadline)
            if timeout == 0.0:
                raise PairingException("TLS read timed out")
            rd, _, _ = select.select([sock], [], [], timeout)
            if not rd:
                raise PairingException("TLS read timed out")
        except SSL.WantWriteError:
            timeout = _remaining(deadline)
            if timeout == 0.0:
                raise PairingException("TLS write timed out")
            _, wr, _ = select.select([], [sock], [], timeout)
            if not wr:
                raise PairingException("TLS write timed out")


class _PyOpenSSLTransport(object):
    """Adapt a ``pyOpenSSL`` ``Connection`` to the ``PairingConnection`` API."""

    def __init__(self, ssl_conn, sock, deadline):
        self._ssl = ssl_conn
        self._sock = sock
        self._deadline = deadline

    def send_all(self, data):
        """Write ``data`` in full, looping on WantRead/WantWrite."""
        # pyOpenSSL's sendall doesn't loop on WantWrite either; do it
        # ourselves with a retry wrapper around recv_into / write semantics.
        view = memoryview(data)
        sent = 0
        while sent < len(view):
            chunk = view[sent:]
            n = _retry_on_want(lambda c=chunk: self._ssl.send(c), self._sock, self._deadline)
            if n <= 0:
                raise PairingException("TLS send returned {}".format(n))
            sent += n

    def recv_exact(self, n):
        """Read exactly ``n`` bytes, looping on WantRead until satisfied."""
        from OpenSSL import SSL  # pylint: disable=import-outside-toplevel

        chunks = []
        remaining = n
        while remaining > 0:
            try:
                chunk = _retry_on_want(
                    lambda r=remaining: self._ssl.recv(r),
                    self._sock,
                    self._deadline,
                )
            except SSL.ZeroReturnError:
                raise PairingException(
                    "TLS connection closed while reading {} bytes".format(n)
                )
            if not chunk:
                raise PairingException(
                    "EOF after {} of {} bytes".format(n - remaining, n)
                )
            chunks.append(chunk)
            remaining -= len(chunk)
        return b"".join(chunks)


def _build_ssl_context(cert_pem, key_pem):
    """Return a ``pyOpenSSL`` ``Context`` configured for ADB pairing."""
    from OpenSSL import SSL, crypto  # pylint: disable=import-outside-toplevel

    ctx = SSL.Context(SSL.TLS_CLIENT_METHOD)
    ctx.set_min_proto_version(SSL.TLS1_3_VERSION)
    ctx.set_max_proto_version(SSL.TLS1_3_VERSION)
    # The peer self-signs and we don't have a CA chain. SPAKE2 provides
    # authentication; the TLS layer is here for confidentiality + the RFC
    # 8446 keying material exporter.
    ctx.set_verify(SSL.VERIFY_NONE, lambda *_: True)

    cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert_pem)
    key = crypto.load_privatekey(crypto.FILETYPE_PEM, key_pem)
    ctx.use_certificate(cert)
    ctx.use_privatekey(key)

    return ctx


def pair(host, port, pairing_code, private_key_pem, public_key, timeout_s=_DEFAULT_TIMEOUT_S):
    """Pair with an Android device using a 6-digit pairing code.

    Parameters
    ----------
    host : str
        The device's IPv4/IPv6 address (or hostname).
    port : int
        The pairing port shown on the device UI alongside the pairing code,
        or learned from a ``_adb-tls-pairing._tcp`` mDNS advertisement.
    pairing_code : str or bytes
        The 6-digit pairing code shown on the device UI.
    private_key_pem : bytes
        The host's RSA 2048 ADB private key, in PEM format. This is the
        contents of the user's ``adbkey`` file.
    public_key : bytes or str
        The host's Android-format ADB public key — typically the contents
        of the user's ``adbkey.pub`` file, i.e.
        ``base64(android_pubkey_struct) + " " + user@host``. This is what
        gets registered on the device.
    timeout_s : float, optional
        Combined connect + handshake timeout, in seconds.

    Returns
    -------
    PeerInfo
        The peer info returned by the device (typically the device's GUID).

    Raises
    ------
    PairingException
        On any failure — TCP, TLS, SPAKE2, AES-GCM, or wrong pairing code.
    """
    from OpenSSL import SSL  # pylint: disable=import-outside-toplevel

    if isinstance(pairing_code, str):
        pairing_code = pairing_code.encode("ascii")
    if isinstance(public_key, str):
        public_key = public_key.encode("ascii")
    if not pairing_code:
        raise ValueError("pairing_code must not be empty")

    # Generate a self-signed cert using the user's existing private key.
    rsa_key = load_rsa_private_key_pem(private_key_pem)
    cert = generate_x509_certificate(rsa_key)
    cert_pem = certificate_to_pem(cert)
    # Re-serialize the private key as PKCS#8 PEM. Some PEMs in the wild are
    # PKCS#1 (RSA PRIVATE KEY); this normalizes to what pyOpenSSL expects.
    key_pem = private_key_to_pem(rsa_key)

    ctx = _build_ssl_context(cert_pem, key_pem)

    sock = None
    ssl_conn = None
    try:
        sock = socket.create_connection((host, port), timeout=timeout_s)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        # Use blocking I/O combined with select-based retry on WantRead/Write
        # in _retry_on_want (pyOpenSSL doesn't auto-loop these).
        sock.setblocking(True)

        deadline = time.monotonic() + timeout_s if timeout_s else None

        ssl_conn = SSL.Connection(ctx, sock)
        ssl_conn.set_connect_state()
        _retry_on_want(ssl_conn.do_handshake, sock, deadline)

        transport = _PyOpenSSLTransport(ssl_conn, sock, deadline)
        peer_info = make_peer_info_from_pubkey(public_key)
        connection = PairingConnection(
            transport=transport,
            exporter=lambda label, length: ssl_conn.export_keying_material(
                label, length, None
            ),
            pairing_code=pairing_code,
            our_peer_info=peer_info,
        )

        return connection.run()
    except SSL.Error as exc:
        raise PairingException("TLS error during pairing: {}".format(exc))
    except (socket.timeout, socket.gaierror, OSError) as exc:
        raise PairingException("network error during pairing: {}".format(exc))
    finally:
        if ssl_conn is not None:
            try:
                ssl_conn.shutdown()
            except SSL.Error:
                pass
            try:
                ssl_conn.close()
            except SSL.Error:
                pass
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass
