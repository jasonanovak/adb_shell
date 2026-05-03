# Copyright (c) 2026 adb_shell contributors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0

"""TCP transport that can be upgraded to TLS 1.3 after an ``A_STLS`` exchange.

Used for connecting to a paired Android device's wireless-debugging port,
where the device greets new connections with ``A_STLS`` instead of
``A_AUTH`` and requires a TLS-encrypted data channel before normal ADB
traffic flows. See ``adb/docs/dev/adb_wifi.md`` for protocol details.

* :class:`TlsTransport`
"""


import os
import socket
import ssl
import tempfile

from .base_transport import BaseTransport
from ..exceptions import TcpTimeoutException


def _make_ssl_context(cert_pem, key_pem):
    """Return a stdlib :class:`ssl.SSLContext` configured for ADB Wi-Fi.

    Matches the device side: TLS 1.3 only, peer cert verification disabled
    (the device self-signs and the SPAKE2 pairing has already established
    that this host's public key is trusted by the device).
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.maximum_version = ssl.TLSVersion.TLSv1_3
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    # stdlib ssl can only load cert + key from file paths, so we round-trip
    # them through tempfiles. The files exist for the duration of the
    # load_cert_chain call and are unlinked immediately after.
    cert_fd, cert_path = tempfile.mkstemp(suffix=".pem", prefix="adbtls-cert-")
    key_fd, key_path = tempfile.mkstemp(suffix=".pem", prefix="adbtls-key-")
    try:
        with os.fdopen(cert_fd, "wb") as f:
            f.write(cert_pem)
        with os.fdopen(key_fd, "wb") as f:
            f.write(key_pem)
        os.chmod(key_path, 0o600)
        ctx.load_cert_chain(certfile=cert_path, keyfile=key_path)
    finally:
        for path in (cert_path, key_path):
            try:
                os.unlink(path)
            except OSError:
                pass
    return ctx


class TlsTransport(BaseTransport):
    """TCP connection that supports an in-band upgrade to TLS 1.3.

    Behaves like :class:`adb_shell.transport.tcp_transport.TcpTransport`
    until :meth:`tls_upgrade` is called; afterward all reads and writes
    are TLS-encrypted. Uses blocking I/O with per-call ``settimeout`` so
    the same code path works before and after the upgrade.

    Parameters
    ----------
    host : str
        The address of the device.
    port : int
        The TCP port — typically the random port advertised by the device's
        ``_adb-tls-connect._tcp`` mDNS service.
    """

    def __init__(self, host, port=5555):
        self._host = host
        self._port = port
        self._connection = None
        self._is_tls = False

    def close(self):
        """Close the connection."""
        if self._connection:
            try:
                self._connection.shutdown(socket.SHUT_RDWR)
            except (OSError, ssl.SSLError):
                pass
            try:
                self._connection.close()
            except (OSError, ssl.SSLError):
                pass
            self._connection = None
        self._is_tls = False

    def connect(self, transport_timeout_s):
        """Open the underlying TCP connection. Does not start TLS."""
        self._connection = socket.create_connection(
            (self._host, self._port), timeout=transport_timeout_s
        )
        # Use blocking I/O combined with per-call settimeout in bulk_read /
        # bulk_write. This keeps the same code path before and after
        # tls_upgrade and avoids the SSLWantReadError dance non-blocking
        # sockets require with stdlib ssl.
        self._connection.settimeout(None)
        self._is_tls = False

    def tls_upgrade(self, cert_pem, key_pem, handshake_timeout_s=10.0):
        """Wrap the underlying socket in TLS 1.3.

        Parameters
        ----------
        cert_pem : bytes
            Self-signed certificate in PEM format. Use
            :func:`adb_shell.auth.x509.generate_x509_certificate` to
            produce one from the host's RSA key.
        key_pem : bytes
            The corresponding RSA private key in PKCS#8 PEM format.
        handshake_timeout_s : float, optional
            Timeout for the TLS handshake in seconds.
        """
        if self._connection is None:
            raise RuntimeError("connect() must be called before tls_upgrade()")
        if self._is_tls:
            raise RuntimeError("tls_upgrade() already called")

        ctx = _make_ssl_context(cert_pem, key_pem)
        self._connection.settimeout(handshake_timeout_s)
        try:
            wrapped = ctx.wrap_socket(
                self._connection,
                server_hostname=None,
                do_handshake_on_connect=True,
            )
        except (ssl.SSLError, socket.timeout) as exc:
            raise TcpTimeoutException(
                "TLS handshake to {}:{} failed: {}".format(self._host, self._port, exc)
            )
        wrapped.settimeout(None)
        self._connection = wrapped
        self._is_tls = True

    def bulk_read(self, numbytes, transport_timeout_s):
        """Receive up to ``numbytes`` bytes; raises on timeout."""
        self._connection.settimeout(transport_timeout_s)
        try:
            return self._connection.recv(numbytes)
        except socket.timeout:
            msg = "Reading from {}:{} timed out ({} seconds)".format(
                self._host, self._port, transport_timeout_s
            )
            raise TcpTimeoutException(msg)
        except ssl.SSLWantReadError:
            msg = "Reading from {}:{} timed out ({} seconds)".format(
                self._host, self._port, transport_timeout_s
            )
            raise TcpTimeoutException(msg)

    def bulk_write(self, data, transport_timeout_s):
        """Send data; returns the number of bytes written."""
        self._connection.settimeout(transport_timeout_s)
        try:
            return self._connection.send(data)
        except socket.timeout:
            msg = "Sending data to {}:{} timed out after {} seconds. No data was sent.".format(
                self._host, self._port, transport_timeout_s
            )
            raise TcpTimeoutException(msg)
        except ssl.SSLWantWriteError:
            msg = "Sending data to {}:{} timed out after {} seconds. No data was sent.".format(
                self._host, self._port, transport_timeout_s
            )
            raise TcpTimeoutException(msg)
