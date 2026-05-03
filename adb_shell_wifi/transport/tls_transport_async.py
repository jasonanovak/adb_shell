# Copyright (c) 2026 adb_shell contributors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0

"""Async TCP transport that can be upgraded to TLS 1.3 mid-stream.

Async counterpart of
:class:`adb_shell.transport.tls_transport.TlsTransport`.

* :class:`TlsTransportAsync`
"""


import asyncio

import async_timeout

from .base_transport_async import BaseTransportAsync
from .tls_transport import _make_ssl_context
from ..exceptions import TcpTimeoutException


class TlsTransportAsync(BaseTransportAsync):
    """Async TCP connection that supports an in-band upgrade to TLS 1.3."""

    def __init__(self, host, port=5555):
        self._host = host
        self._port = port
        self._reader = None
        self._writer = None
        self._is_tls = False

    async def close(self):
        """Close the connection."""
        if self._writer:
            try:
                self._writer.close()
                await self._writer.wait_closed()
            except (OSError, ConnectionResetError):
                pass
        self._reader = None
        self._writer = None
        self._is_tls = False

    async def connect(self, transport_timeout_s):
        """Open the underlying TCP connection. Does not start TLS."""
        try:
            async with async_timeout.timeout(transport_timeout_s):
                self._reader, self._writer = await asyncio.open_connection(
                    self._host, self._port
                )
        except asyncio.TimeoutError as exc:
            msg = "Connecting to {}:{} timed out ({} seconds)".format(
                self._host, self._port, transport_timeout_s
            )
            raise TcpTimeoutException(msg) from exc
        self._is_tls = False

    async def tls_upgrade(self, cert_pem, key_pem, handshake_timeout_s=10.0):
        """Wrap the active stream in TLS 1.3.

        Uses :meth:`asyncio.AbstractEventLoop.start_tls` (Python 3.7+) to
        upgrade the existing transport in place. Same parameters as the
        sync :meth:`adb_shell.transport.tls_transport.TlsTransport.tls_upgrade`.
        """
        if self._writer is None or self._reader is None:
            raise RuntimeError("connect() must be called before tls_upgrade()")
        if self._is_tls:
            raise RuntimeError("tls_upgrade() already called")

        ctx = _make_ssl_context(cert_pem, key_pem)

        loop = asyncio.get_event_loop()
        old_transport = self._writer.transport
        protocol = self._writer.transport.get_protocol()

        try:
            async with async_timeout.timeout(handshake_timeout_s):
                new_transport = await loop.start_tls(
                    old_transport,
                    protocol,
                    ctx,
                    server_side=False,
                )
        except asyncio.TimeoutError as exc:
            raise TcpTimeoutException(
                "TLS handshake to {}:{} timed out".format(self._host, self._port)
            ) from exc

        # Splice the new TLS transport back into the existing reader/writer.
        # The protocol object was already wired to feed the StreamReader, so
        # it keeps working; we just need to point the writer at the new
        # transport.
        self._writer._transport = new_transport  # pylint: disable=protected-access
        protocol._stream_writer = self._writer  # pylint: disable=protected-access
        self._is_tls = True

    async def bulk_read(self, numbytes, transport_timeout_s):
        """Receive up to ``numbytes`` bytes; raises on timeout."""
        try:
            async with async_timeout.timeout(transport_timeout_s):
                return await self._reader.read(numbytes)
        except asyncio.TimeoutError as exc:
            msg = "Reading from {}:{} timed out ({} seconds)".format(
                self._host, self._port, transport_timeout_s
            )
            raise TcpTimeoutException(msg) from exc

    async def bulk_write(self, data, transport_timeout_s):
        """Send data; returns the number of bytes written."""
        try:
            self._writer.write(data)
            async with async_timeout.timeout(transport_timeout_s):
                await self._writer.drain()
                return len(data)
        except asyncio.TimeoutError as exc:
            msg = "Sending data to {}:{} timed out after {} seconds.".format(
                self._host, self._port, transport_timeout_s
            )
            raise TcpTimeoutException(msg) from exc
