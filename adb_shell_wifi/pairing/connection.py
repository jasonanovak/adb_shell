# Copyright (c) 2026 adb_shell contributors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0

"""ADB Wi-Fi pairing protocol state machine.

Port of ``adb/pairing_connection/pairing_connection.cpp`` (client role only).

* :class:`PeerInfo`
* :class:`PairingConnection`

The :class:`PairingConnection` class drives the protocol over a TLS channel
that's already been handshaken and provides RFC 5705 / RFC 8446 keying
material via :func:`exporter`. The transport itself is provided as a duck-
typed object with ``send_all`` / ``recv_exact`` methods so the same logic
can be reused by sync and async wrappers.
"""


import struct

from .auth import PairingAuthCtx, ROLE_CLIENT
from .constants import (
    MAX_PAYLOAD_SIZE,
    PAIRING_PACKET_HEADER_FORMAT,
    PAIRING_PACKET_HEADER_SIZE,
    PAIRING_PACKET_HEADER_VERSION,
    PAIRING_PACKET_TYPE_PEER_INFO,
    PAIRING_PACKET_TYPE_SPAKE2_MSG,
    PEER_INFO_DATA_SIZE,
    PEER_INFO_SIZE,
    PEER_INFO_TYPE_ADB_RSA_PUB_KEY,
    TLS_EXPORTER_LABEL,
    TLS_EXPORTER_LENGTH,
)
from ..exceptions import AdbConnectionError


class PairingException(AdbConnectionError):
    """Raised when the pairing handshake cannot complete successfully."""


class PeerInfo(object):
    """The 8192-byte PeerInfo struct exchanged between host and device."""

    __slots__ = ("type", "data")

    def __init__(self, peer_type, data):
        if len(data) > PEER_INFO_DATA_SIZE:
            raise ValueError(
                "PeerInfo data too large: {} > {}".format(len(data), PEER_INFO_DATA_SIZE)
            )
        self.type = peer_type
        self.data = data

    def pack(self):
        """Serialize to the 8192-byte wire format (zero-padded)."""
        padding = b"\x00" * (PEER_INFO_DATA_SIZE - len(self.data))
        return struct.pack("B", self.type) + self.data + padding

    @classmethod
    def unpack(cls, blob):
        """Parse the 8192-byte wire format and return a :class:`PeerInfo`."""
        if len(blob) != PEER_INFO_SIZE:
            raise ValueError(
                "PeerInfo blob has wrong size: {} != {}".format(len(blob), PEER_INFO_SIZE)
            )
        peer_type = blob[0]
        # Strip trailing zero padding for ergonomics; callers that need the
        # exact bytes can re-pack via pack().
        data = blob[1:].rstrip(b"\x00")
        return cls(peer_type, data)


def _pack_header(packet_type, payload_size):
    """Serialize a 6-byte ``PairingPacketHeader`` (version 1)."""
    return struct.pack(
        PAIRING_PACKET_HEADER_FORMAT,
        PAIRING_PACKET_HEADER_VERSION,
        packet_type,
        payload_size,
    )


def _unpack_header(blob):
    """Parse a 6-byte ``PairingPacketHeader``; raises on malformed input."""
    if len(blob) != PAIRING_PACKET_HEADER_SIZE:
        raise PairingException("short packet header")
    version, packet_type, payload_size = struct.unpack(PAIRING_PACKET_HEADER_FORMAT, blob)
    if version != PAIRING_PACKET_HEADER_VERSION:
        raise PairingException(
            "unsupported PairingPacketHeader version: got {}, expected {}".format(
                version, PAIRING_PACKET_HEADER_VERSION
            )
        )
    if payload_size == 0 or payload_size > MAX_PAYLOAD_SIZE:
        raise PairingException("invalid payload size: {}".format(payload_size))
    return packet_type, payload_size


class PairingConnection(object):
    """Drive the pairing protocol over an established TLS channel.

    Parameters
    ----------
    transport : object with ``send_all(data)`` and ``recv_exact(n)`` methods
        Already TLS-wrapped, post-handshake. Both methods raise on error.
    exporter : callable(label: bytes, length: int) -> bytes
        Returns RFC 5705 / RFC 8446 keying material from the TLS session.
    pairing_code : bytes
        The 6-digit pairing code from the device UI, e.g. ``b"515109"``.
    our_peer_info : PeerInfo
        The peer info we will send to the device — typically
        ``PeerInfo(PEER_INFO_TYPE_ADB_RSA_PUB_KEY, public_key_bytes)``.
    """

    def __init__(self, transport, exporter, pairing_code, our_peer_info):
        self._transport = transport
        self._exporter = exporter
        self._pairing_code = pairing_code
        self._our_peer_info = our_peer_info

    def run(self):
        """Run the full handshake. Returns the device's :class:`PeerInfo`.

        Raises :class:`PairingException` on any failure.
        """
        # Append RFC 5705 / RFC 8446 keying material to the pairing code.
        # This binds the SPAKE2 PAKE to the specific TLS session, so that a
        # MITM cannot proxy the SPAKE2 exchange.
        try:
            keying_material = self._exporter(TLS_EXPORTER_LABEL, TLS_EXPORTER_LENGTH)
        except Exception as exc:  # pylint: disable=broad-except
            raise PairingException("failed to export TLS keying material: {}".format(exc))

        if len(keying_material) != TLS_EXPORTER_LENGTH:
            raise PairingException(
                "TLS exporter returned {} bytes, expected {}".format(
                    len(keying_material), TLS_EXPORTER_LENGTH
                )
            )

        password = self._pairing_code + keying_material
        auth = PairingAuthCtx(ROLE_CLIENT, password)

        self._exchange_spake2(auth)
        their_peer_info = self._exchange_peer_info(auth)
        return their_peer_info

    def _exchange_spake2(self, auth):
        # Send our SPAKE2 message.
        self._transport.send_all(
            _pack_header(PAIRING_PACKET_TYPE_SPAKE2_MSG, len(auth.our_msg))
        )
        self._transport.send_all(auth.our_msg)

        # Read peer SPAKE2 message.
        header = self._transport.recv_exact(PAIRING_PACKET_HEADER_SIZE)
        packet_type, payload_size = _unpack_header(header)
        if packet_type != PAIRING_PACKET_TYPE_SPAKE2_MSG:
            raise PairingException(
                "expected SPAKE2_MSG, got type {}".format(packet_type)
            )
        their_msg = self._transport.recv_exact(payload_size)

        if not auth.init_cipher(their_msg):
            raise PairingException("SPAKE2 init_cipher failed (malformed peer message)")

    def _exchange_peer_info(self, auth):
        # Encrypt and send our PeerInfo.
        plaintext = self._our_peer_info.pack()
        ciphertext = auth.encrypt(plaintext)

        self._transport.send_all(
            _pack_header(PAIRING_PACKET_TYPE_PEER_INFO, len(ciphertext))
        )
        self._transport.send_all(ciphertext)

        # Read encrypted peer info from the device.
        header = self._transport.recv_exact(PAIRING_PACKET_HEADER_SIZE)
        packet_type, payload_size = _unpack_header(header)
        if packet_type != PAIRING_PACKET_TYPE_PEER_INFO:
            raise PairingException(
                "expected PEER_INFO, got type {}".format(packet_type)
            )

        encrypted = self._transport.recv_exact(payload_size)

        try:
            decrypted = auth.decrypt(encrypted)
        except Exception as exc:  # pylint: disable=broad-except
            # AES-GCM tag failure here typically means the pairing code was
            # wrong (the SPAKE2 keys derived from different passwords don't
            # match, so the device's encryption uses a different key from
            # what we expected).
            raise PairingException("decryption of peer PEER_INFO failed: {}".format(exc))

        return PeerInfo.unpack(decrypted)


def make_peer_info_from_pubkey(pubkey_bytes):
    """Build a :class:`PeerInfo` containing the host's ADB public key.

    ``pubkey_bytes`` should be the bytes of the user's ``adbkey.pub`` file,
    i.e. ``base64(android_pubkey_struct) + " " + user@host``. This format
    matches what :func:`adb_shell.auth.keygen.write_public_keyfile`
    produces and what the C++
    ``adb/crypto/rsa_2048_key.cpp:CalculatePublicKey`` produces.
    """
    return PeerInfo(PEER_INFO_TYPE_ADB_RSA_PUB_KEY, pubkey_bytes)
