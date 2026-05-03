# Copyright (c) 2026 adb_shell contributors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0

"""SPAKE2 + AES-128-GCM authentication for ADB Wi-Fi pairing.

Port of ``adb/pairing_auth/pairing_auth.cpp`` and
``adb/pairing_auth/aes_128_gcm.cpp``.

* :class:`PairingAuthCtx`
"""


import struct

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .constants import (
    AES_KEY_LENGTH,
    HKDF_INFO,
    SPAKE2_CLIENT_NAME,
    SPAKE2_SERVER_NAME,
)


ROLE_CLIENT = "client"
ROLE_SERVER = "server"


def _build_nonce(sequence):
    """Return the 12-byte AES-GCM nonce for a given sequence number.

    Matches ``Aes128Gcm::Encrypt`` / ``Decrypt`` in the C++ reference: the
    sequence number occupies the low 8 bytes (little-endian) and the high 4
    bytes are zero.
    """
    return struct.pack("<Q", sequence) + b"\x00\x00\x00\x00"


class PairingAuthCtx(object):
    """Wrap SPAKE2-edwards25519 + AES-128-GCM for one pairing session.

    The flow is:

    1. Construct with ``role`` and ``password``.
    2. Send :attr:`our_msg` to the peer; receive their SPAKE2 message.
    3. Call :meth:`init_cipher` with the peer's message. If both sides used
       the same password, this returns ``True`` and the cipher is ready.
    4. Use :meth:`encrypt` / :meth:`decrypt` to exchange further data.
    """

    def __init__(self, role, password):
        if role not in (ROLE_CLIENT, ROLE_SERVER):
            raise ValueError("role must be ROLE_CLIENT or ROLE_SERVER")
        if not password:
            raise ValueError("password must not be empty")

        # Imported lazily so the dependency only loads when pairing is used.
        from spake2.spake2 import Spake2_Alice, Spake2_Bob  # pylint: disable=import-outside-toplevel

        self._role = role
        self._cipher = None

        if role == ROLE_CLIENT:
            self._spake = Spake2_Alice(SPAKE2_CLIENT_NAME, SPAKE2_SERVER_NAME)
        else:
            self._spake = Spake2_Bob(SPAKE2_SERVER_NAME, SPAKE2_CLIENT_NAME)

        self._our_msg = self._spake.generate_msg(password)
        self._enc_sequence = 0
        self._dec_sequence = 0

    @property
    def our_msg(self):
        """The SPAKE2 message to send to the peer."""
        return self._our_msg

    @property
    def role(self):
        """Either :data:`ROLE_CLIENT` or :data:`ROLE_SERVER`."""
        return self._role

    def init_cipher(self, their_msg):
        """Process the peer's SPAKE2 message and derive the AES-128-GCM key.

        Returns ``True`` on success. On failure (most often: the peer used a
        different password) returns ``False`` and the cipher remains
        uninitialized; the only sensible next step is to discard this
        context.
        """
        if not their_msg:
            raise ValueError("their_msg must not be empty")
        if self._cipher is not None:
            raise RuntimeError("init_cipher already called")

        try:
            key_material = self._spake.process_msg(their_msg)
        except Exception:  # pylint: disable=broad-except
            return False

        if not key_material:
            return False

        # HKDF-SHA256 over the SPAKE2 key material, no salt, fixed info,
        # producing the 16-byte AES-128 key. Matches the C++ Aes128Gcm
        # constructor.
        derived = HKDF(
            algorithm=hashes.SHA256(),
            length=AES_KEY_LENGTH,
            salt=None,
            info=HKDF_INFO,
        ).derive(key_material)

        self._cipher = AESGCM(derived)
        return True

    def encrypt(self, plaintext):
        """Encrypt ``plaintext`` with the next outgoing nonce."""
        if self._cipher is None:
            raise RuntimeError("init_cipher must succeed before encrypt")
        nonce = _build_nonce(self._enc_sequence)
        ciphertext = self._cipher.encrypt(nonce, plaintext, None)
        self._enc_sequence += 1
        return ciphertext

    def decrypt(self, ciphertext):
        """Decrypt ``ciphertext`` with the next incoming nonce."""
        if self._cipher is None:
            raise RuntimeError("init_cipher must succeed before decrypt")
        nonce = _build_nonce(self._dec_sequence)
        plaintext = self._cipher.decrypt(nonce, ciphertext, None)
        self._dec_sequence += 1
        return plaintext

    @staticmethod
    def safe_encrypted_size(plaintext_len):
        """Worst-case ciphertext size for a given plaintext size.

        AES-GCM appends a 16-byte authentication tag to the ciphertext.
        """
        return plaintext_len + 16

    @staticmethod
    def safe_decrypted_size(ciphertext_len):
        """Worst-case plaintext size for a given ciphertext size."""
        return ciphertext_len
