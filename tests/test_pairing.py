# Copyright (c) 2026 adb_shell contributors
#
# Unit tests for the ADB Wi-Fi pairing implementation.

import socket
import struct
import threading
import unittest

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtensionOID, NameOID

from adb_shell_wifi.auth.x509 import (
    certificate_to_pem,
    generate_x509_certificate,
    load_rsa_private_key_pem,
    private_key_to_pem,
)
from adb_shell_wifi.pairing import constants as pconst
from adb_shell_wifi.pairing.auth import PairingAuthCtx, ROLE_CLIENT, ROLE_SERVER, _build_nonce
from adb_shell_wifi.pairing.connection import (
    PairingConnection,
    PairingException,
    PeerInfo,
    _pack_header,
    _unpack_header,
    make_peer_info_from_pubkey,
)


def _make_rsa_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


class X509CertGenerationTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.key = _make_rsa_key()
        cls.cert = generate_x509_certificate(cls.key)

    def test_subject_and_issuer(self):
        for name in (self.cert.subject, self.cert.issuer):
            self.assertEqual(
                name.get_attributes_for_oid(NameOID.COUNTRY_NAME)[0].value, "US"
            )
            self.assertEqual(
                name.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)[0].value, "Android"
            )
            self.assertEqual(
                name.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value, "Adb"
            )

    def test_serial_is_one(self):
        self.assertEqual(self.cert.serial_number, 1)

    def test_self_signed(self):
        self.assertEqual(self.cert.subject, self.cert.issuer)

    def test_validity_is_about_ten_years(self):
        delta = self.cert.not_valid_after_utc - self.cert.not_valid_before_utc
        self.assertGreater(delta.days, 10 * 365 - 2)
        self.assertLess(delta.days, 10 * 365 + 2)

    def test_signature_is_sha256(self):
        self.assertEqual(self.cert.signature_hash_algorithm.name, "sha256")

    def test_basic_constraints(self):
        ext = self.cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS)
        self.assertTrue(ext.critical)
        self.assertTrue(ext.value.ca)

    def test_key_usage(self):
        ext = self.cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE)
        self.assertTrue(ext.critical)
        self.assertTrue(ext.value.digital_signature)
        self.assertTrue(ext.value.key_cert_sign)
        self.assertTrue(ext.value.crl_sign)
        self.assertFalse(ext.value.key_encipherment)

    def test_subject_key_identifier_present(self):
        ext = self.cert.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_KEY_IDENTIFIER
        )
        self.assertFalse(ext.critical)
        self.assertEqual(len(ext.value.digest), 20)  # SHA-1 digest = 160 bits

    def test_pem_round_trip(self):
        pem = certificate_to_pem(self.cert)
        self.assertTrue(pem.startswith(b"-----BEGIN CERTIFICATE-----"))
        parsed = x509.load_pem_x509_certificate(pem)
        self.assertEqual(parsed.serial_number, 1)

    def test_load_pem_helper_round_trips(self):
        pem = private_key_to_pem(self.key)
        loaded = load_rsa_private_key_pem(pem)
        self.assertEqual(
            loaded.private_numbers().public_numbers.n,
            self.key.private_numbers().public_numbers.n,
        )

    def test_rejects_non_rsa_key(self):
        from cryptography.hazmat.primitives.asymmetric import ed25519

        ed_key = ed25519.Ed25519PrivateKey.generate()
        with self.assertRaises(TypeError):
            generate_x509_certificate(ed_key)


class PairingAuthCtxTest(unittest.TestCase):
    PASSWORD = b"515109" + b"\xab" * pconst.TLS_EXPORTER_LENGTH

    def test_round_trip_same_password(self):
        client = PairingAuthCtx(ROLE_CLIENT, self.PASSWORD)
        server = PairingAuthCtx(ROLE_SERVER, self.PASSWORD)

        self.assertEqual(len(client.our_msg), 32)
        self.assertEqual(len(server.our_msg), 32)

        self.assertTrue(server.init_cipher(client.our_msg))
        self.assertTrue(client.init_cipher(server.our_msg))

        ct = client.encrypt(b"hello server")
        self.assertEqual(server.decrypt(ct), b"hello server")
        ct2 = server.encrypt(b"hello client")
        self.assertEqual(client.decrypt(ct2), b"hello client")

    def test_wrong_password_fails_at_decrypt(self):
        client = PairingAuthCtx(ROLE_CLIENT, b"wrong" + b"\x00" * 64)
        server = PairingAuthCtx(ROLE_SERVER, b"right" + b"\x00" * 64)

        # SPAKE2 itself doesn't fail — both sides derive different keys, so
        # the first cross-decrypt is what reveals the mismatch.
        self.assertTrue(server.init_cipher(client.our_msg))
        self.assertTrue(client.init_cipher(server.our_msg))

        from cryptography.exceptions import InvalidTag

        ct = client.encrypt(b"smuggled data")
        with self.assertRaises(InvalidTag):
            server.decrypt(ct)

    def test_safe_sizes(self):
        self.assertEqual(PairingAuthCtx.safe_encrypted_size(100), 116)
        self.assertEqual(PairingAuthCtx.safe_decrypted_size(116), 116)

    def test_invalid_role_rejected(self):
        with self.assertRaises(ValueError):
            PairingAuthCtx("evil", self.PASSWORD)

    def test_empty_password_rejected(self):
        with self.assertRaises(ValueError):
            PairingAuthCtx(ROLE_CLIENT, b"")

    def test_init_cipher_can_only_run_once(self):
        client = PairingAuthCtx(ROLE_CLIENT, self.PASSWORD)
        server = PairingAuthCtx(ROLE_SERVER, self.PASSWORD)
        self.assertTrue(client.init_cipher(server.our_msg))
        with self.assertRaises(RuntimeError):
            client.init_cipher(server.our_msg)

    def test_encrypt_before_init_cipher_raises(self):
        client = PairingAuthCtx(ROLE_CLIENT, self.PASSWORD)
        with self.assertRaises(RuntimeError):
            client.encrypt(b"x")

    def test_nonce_layout(self):
        # 12-byte buffer: little-endian uint64 sequence in low 8 bytes,
        # high 4 bytes zero. Matches Aes128Gcm in the C++ reference.
        self.assertEqual(_build_nonce(0), b"\x00" * 12)
        self.assertEqual(
            _build_nonce(1),
            b"\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
        )
        self.assertEqual(len(_build_nonce(0xDEADBEEF)), 12)


class PairingPacketHeaderTest(unittest.TestCase):
    def test_pack_round_trip(self):
        for ptype, payload in [(0, 1), (1, 8208), (0, pconst.MAX_PAYLOAD_SIZE)]:
            packed = _pack_header(ptype, payload)
            self.assertEqual(len(packed), pconst.PAIRING_PACKET_HEADER_SIZE)
            unpacked = _unpack_header(packed)
            self.assertEqual(unpacked, (ptype, payload))

    def test_payload_is_big_endian(self):
        # Verify wire byte order matches the C++ ``htonl`` reference.
        packed = _pack_header(0, 0x01020304)
        # Layout: version=1, type=0, payload (BE) = 01 02 03 04
        self.assertEqual(packed[0], 1)
        self.assertEqual(packed[1], 0)
        self.assertEqual(packed[2:], b"\x01\x02\x03\x04")

    def test_unpack_rejects_unknown_version(self):
        bad = struct.pack(">BBI", 99, 0, 16)
        with self.assertRaises(PairingException):
            _unpack_header(bad)

    def test_unpack_rejects_zero_payload(self):
        bad = struct.pack(">BBI", 1, 0, 0)
        with self.assertRaises(PairingException):
            _unpack_header(bad)

    def test_unpack_rejects_oversized_payload(self):
        bad = struct.pack(">BBI", 1, 0, pconst.MAX_PAYLOAD_SIZE + 1)
        with self.assertRaises(PairingException):
            _unpack_header(bad)


class PeerInfoTest(unittest.TestCase):
    def test_pack_size(self):
        info = make_peer_info_from_pubkey(b"some-android-pubkey user@host")
        packed = info.pack()
        self.assertEqual(len(packed), pconst.PEER_INFO_SIZE)
        self.assertEqual(packed[0], pconst.PEER_INFO_TYPE_ADB_RSA_PUB_KEY)
        # Data starts at byte 1, padded with zeros.
        self.assertTrue(packed[1:].startswith(b"some-android-pubkey user@host"))
        # Padding fills the rest with zeros.
        self.assertTrue(packed.endswith(b"\x00"))

    def test_unpack_strips_padding(self):
        info = make_peer_info_from_pubkey(b"hello world")
        decoded = PeerInfo.unpack(info.pack())
        self.assertEqual(decoded.type, pconst.PEER_INFO_TYPE_ADB_RSA_PUB_KEY)
        self.assertEqual(decoded.data, b"hello world")

    def test_unpack_rejects_wrong_size(self):
        with self.assertRaises(ValueError):
            PeerInfo.unpack(b"short")

    def test_oversized_data_rejected(self):
        with self.assertRaises(ValueError):
            PeerInfo(0, b"\x00" * (pconst.PEER_INFO_DATA_SIZE + 1))


class _InMemoryTransport(object):
    """Transport that hands bytes off to a paired counterpart, blocking on
    reads until the peer has supplied enough bytes (so the test can drive
    both sides in separate threads without a race)."""

    def __init__(self):
        self._cond = threading.Condition()
        self._in = bytearray()
        self._peer = None

    def link(self, peer):
        self._peer = peer

    def send_all(self, data):
        peer = self._peer
        with peer._cond:  # pylint: disable=protected-access
            peer._in.extend(data)  # pylint: disable=protected-access
            peer._cond.notify_all()  # pylint: disable=protected-access

    def recv_exact(self, n):
        with self._cond:
            while len(self._in) < n:
                self._cond.wait(timeout=5)
                if len(self._in) < n:
                    raise PairingException("recv_exact timed out")
            out = bytes(self._in[:n])
            del self._in[:n]
            return out


class PairingConnectionTest(unittest.TestCase):
    """The PairingConnection itself only implements the client role, so we
    drive the server side manually with a PairingAuthCtx."""

    PASSWORD_CODE = b"515109"
    EXPORTER_BYTES = b"\xcd" * pconst.TLS_EXPORTER_LENGTH

    def _drive_server_side(self, client_transport, server_transport):
        """Run the server-side state machine on ``server_transport``.

        Reads the client's SPAKE2_MSG, replies with our own, exchanges
        encrypted PEER_INFO blobs, and returns the auth ctx so callers can
        introspect.
        """
        password = self.PASSWORD_CODE + self.EXPORTER_BYTES
        auth = PairingAuthCtx(ROLE_SERVER, password)

        hdr = server_transport.recv_exact(pconst.PAIRING_PACKET_HEADER_SIZE)
        ptype, plen = _unpack_header(hdr)
        self.assertEqual(ptype, pconst.PAIRING_PACKET_TYPE_SPAKE2_MSG)
        client_msg = server_transport.recv_exact(plen)

        server_transport.send_all(
            _pack_header(pconst.PAIRING_PACKET_TYPE_SPAKE2_MSG, len(auth.our_msg))
        )
        server_transport.send_all(auth.our_msg)
        self.assertTrue(auth.init_cipher(client_msg))

        hdr = server_transport.recv_exact(pconst.PAIRING_PACKET_HEADER_SIZE)
        ptype, plen = _unpack_header(hdr)
        self.assertEqual(ptype, pconst.PAIRING_PACKET_TYPE_PEER_INFO)
        encrypted = server_transport.recv_exact(plen)
        plain = auth.decrypt(encrypted)
        client_pi = PeerInfo.unpack(plain)

        # Reply with the device's PeerInfo.
        device_pi = PeerInfo(pconst.PEER_INFO_TYPE_ADB_DEVICE_GUID, b"fake-device-guid")
        ct = auth.encrypt(device_pi.pack())
        server_transport.send_all(
            _pack_header(pconst.PAIRING_PACKET_TYPE_PEER_INFO, len(ct))
        )
        server_transport.send_all(ct)

        return auth, client_pi

    def test_protocol_round_trip(self):
        client_t = _InMemoryTransport()
        server_t = _InMemoryTransport()
        client_t.link(server_t)
        server_t.link(client_t)

        # Drive the server side from a worker thread because the client
        # blocks on recv before the server has replied.
        captured = {}
        def server_thread():
            captured["auth"], captured["client_pi"] = self._drive_server_side(client_t, server_t)
        t = threading.Thread(target=server_thread)
        t.start()

        client_pi = make_peer_info_from_pubkey(b"AAAA-FAKE-PUBKEY user@host")
        connection = PairingConnection(
            transport=client_t,
            exporter=lambda label, length: self.EXPORTER_BYTES,
            pairing_code=self.PASSWORD_CODE,
            our_peer_info=client_pi,
        )
        result = connection.run()
        t.join(timeout=5)

        self.assertFalse(t.is_alive())
        self.assertEqual(result.type, pconst.PEER_INFO_TYPE_ADB_DEVICE_GUID)
        self.assertEqual(result.data, b"fake-device-guid")
        self.assertEqual(captured["client_pi"].type, pconst.PEER_INFO_TYPE_ADB_RSA_PUB_KEY)
        self.assertEqual(captured["client_pi"].data, b"AAAA-FAKE-PUBKEY user@host")

    def test_exporter_failure_raises(self):
        client_t = _InMemoryTransport()
        client_t.link(client_t)  # never actually used

        def boom(*_args):
            raise RuntimeError("nope")

        connection = PairingConnection(
            transport=client_t,
            exporter=boom,
            pairing_code=b"123456",
            our_peer_info=make_peer_info_from_pubkey(b"k"),
        )
        with self.assertRaises(PairingException):
            connection.run()


if __name__ == "__main__":
    unittest.main()
