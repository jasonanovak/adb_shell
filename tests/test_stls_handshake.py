# Copyright (c) 2026 adb_shell contributors
#
# Tests for the A_STLS handshake path in _AdbIOManager.connect.

import asyncio
import inspect
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from adb_shell import constants, exceptions
from adb_shell.adb_device import AdbDevice, AdbDeviceTls
from adb_shell.adb_device_async import AdbDeviceAsync, AdbDeviceTlsAsync
from adb_shell.adb_message import AdbMessage
from adb_shell.transport.base_transport import BaseTransport
from adb_shell.transport.base_transport_async import BaseTransportAsync


# An RSA key shared across tests; expensive to generate, so do it once.
_RSA_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_PRIV_PEM = _RSA_KEY.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption(),
)


def _stls_packet():
    return AdbMessage(constants.STLS, constants.STLS_VERSION, 0, b'')


def _cnxn_packet(maxdata=constants.MAX_LEGACY_ADB_DATA):
    return AdbMessage(
        command=constants.CNXN,
        arg0=constants.PROTOCOL,
        arg1=maxdata,
        data=b'host::device-banner\0',
    )


class _FakeTlsTransport(BaseTransport):
    """Sync fake transport that supports the same surface as TlsTransport."""

    def __init__(self):
        self.bulk_read_data = b''
        self.bulk_write_data = b''
        self.tls_upgraded = False
        self.tls_upgrade_args = None

    def close(self):
        pass

    def connect(self, transport_timeout_s=None):
        pass

    def tls_upgrade(self, cert_pem, key_pem, handshake_timeout_s=10.0):
        self.tls_upgraded = True
        self.tls_upgrade_args = (cert_pem, key_pem, handshake_timeout_s)

    def bulk_read(self, numbytes, transport_timeout_s=None):
        num = min(numbytes, constants.MAX_ADB_DATA)
        ret = self.bulk_read_data[:num]
        self.bulk_read_data = self.bulk_read_data[num:]
        return ret

    def bulk_write(self, data, transport_timeout_s=None):
        self.bulk_write_data += data
        return len(data)


class _FakeTcpOnlyTransport(BaseTransport):
    """Fake transport that does NOT have tls_upgrade — to verify rejection."""

    def __init__(self):
        self.bulk_read_data = b''
        self.bulk_write_data = b''

    def close(self):
        pass

    def connect(self, transport_timeout_s=None):
        pass

    def bulk_read(self, numbytes, transport_timeout_s=None):
        num = min(numbytes, constants.MAX_ADB_DATA)
        ret = self.bulk_read_data[:num]
        self.bulk_read_data = self.bulk_read_data[num:]
        return ret

    def bulk_write(self, data, transport_timeout_s=None):
        self.bulk_write_data += data
        return len(data)


class StlsHandshakeSyncTest(unittest.TestCase):
    def _build_device(self, transport):
        return AdbDevice(transport=transport, banner=b'banner')

    def test_stls_path_completes_with_cert_upgrade(self):
        transport = _FakeTlsTransport()
        # Device sends STLS, then CNXN after the upgrade.
        stls = _stls_packet()
        cnxn = _cnxn_packet(maxdata=constants.MAX_LEGACY_ADB_DATA)
        transport.bulk_read_data = stls.pack() + stls.data + cnxn.pack() + cnxn.data

        device = self._build_device(transport)
        ok = device.connect(rsa_keys=[], tls_priv_pem=_PRIV_PEM)

        self.assertTrue(ok)
        self.assertTrue(transport.tls_upgraded)
        # We sent: CNXN (initial) + STLS (our reply).
        # AdbMessage.pack() emits the 24-byte header followed by data; our
        # STLS reply has empty data so write buffer ends with the STLS header.
        # The first packet written must be a CNXN.
        first_cmd = transport.bulk_write_data[:4]
        self.assertEqual(first_cmd, constants.CNXN)
        self.assertIn(constants.STLS, transport.bulk_write_data)

    def test_stls_without_priv_key_raises(self):
        transport = _FakeTlsTransport()
        stls = _stls_packet()
        transport.bulk_read_data = stls.pack() + stls.data

        device = self._build_device(transport)
        with self.assertRaises(exceptions.DeviceAuthError):
            device.connect(rsa_keys=[], tls_priv_pem=None)
        self.assertFalse(transport.tls_upgraded)

    def test_stls_without_tls_capable_transport_raises(self):
        transport = _FakeTcpOnlyTransport()
        stls = _stls_packet()
        transport.bulk_read_data = stls.pack() + stls.data

        device = self._build_device(transport)
        with self.assertRaises(exceptions.DeviceAuthError):
            device.connect(rsa_keys=[], tls_priv_pem=_PRIV_PEM)

    def test_legacy_cnxn_path_unchanged(self):
        # If the device's first reply is CNXN (no auth required, no STLS),
        # the connect should succeed without touching tls_upgrade.
        transport = _FakeTlsTransport()
        cnxn = _cnxn_packet()
        transport.bulk_read_data = cnxn.pack() + cnxn.data

        device = self._build_device(transport)
        ok = device.connect(rsa_keys=[], tls_priv_pem=_PRIV_PEM)
        self.assertTrue(ok)
        self.assertFalse(transport.tls_upgraded)


class _FakeTlsTransportAsync(BaseTransportAsync):
    def __init__(self):
        self.bulk_read_data = b''
        self.bulk_write_data = b''
        self.tls_upgraded = False

    async def close(self):
        pass

    async def connect(self, transport_timeout_s=None):
        pass

    async def tls_upgrade(self, cert_pem, key_pem, handshake_timeout_s=10.0):
        self.tls_upgraded = True

    async def bulk_read(self, numbytes, transport_timeout_s=None):
        num = min(numbytes, constants.MAX_ADB_DATA)
        ret = self.bulk_read_data[:num]
        self.bulk_read_data = self.bulk_read_data[num:]
        return ret

    async def bulk_write(self, data, transport_timeout_s=None):
        self.bulk_write_data += data
        return len(data)


class _FakeTcpOnlyTransportAsync(BaseTransportAsync):
    def __init__(self):
        self.bulk_read_data = b''
        self.bulk_write_data = b''

    async def close(self):
        pass

    async def connect(self, transport_timeout_s=None):
        pass

    async def bulk_read(self, numbytes, transport_timeout_s=None):
        num = min(numbytes, constants.MAX_ADB_DATA)
        ret = self.bulk_read_data[:num]
        self.bulk_read_data = self.bulk_read_data[num:]
        return ret

    async def bulk_write(self, data, transport_timeout_s=None):
        self.bulk_write_data += data
        return len(data)


def _run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


class StlsHandshakeAsyncTest(unittest.TestCase):
    def test_async_stls_path_completes_with_cert_upgrade(self):
        async def go():
            transport = _FakeTlsTransportAsync()
            stls = _stls_packet()
            cnxn = _cnxn_packet(maxdata=constants.MAX_LEGACY_ADB_DATA)
            transport.bulk_read_data = stls.pack() + stls.data + cnxn.pack() + cnxn.data

            device = AdbDeviceAsync(transport=transport, banner=b'banner')
            ok = await device.connect(rsa_keys=[], tls_priv_pem=_PRIV_PEM)
            self.assertTrue(ok)
            self.assertTrue(transport.tls_upgraded)
        _run(go())

    def test_async_stls_without_priv_key_raises(self):
        async def go():
            transport = _FakeTlsTransportAsync()
            stls = _stls_packet()
            transport.bulk_read_data = stls.pack() + stls.data
            device = AdbDeviceAsync(transport=transport, banner=b'banner')
            with self.assertRaises(exceptions.DeviceAuthError):
                await device.connect(rsa_keys=[], tls_priv_pem=None)
        _run(go())

    def test_async_stls_without_tls_capable_transport_raises(self):
        async def go():
            transport = _FakeTcpOnlyTransportAsync()
            stls = _stls_packet()
            transport.bulk_read_data = stls.pack() + stls.data
            device = AdbDeviceAsync(transport=transport, banner=b'banner')
            with self.assertRaises(exceptions.DeviceAuthError):
                await device.connect(rsa_keys=[], tls_priv_pem=_PRIV_PEM)
        _run(go())


class TlsTransportSmokeTest(unittest.TestCase):
    def test_sync_tls_class_constructible(self):
        device = AdbDeviceTls('127.0.0.1', 1)
        self.assertIsNotNone(device)

    def test_async_tls_class_constructible(self):
        device = AdbDeviceTlsAsync('127.0.0.1', 1)
        self.assertIsNotNone(device)


if __name__ == "__main__":
    unittest.main()
