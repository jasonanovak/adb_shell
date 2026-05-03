# Copyright (c) 2026 adb_shell contributors
#
# Tests for adb_shell.mdns.discovery using a mocked zeroconf backend.

import asyncio
import unittest

try:
    from unittest.mock import patch, MagicMock
except ImportError:  # pragma: no cover
    from mock import patch, MagicMock

from adb_shell_wifi.mdns import (
    AdbService,
    SERVICE_TYPE_PAIRING,
    SERVICE_TYPE_TLS_CONNECT,
    discover_connect_services,
    discover_pairing_services,
    discover_services,
)
from adb_shell_wifi.mdns import discovery as discovery_mod


def _fake_service_info(addresses, port):
    info = MagicMock()
    info.parsed_addresses.return_value = addresses
    info.port = port
    return info


class _FakeZeroconfFactory(object):
    """Fakes zeroconf.Zeroconf and ServiceBrowser.

    When a browser is created, immediately delivers each fake service to the
    listener's add_service. Listener then calls zc.get_service_info, which we
    map from a precomputed table.
    """

    def __init__(self, services_by_type):
        # services_by_type: {type_: [(name, addresses, port), ...]}
        self.services_by_type = services_by_type
        self.closed = False

    def Zeroconf(self):  # pylint: disable=invalid-name
        zc = MagicMock()
        zc.get_service_info = self._lookup
        zc.close = self._close
        return zc

    def ServiceBrowser(self, zc, type_, listener):  # pylint: disable=invalid-name
        for name, _addresses, _port in self.services_by_type.get(type_, []):
            full_name = "{}.{}".format(name, type_)
            listener.add_service(zc, type_, full_name)
        return MagicMock()

    def _lookup(self, type_, name):
        for sname, addresses, port in self.services_by_type.get(type_, []):
            if name == "{}.{}".format(sname, type_):
                return _fake_service_info(addresses, port)
        return None

    def _close(self):
        self.closed = True


class DiscoverServicesSyncTest(unittest.TestCase):
    def test_returns_resolved_services(self):
        factory = _FakeZeroconfFactory({
            SERVICE_TYPE_TLS_CONNECT: [
                ("adb-DEVICE1", ["192.168.1.21"], 33015),
                ("adb-DEVICE2", ["192.168.1.42"], 44643),
            ],
        })

        with patch.object(discovery_mod, "time") as fake_time, \
             patch("zeroconf.Zeroconf", factory.Zeroconf), \
             patch("zeroconf.ServiceBrowser", factory.ServiceBrowser):
            fake_time.sleep = lambda _: None  # don't actually sleep in tests
            results = discover_services([SERVICE_TYPE_TLS_CONNECT], timeout_s=0.1)

        self.assertEqual(len(results), 2)
        names = {r.name for r in results}
        self.assertEqual(names, {"adb-DEVICE1", "adb-DEVICE2"})
        for r in results:
            self.assertEqual(r.type, SERVICE_TYPE_TLS_CONNECT)

        d1 = next(r for r in results if r.name == "adb-DEVICE1")
        self.assertEqual(d1.host, "192.168.1.21")
        self.assertEqual(d1.port, 33015)

    def test_filters_by_service_type(self):
        # If zeroconf reports a service the caller didn't ask for, ignore it.
        factory = _FakeZeroconfFactory({
            SERVICE_TYPE_PAIRING: [("studio-foo", ["10.0.0.1"], 555)],
            SERVICE_TYPE_TLS_CONNECT: [("adb-X", ["10.0.0.2"], 777)],
        })

        with patch.object(discovery_mod, "time") as fake_time, \
             patch("zeroconf.Zeroconf", factory.Zeroconf), \
             patch("zeroconf.ServiceBrowser", factory.ServiceBrowser):
            fake_time.sleep = lambda _: None
            results = discover_pairing_services(timeout_s=0.1)

        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].name, "studio-foo")
        self.assertEqual(results[0].type, SERVICE_TYPE_PAIRING)

    def test_skips_service_with_no_addresses(self):
        factory = _FakeZeroconfFactory({
            SERVICE_TYPE_TLS_CONNECT: [
                ("adb-good", ["192.168.1.1"], 1234),
                ("adb-no-ip", [], 5678),
            ],
        })

        with patch.object(discovery_mod, "time") as fake_time, \
             patch("zeroconf.Zeroconf", factory.Zeroconf), \
             patch("zeroconf.ServiceBrowser", factory.ServiceBrowser):
            fake_time.sleep = lambda _: None
            results = discover_connect_services(timeout_s=0.1)

        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].name, "adb-good")

    def test_namedtuple_equality(self):
        # Smoke test: AdbService is a value type usable in sets/dicts.
        a = AdbService(name="x", type=SERVICE_TYPE_TLS_CONNECT, host="1.1.1.1", port=1)
        b = AdbService(name="x", type=SERVICE_TYPE_TLS_CONNECT, host="1.1.1.1", port=1)
        self.assertEqual(a, b)
        self.assertEqual(len({a, b}), 1)


def _run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


class DiscoverServicesAsyncTest(unittest.TestCase):
    def test_async_module_imports(self):
        # The async path requires zeroconf.asyncio to be importable; we
        # verify it loads cleanly. Behavior is exercised by the manual
        # E2E sweep against a live LAN.
        from adb_shell_wifi.mdns.discovery_async import (  # noqa: F401
            discover_connect_services_async,
            discover_pairing_services_async,
            discover_services_async,
        )

    def test_async_returns_empty_for_no_services(self):
        # When nothing matches, the async API should return an empty list
        # (and not raise). We use a tiny timeout so the test is fast.
        from adb_shell_wifi.mdns.discovery_async import discover_services_async

        async def go():
            return await discover_services_async(
                ["_definitely-no-such-service._tcp.local."], timeout_s=0.1
            )

        self.assertEqual(_run(go()), [])


if __name__ == "__main__":
    unittest.main()
