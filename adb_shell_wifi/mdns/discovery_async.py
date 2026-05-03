# Copyright (c) 2026 adb_shell contributors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0

"""Async mDNS discovery for ADB Wi-Fi services.

* :func:`discover_services_async`
* :func:`discover_pairing_services_async`
* :func:`discover_connect_services_async`
"""


import asyncio

from .discovery import (
    AdbService,
    SERVICE_TYPE_PAIRING,
    SERVICE_TYPE_TLS_CONNECT,
)


class _AsyncCollector(object):
    """Listener that records observed (type, name) pairs without resolving.

    Resolution to host/port via AsyncServiceInfo happens after the browse
    window closes, off the zeroconf event-loop callback path (so we don't
    invoke the sync ``ServiceInfo.request`` from inside an async callback,
    which zeroconf's async stack explicitly rejects).
    """

    def __init__(self, service_types):
        self._service_types = set(service_types)
        self.observed = set()  # set of (type_, name)

    def add_service(self, zc, type_, name):
        if type_ in self._service_types:
            self.observed.add((type_, name))

    def remove_service(self, zc, type_, name):  # pylint: disable=unused-argument
        self.observed.discard((type_, name))

    def update_service(self, zc, type_, name):
        if type_ in self._service_types:
            self.observed.add((type_, name))


async def discover_services_async(service_types, timeout_s=4.0):
    """Async equivalent of :func:`adb_shell.mdns.discovery.discover_services`."""
    from zeroconf import IPVersion  # pylint: disable=import-outside-toplevel
    from zeroconf.asyncio import (  # pylint: disable=import-outside-toplevel
        AsyncServiceBrowser,
        AsyncServiceInfo,
        AsyncZeroconf,
    )

    collector = _AsyncCollector(service_types)
    azc = AsyncZeroconf()
    browsers = []
    try:
        for svc_type in service_types:
            browsers.append(
                AsyncServiceBrowser(azc.zeroconf, svc_type, listener=collector)
            )
        await asyncio.sleep(timeout_s)

        results = {}
        for type_, name in collector.observed:
            info = AsyncServiceInfo(type_, name)
            ok = await info.async_request(azc.zeroconf, timeout=2000)
            if not ok:
                continue
            ips = info.parsed_addresses(version=IPVersion.V4Only)
            if not ips:
                continue
            short_name = (
                name[: -(len(type_) + 1)] if name.endswith("." + type_) else name
            )
            results[name] = AdbService(
                name=short_name, type=type_, host=ips[0], port=info.port
            )
    finally:
        for browser in browsers:
            await browser.async_cancel()
        await azc.async_close()
    return list(results.values())


async def discover_pairing_services_async(timeout_s=4.0):
    """Async: find devices advertising a pairing server."""
    return await discover_services_async([SERVICE_TYPE_PAIRING], timeout_s=timeout_s)


async def discover_connect_services_async(timeout_s=4.0):
    """Async: find paired devices advertising a TLS data port."""
    return await discover_services_async([SERVICE_TYPE_TLS_CONNECT], timeout_s=timeout_s)
