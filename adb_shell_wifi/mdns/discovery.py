# Copyright (c) 2026 adb_shell contributors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0

"""Synchronous mDNS discovery for ADB Wi-Fi services.

* :class:`AdbService`
* :func:`discover_services`
* :func:`discover_pairing_services`
* :func:`discover_connect_services`
"""


import time
from collections import namedtuple


SERVICE_TYPE_LEGACY = "_adb._tcp.local."
SERVICE_TYPE_PAIRING = "_adb-tls-pairing._tcp.local."
SERVICE_TYPE_TLS_CONNECT = "_adb-tls-connect._tcp.local."


AdbService = namedtuple("AdbService", ("name", "type", "host", "port"))
"""A discovered ADB-related mDNS service.

Attributes
----------
name : str
    The instance name with the trailing service-type stripped (e.g.
    ``adb-G6G16D10104203M7``).
type : str
    The full service type string (e.g. ``_adb-tls-connect._tcp.local.``).
host : str
    First IPv4 address resolved for the service.
port : int
    Port the service is listening on.
"""


class _Listener(object):
    """Collects services as zeroconf reports them."""

    def __init__(self, service_types):
        self._service_types = set(service_types)
        self.results = {}  # name -> AdbService

    def add_service(self, zc, type_, name):
        """Resolve the service and store the result if it is a type we care about."""
        if type_ not in self._service_types:
            return
        info = zc.get_service_info(type_, name)
        if info is None:
            return
        ips = info.parsed_addresses()
        if not ips:
            return
        # Strip trailing ".<service_type>" from the name for ergonomics.
        short_name = name[: -(len(type_) + 1)] if name.endswith("." + type_) else name
        self.results[name] = AdbService(
            name=short_name, type=type_, host=ips[0], port=info.port
        )

    def remove_service(self, zc, type_, name):  # pylint: disable=unused-argument
        """Drop a service that was withdrawn from the network."""
        self.results.pop(name, None)

    def update_service(self, zc, type_, name):
        """Re-resolve a service whose records changed."""
        self.add_service(zc, type_, name)


def discover_services(service_types, timeout_s=4.0):
    """Browse for mDNS services of the given types and return what was found.

    Parameters
    ----------
    service_types : iterable of str
        e.g. ``[SERVICE_TYPE_TLS_CONNECT]``. Pass multiple to search several
        service types in a single sweep.
    timeout_s : float
        Seconds to listen before returning. Most LAN responses arrive in
        well under a second, but waiting a few helps with sleepy devices.

    Returns
    -------
    list of :class:`AdbService`
    """
    # Imported lazily so the dependency only loads when discovery is used.
    from zeroconf import ServiceBrowser, Zeroconf  # pylint: disable=import-outside-toplevel

    listener = _Listener(service_types)
    zc = Zeroconf()
    try:
        for svc_type in service_types:
            ServiceBrowser(zc, svc_type, listener)
        time.sleep(timeout_s)
    finally:
        zc.close()
    return list(listener.results.values())


def discover_pairing_services(timeout_s=4.0):
    """Find devices currently advertising a pairing server (``_adb-tls-pairing``)."""
    return discover_services([SERVICE_TYPE_PAIRING], timeout_s=timeout_s)


def discover_connect_services(timeout_s=4.0):
    """Find paired devices currently advertising a TLS data port (``_adb-tls-connect``)."""
    return discover_services([SERVICE_TYPE_TLS_CONNECT], timeout_s=timeout_s)
