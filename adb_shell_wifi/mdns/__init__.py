# Copyright (c) 2026 adb_shell contributors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0

"""Local-network discovery of ADB Wi-Fi services.

Android devices with "Wireless debugging" enabled advertise three mDNS
service types (see ``adb/docs/dev/adb_wifi.md``):

* ``_adb._tcp`` — legacy ``adb tcpip`` socket.
* ``_adb-tls-pairing._tcp`` — pairing server (only while the "Pair device
  with pairing code" dialog is open on the device).
* ``_adb-tls-connect._tcp`` — TLS data channel for paired devices, on a
  random port chosen by adbd.

Public API:

* :class:`AdbService` — discovered service entry.
* :func:`discover_pairing_services` / :func:`discover_pairing_services_async`
* :func:`discover_connect_services` / :func:`discover_connect_services_async`
"""

from .discovery import (
    AdbService,
    SERVICE_TYPE_LEGACY,
    SERVICE_TYPE_PAIRING,
    SERVICE_TYPE_TLS_CONNECT,
    discover_connect_services,
    discover_pairing_services,
    discover_services,
)
from .discovery_async import (
    discover_connect_services_async,
    discover_pairing_services_async,
    discover_services_async,
)


__all__ = [
    "AdbService",
    "SERVICE_TYPE_LEGACY",
    "SERVICE_TYPE_PAIRING",
    "SERVICE_TYPE_TLS_CONNECT",
    "discover_connect_services",
    "discover_pairing_services",
    "discover_services",
    "discover_connect_services_async",
    "discover_pairing_services_async",
    "discover_services_async",
]
