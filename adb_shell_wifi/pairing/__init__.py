# Copyright (c) 2026 adb_shell contributors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0

"""ADB Wi-Fi pairing client.

Public API:

* :func:`pair` / :func:`pair_async` — perform the SPAKE2 + TLS pairing
  handshake against an Android device and register the host's RSA public
  key in the device's keystore.
* :class:`PeerInfo` — the structured result returned by :func:`pair`.
* :exc:`PairingException` — raised on any failure during the handshake.
"""

from .connection import PairingException, PeerInfo
from .pairing_device import pair
from .pairing_device_async import pair_async


__all__ = ["pair", "pair_async", "PairingException", "PeerInfo"]
