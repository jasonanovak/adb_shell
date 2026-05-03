# Copyright (c) 2026 adb_shell contributors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0

"""Asynchronous wrapper around :func:`adb_shell.pairing.pairing_device.pair`.

Pairing is a one-shot, user-initiated operation, so we delegate to the sync
implementation in a thread executor rather than re-implementing the TLS +
SPAKE2 handshake on top of asyncio. This keeps the async surface trivial
while matching the API shape of the rest of the package's ``*_async``
modules.

* :func:`pair_async`
"""


import asyncio
import functools

from .pairing_device import _DEFAULT_TIMEOUT_S, pair


async def pair_async(host, port, pairing_code, private_key_pem, public_key,
                     timeout_s=_DEFAULT_TIMEOUT_S):
    """Async wrapper around :func:`adb_shell.pairing.pairing_device.pair`.

    The arguments and return value match the sync version. The handshake
    runs in the default thread executor so the calling event loop is not
    blocked.
    """
    loop = asyncio.get_event_loop()
    func = functools.partial(
        pair,
        host=host,
        port=port,
        pairing_code=pairing_code,
        private_key_pem=private_key_pem,
        public_key=public_key,
        timeout_s=timeout_s,
    )
    return await loop.run_in_executor(None, func)
