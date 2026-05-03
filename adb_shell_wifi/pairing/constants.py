# Copyright (c) 2026 adb_shell contributors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0

"""Wire-format constants for the ADB Wi-Fi pairing protocol.

Every value here is verified against the AOSP ``adb`` source. Do not change
without re-reading the C++ reference.
"""


# SPAKE2 role names. The peer C++ code passes ``sizeof(kClientName)`` which
# includes the trailing NUL; ``spake2-cffi`` appends the NUL automatically,
# so we pass the literal without it.
SPAKE2_CLIENT_NAME = b"adb pair client"
SPAKE2_SERVER_NAME = b"adb pair server"

# HKDF-SHA256 info string used to derive the AES-128-GCM key from the
# 64-byte SPAKE2 key material. From ``adb/pairing_auth/aes_128_gcm.cpp``.
HKDF_INFO = b"adb pairing_auth aes-128-gcm key"
AES_KEY_LENGTH = 16

# RFC 5705 / RFC 8446 TLS exporter. From ``adb/tls/tls_connection.cpp:185``:
# the C++ passes ``sizeof(kExportedKeyLabel)`` to ``SSL_export_keying_material``,
# which is 10 (the literal "adb-label" *plus* the trailing NUL byte), not 9.
# This is the byte sequence that goes into TLS 1.3's exporter HKDF, so it
# must match exactly or the host and device derive different key material.
TLS_EXPORTER_LABEL = b"adb-label\x00"
TLS_EXPORTER_LENGTH = 64

# PairingPacketHeader (6 bytes total): version (uint8), type (uint8),
# payload length (uint32 big-endian).
PAIRING_PACKET_HEADER_VERSION = 1
PAIRING_PACKET_HEADER_FORMAT = ">BBI"
PAIRING_PACKET_HEADER_SIZE = 6

# PairingPacket.Type values from ``adb/proto/pairing.proto``.
PAIRING_PACKET_TYPE_SPAKE2_MSG = 0
PAIRING_PACKET_TYPE_PEER_INFO = 1

# PeerInfo struct from ``adb/pairing_connection/include/adb/pairing/pairing_connection.h``.
# Fixed 8192-byte payload: 1-byte type + 8191-byte data, the latter zero-padded.
PEER_INFO_SIZE = 8192
PEER_INFO_DATA_SIZE = PEER_INFO_SIZE - 1

# PeerInfoType values.
PEER_INFO_TYPE_ADB_RSA_PUB_KEY = 0
PEER_INFO_TYPE_ADB_DEVICE_GUID = 1

# Maximum payload size accepted in a PairingPacketHeader. Mirrors the C++
# constant ``kMaxPayloadSize = kMaxPeerInfoSize * 2``.
MAX_PAYLOAD_SIZE = PEER_INFO_SIZE * 2
