# ADB Wifi support — implementation plan

## Context

`adb_shell` is the Python ADB client used by Home Assistant's Android TV
integration. Modern Android (11+) deprecated the legacy `adb tcpip` flow in
favor of **ADB Wifi**, which adds three things on top of the existing ADB
protocol:

1. **Pairing.** A SPAKE2 + TLS handshake bootstrapped by a 6-digit code
   that gets the host's RSA public key into the device's keystore without
   needing a USB cable + on-device "Allow debugging" tap.
2. **TLS data channel.** After pairing, the device's wireless-debugging
   socket greets connections with `A_STLS` instead of `A_AUTH`. The host
   must complete a TLS 1.3 handshake (with the same RSA cert) before any
   normal ADB traffic flows.
3. **mDNS discovery.** Devices advertise `_adb-tls-pairing._tcp` while a
   pairing server is running and `_adb-tls-connect._tcp` while the TLS
   data server is running.

The reference is the C++ AOSP `adb` source tree at `../adb` (read-only).
Current `adb_shell` has no support for any of this — it only speaks the
legacy `A_AUTH` flow on USB and on `tcpip`-style ports. The end goal is
that the modified `adb_shell` drops into Home Assistant unchanged in API
surface while supporting modern Android TV devices.

## Delivery shape

Three sequential PRs against `wifi_support`. **Each PR follows a
commit → debug → test → commit cycle and must be verified working before
the next PR begins.** Each PR ships sync + async parity to match the
existing `adb_device.py` / `adb_device_async.py` split.

Progress is tracked via the agent task list (tasks #6–#18 at the time of
writing). Each task corresponds to a checklist item below.

---

## PR 1 — Pairing

Implements `pair(host, port, code, signer)` (and `pair_async(...)`): the
host performs a TLS handshake against the device's pairing server, runs
SPAKE2 over the TLS channel using `pairing_code +
TLS-exporter-keying-material` as the shared secret, and exchanges
encrypted `PeerInfo` blobs so the device records the host's RSA public key
in its keystore.

### Checklist

- [ ] **#6** Add `spake2-cffi>=1.0.0` and `pyOpenSSL>=22.0.0` to
      `setup.py:install_requires`. Note in `README.rst` that `spake2-cffi`
      has no Windows wheels (Windows users need a C toolchain).
- [ ] **#7** `adb_shell/auth/x509.py` — self-signed cert generator.
- [ ] **#8** `adb_shell/pairing/auth.py` — `PairingAuthCtx`
      (SPAKE2 + AES-128-GCM).
- [ ] **#9** `adb_shell/pairing/pairing_device.py` — sync `pair()`.
- [ ] **#10** `adb_shell/pairing/pairing_device_async.py` — async
      `pair_async()`.
- [ ] **#11** `tests/test_pairing.py` — unit tests.
- [ ] **#12** Manual E2E against a real Android TV; commit; open PR; wait
      for merge before PR 2.

### Protocol constants — verified from `../adb`, do not change

These must match the C++ implementation byte-for-byte. When in doubt,
re-read the reference rather than guessing.

- **SPAKE2 names** (the trailing NUL is included — the C source uses
  `sizeof(kClientName)`):
  - Client (Alice): `b"adb pair client\x00"` (16 bytes)
  - Server (Bob):   `b"adb pair server\x00"` (16 bytes)
- **HKDF derivation** (`adb/pairing_auth/aes_128_gcm.cpp`):
  - HKDF-SHA256 over the 64-byte SPAKE2 key material, no salt, info =
    `b"adb pairing_auth aes-128-gcm key"` (32 bytes, no trailing NUL),
    output 16 bytes (AES-128 key).
- **AES-128-GCM nonces**: 12-byte buffer with little-endian uint64
  sequence number in the low 8 bytes (high 4 bytes zero), separate
  counters for encrypt/decrypt, both starting at 0, incremented per
  message.
- **TLS exporter** (`adb/tls/tls_connection.cpp:36`): label =
  `b"adb-label"`, length = **64 bytes** (`kExportedKeySize` in
  `pairing_connection.cpp`), context = `None`. Result is appended to the
  pairing-code bytes to form the SPAKE2 password.
- **TLS version**: 1.3 only
  (`SSL_CTX_set_min/max_proto_version` both `TLS1_3_VERSION`). Peer cert
  is required by OpenSSL but **any cert is accepted** — the SPAKE2 PAKE
  provides authentication.
- **`PairingPacketHeader`** (6 bytes, packed):
  - `version` (uint8) = 1
  - `type` (uint8) — `0 = SPAKE2_MSG`, `1 = PEER_INFO`
  - `payload` (uint32, **big-endian**) — payload length in bytes
- **`PeerInfo`** (8192 bytes, fixed-size, packed):
  - `type` (uint8) = `0` (`ADB_RSA_PUB_KEY`)
  - `data` (8191 bytes) — host's Android-format public key as
    `<base64-android-pubkey> <user>@<host>` with the rest zero-padded.
    **This format already matches what
    `adb_shell/auth/keygen.py:write_public_keyfile` produces** — verified
    against `adb/crypto/rsa_2048_key.cpp:CalculatePublicKey`.

### X.509 certificate — verified from `adb/crypto/x509_generator.cpp`

Self-signed using the user's existing RSA 2048 ADB key:

- Subject = Issuer = `C=US, O=Android, CN=Adb`
- Serial = 1
- Not-before = now, not-after = now + 10 years
- Extensions in this order:
  - `basicConstraints` = `critical, CA:TRUE`
  - `keyUsage` = `critical, keyCertSign, cRLSign, digitalSignature`
  - `subjectKeyIdentifier` = `hash` (computed from the cert)
- Signed with SHA-256

Implement using `cryptography.x509.CertificateBuilder`. Reuse the user's
existing private key (`PythonRSASigner.priv_key`) — do not generate a
separate key for pairing.

### Handshake state machine — from `pairing_connection.cpp`

1. Open TCP connection to `<host>:<port>` (port from user, no default).
2. Wrap as TLS 1.3 client with cert + key, accept any peer cert.
3. After handshake, call
   `ssl.export_keying_material(b"adb-label", 64, None)` and append to
   the 6-digit pairing-code bytes → SPAKE2 password.
4. Build `PairingAuthCtx(role=client, password)` → produces our SPAKE2
   message.
5. Send `PairingPacketHeader(SPAKE2_MSG, len(our_msg))` + `our_msg`.
6. Read peer header, verify `type == SPAKE2_MSG`, read peer SPAKE2 msg,
   call `ctx.process_msg(peer_msg)` to derive the AES key. If this
   fails, the pairing code was wrong.
7. Build `PeerInfo` with our public key, AES-encrypt it.
8. Send `PairingPacketHeader(PEER_INFO, len(encrypted))` + encrypted
   blob.
9. Read peer header (must be `PEER_INFO`), read encrypted payload,
   AES-decrypt, parse 8192-byte `PeerInfo` struct.
10. Return success — the device has now persisted our public key.

### Verification

- Unit: `PairingAuthCtx` round-trip — client + server with the same
  password decrypt each other's ciphertext to the original plaintext.
- Unit: x509 cert structure — generate from a fixed RSA key, parse back,
  assert subject/issuer/extensions/validity match.
- Unit: `PairingPacketHeader` round-trip.
- Unit: `PeerInfo` packing — `len(packed) == 8192`, type byte 0, data
  starts with the public-key bytes, rest zero-padded.
- Manual E2E (the only true verification): on an Android TV with developer
  options open, "Pair device with pairing code" → run `pair("ip", port,
  "code", signer)` from a Python REPL → expect device UI to confirm
  pairing, and a subsequent `adb` command from the system `adb` binary
  using the same key should succeed.

---

## PR 2 — TLS data channel

After pairing, the device's wireless-debugging socket greets new
connections with an `A_STLS` packet instead of `A_AUTH`. The host must
respond with its own `A_STLS` packet, then both sides run a TLS 1.3
handshake (using the same RSA cert + key as pairing), and only then can
normal ADB traffic flow. Without this, paired devices cannot actually be
shelled.

### Checklist

- [ ] **#13** Add `STLS = b'STLS'`, `A_STLS_VERSION = 0x01000000` to
      `adb_shell/constants.py`. Add `STLS` to `IDS` so
      `_AdbIOManager._read_packet_from_device` accepts it.
- [ ] **#14** `adb_shell/transport/tls_transport.py` and
      `tls_transport_async.py` — TCP-style transport with an explicit
      `tls_upgrade(cert_pem, priv_key_pem)` method called after the
      `A_STLS` exchange.
- [ ] **#15** Wire `A_STLS` handling into `_AdbIOManager.connect`
      (sync + async): if the first packet is `STLS`, send our `STLS`
      reply (`arg0 = A_STLS_VERSION`, no data), call
      `transport.tls_upgrade(...)` if the transport supports it, then
      re-read for `A_CNXN`. Legacy `A_AUTH` and `A_CNXN`-first paths
      remain unchanged.
- [ ] **#16** Tests + manual E2E (connect to paired device's
      `_adb-tls-connect` port, run a shell command); commit; PR; wait
      for green before PR 3.

### Verification

- Unit: mocked transport emitting `STLS` then `CNXN` — assert
  `tls_upgrade` is called and the CNXN handler runs.
- Unit: legacy `AUTH` path is unchanged when the first packet is `AUTH`.
- Manual E2E: connect to the paired device's `_adb-tls-connect` port and
  run a shell command end-to-end. Verify USB and `tcpip`-on-5555 still
  work.

---

## PR 3 — mDNS discovery

Browse the local network for `_adb-tls-pairing._tcp` and
`_adb-tls-connect._tcp` services so callers can discover paired devices
without typing IP/port by hand.

### Checklist

- [ ] **#17** Add `zeroconf>=0.39` to `setup.py`. Create
      `adb_shell/mdns/discovery.py` and `discovery_async.py` with
      `discover_pairing_services(timeout=5.0)` and
      `discover_connect_services(timeout=5.0)` returning
      `[(name, host, port)]`. Sync uses `zeroconf.Zeroconf`; async uses
      `zeroconf.asyncio.AsyncZeroconf`.
- [ ] **#18** Tests with a mocked Zeroconf browser; manual E2E (paired
      Android TV on LAN should appear in `discover_connect_services()`);
      commit; final PR.

### Verification

- Unit: mocked `Zeroconf` service browser yielding fake service records.
- Manual E2E: paired Android TV on LAN appears in
  `discover_connect_services()` with correct random port.

---

## Critical reference files (read-only, in `../adb`)

For each PR, treat these as authoritative — when in doubt, re-read them
rather than guessing.

**PR 1**:
- `pairing_auth/pairing_auth.cpp` and `pairing_auth/aes_128_gcm.cpp`
- `pairing_connection/pairing_connection.cpp`
- `client/pairing/pairing_client.cpp`
- `client/auth.cpp:adb_auth_get_userkey` (PeerInfo construction)
- `crypto/x509_generator.cpp` (cert details)
- `crypto/rsa_2048_key.cpp:CalculatePublicKey` (pubkey format — already
  matches `adb_shell/auth/keygen.py`)
- `tls/tls_connection.cpp` (TLS version + exporter label)
- `proto/pairing.proto` (`PairingPacket` enum values)
- `pairing_connection/include/adb/pairing/pairing_connection.h`
  (`PeerInfo` struct, `kMaxPeerInfoSize = 8192`)

**PR 2**:
- `adb.h` (`A_STLS = 0x534C5453`, `A_STLS_VERSION = 0x01000000`)
- `transport.cpp` — the `if (packet->msg.command == A_STLS)` branch
  shows the host-side handling sequence

**PR 3**:
- `docs/dev/adb_wifi.md` § Network Advertising (mDNS service types)
- `client/transport_mdns.cpp` (service-name format details if needed)
