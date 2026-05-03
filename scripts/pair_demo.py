#!/usr/bin/env python3
"""Run the ADB Wi-Fi pairing handshake against a real device.

Usage:
    python scripts/pair_demo.py <host> <port> <pairing-code> <adbkey-path>

Example:
    python scripts/pair_demo.py 192.168.1.42 43811 515109 ~/.android/adbkey

On the device, open
    Settings > System > Developer options > Wireless debugging
        > Pair device with pairing code
and use the IP/port/code shown there. The corresponding public key file
must exist at <adbkey-path> + ".pub".
"""

import os
import sys

from adb_shell_wifi.pairing import pair


def main():
    if len(sys.argv) != 5:
        print(__doc__, file=sys.stderr)
        sys.exit(2)

    host, port, code, adbkey_path = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4]

    adbkey_path = os.path.expanduser(adbkey_path)
    pub_path = adbkey_path + ".pub"

    with open(adbkey_path, "rb") as f:
        priv = f.read()
    with open(pub_path, "rb") as f:
        pub = f.read()

    print("pairing with {}:{} ...".format(host, port))
    peer_info = pair(
        host=host,
        port=port,
        pairing_code=code,
        private_key_pem=priv,
        public_key=pub,
    )
    print("paired. device peer info type={}, data={}".format(peer_info.type, peer_info.data))


if __name__ == "__main__":
    main()
