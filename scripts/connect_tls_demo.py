#!/usr/bin/env python3
"""Connect to a paired Android device over the post-pairing TLS data channel.

Usage:
    python scripts/connect_tls_demo.py <host> <port> <adbkey-path> [<shell-command>]

Example:
    python scripts/connect_tls_demo.py 192.168.1.21 33015 ~/.android/adbkey "echo hello"

The <port> is the random port advertised by the device's
``_adb-tls-connect._tcp`` mDNS service (different from the pairing port).
You can find it by running ``adb mdns services`` from a system that has
the official adb client, or temporarily by running:

    python -c '
    from zeroconf import Zeroconf, ServiceBrowser
    import time
    class L:
        def add_service(self, zc, type_, name):
            info = zc.get_service_info(type_, name)
            print(name, info.parsed_addresses(), info.port)
        def remove_service(self, *a): pass
        def update_service(self, *a): pass
    zc = Zeroconf(); ServiceBrowser(zc, "_adb-tls-connect._tcp.local.", L())
    time.sleep(3); zc.close()'

If <shell-command> is omitted, the script just verifies that the connect
succeeds and prints the device banner.
"""

import os
import sys

from adb_shell_wifi.adb_device import AdbDeviceTls


def main():
    if len(sys.argv) < 4 or len(sys.argv) > 5:
        print(__doc__, file=sys.stderr)
        sys.exit(2)

    host = sys.argv[1]
    port = int(sys.argv[2])
    adbkey_path = os.path.expanduser(sys.argv[3])
    shell_cmd = sys.argv[4] if len(sys.argv) == 5 else None

    with open(adbkey_path, "rb") as f:
        priv_pem = f.read()

    print("connecting (TLS) to {}:{} ...".format(host, port))
    device = AdbDeviceTls(host, port, default_transport_timeout_s=10.0)
    ok = device.connect(rsa_keys=[], tls_priv_pem=priv_pem, auth_timeout_s=10.0)
    if not ok:
        print("connect failed", file=sys.stderr)
        sys.exit(1)
    print("connected.")

    if shell_cmd:
        print("running: {}".format(shell_cmd))
        result = device.shell(shell_cmd, timeout_s=10.0)
        print("output:")
        print(result)

    device.close()


if __name__ == "__main__":
    main()
