#!/usr/bin/env python3
"""Browse the local network for ADB Wi-Fi services.

Usage:
    python scripts/mdns_demo.py          # both pairing + connect
    python scripts/mdns_demo.py pair     # just _adb-tls-pairing
    python scripts/mdns_demo.py connect  # just _adb-tls-connect

Lists each device's instance name, type, IP, and port — useful for finding
the random port a paired device's TLS data channel is listening on.
"""

import sys

from adb_shell.mdns import (
    SERVICE_TYPE_PAIRING,
    SERVICE_TYPE_TLS_CONNECT,
    discover_services,
)


def main():
    arg = sys.argv[1].lower() if len(sys.argv) > 1 else "all"
    if arg == "pair":
        types = [SERVICE_TYPE_PAIRING]
    elif arg == "connect":
        types = [SERVICE_TYPE_TLS_CONNECT]
    elif arg in ("all", ""):
        types = [SERVICE_TYPE_PAIRING, SERVICE_TYPE_TLS_CONNECT]
    else:
        print(__doc__, file=sys.stderr)
        sys.exit(2)

    print("Scanning for {} ...".format(", ".join(types)))
    results = discover_services(types, timeout_s=4.0)
    if not results:
        print("(no services found)")
        return
    for r in results:
        print("  {}  {}  {}:{}".format(r.name, r.type, r.host, r.port))


if __name__ == "__main__":
    main()
