adb\_shell\_wifi
================

This package is a fork of `adb_shell <https://github.com/JeffLIrion/adb_shell>`_
that adds support for **modern ADB Wi-Fi pairing** — the 6-digit-code TLS
pairing flow introduced in Android 11's "Wireless debugging" feature, plus
the post-pairing TLS data channel and mDNS-based service discovery.

It exists primarily as a testbed for verifying that Wi-Fi pairing support
can be added to Home Assistant's Android TV integration. If you do not
need Wi-Fi pairing, install upstream ``adb-shell`` instead — the upstream
package is the canonical home of all non-Wi-Fi functionality.

Original ``adb_shell`` documentation: https://adb-shell.readthedocs.io/

Origin
------

This Python package implements ADB shell and FileSync functionality. It
originated from `python-adb <https://github.com/google/python-adb>`_ and
was substantially rewritten by Jeff Irion in
`adb_shell <https://github.com/JeffLIrion/adb_shell>`_; this fork adds
Wi-Fi pairing on top.

Installation
------------

.. code-block::

   pip install adb-shell-wifi


Async
*****

To utilize the async version of this code, you must install into a Python 3.7+ environment via:

.. code-block::

   pip install adb-shell-wifi[async]


USB Support (Experimental)
**************************

To connect to a device via USB, install this package via:

.. code-block::

   pip install adb-shell-wifi[usb]


Wi-Fi Pairing Support (Experimental)
************************************

To pair with a modern Android device using a 6-digit pairing code (Android 11+
"Wireless debugging"), install this package via:

.. code-block::

   pip install adb-shell-wifi[wifi]

This pulls in ``spake2-cffi`` and ``pyOpenSSL``. Note: ``spake2-cffi`` does
not publish Windows wheels, so Windows users will need a C toolchain
available at install time.

On the device, open ``Settings > System > Developer options > Wireless
debugging > Pair device with pairing code``. Note the IP address, port, and
6-digit code shown by the device, then:

.. code-block:: python

   from adb_shell_wifi.pairing import pair

   adbkey = "path/to/adbkey"
   with open(adbkey, "rb") as f:
       priv = f.read()
   with open(adbkey + ".pub", "rb") as f:
       pub = f.read()

   peer_info = pair(
       host="192.168.1.42",   # from device UI
       port=43811,            # from device UI
       pairing_code="515109", # from device UI
       private_key_pem=priv,
       public_key=pub,
   )
   print("device peer info:", peer_info.type, peer_info.data)

After pairing succeeds, the device records the host's public key in its
keystore. To actually run shell commands, push, pull, etc. over the
post-pairing TLS channel, use :class:`AdbDeviceTls` and pass the same
``adbkey`` PEM as ``tls_priv_pem``:

.. code-block:: python

   from adb_shell_wifi.adb_device import AdbDeviceTls
   from adb_shell_wifi.mdns import discover_connect_services

   # Find the random port the device chose for its TLS data socket.
   services = discover_connect_services(timeout_s=4.0)
   svc = services[0]   # or pick the right device by name/host

   device = AdbDeviceTls(svc.host, svc.port, default_transport_timeout_s=10.0)
   device.connect(rsa_keys=[], tls_priv_pem=priv, auth_timeout_s=10.0)
   print(device.shell("echo hello from adb_shell_wifi"))
   device.close()

The ``mdns`` module also exposes ``discover_pairing_services()`` for
finding devices that currently have a pairing dialog open, plus async
equivalents (``discover_connect_services_async``,
``discover_pairing_services_async``).


Example Usage
-------------

(Based on `androidtv/adb_manager.py <https://github.com/JeffLIrion/python-androidtv/blob/133063c8d6793a88259af405d6a69ceb301a0ca0/androidtv/adb_manager.py#L67>`_)

.. code-block:: python

   from adb_shell_wifi.adb_device import AdbDeviceTcp, AdbDeviceUsb
   from adb_shell_wifi.auth.sign_pythonrsa import PythonRSASigner

   # Load the public and private keys
   adbkey = 'path/to/adbkey'
   with open(adbkey) as f:
       priv = f.read()
   with open(adbkey + '.pub') as f:
        pub = f.read()
   signer = PythonRSASigner(pub, priv)

   # Connect
   device1 = AdbDeviceTcp('192.168.0.222', 5555, default_transport_timeout_s=9.)
   device1.connect(rsa_keys=[signer], auth_timeout_s=0.1)

   # Connect via USB (package must be installed via `pip install adb-shell-wifi[usb])`
   device2 = AdbDeviceUsb()
   device2.connect(rsa_keys=[signer], auth_timeout_s=0.1)

   # Send a shell command
   response1 = device1.shell('echo TEST1')
   response2 = device2.shell('echo TEST2')


Generate ADB Key Files
**********************

If you need to generate a key, you can do so as follows.

.. code-block:: python

  from adb_shell_wifi.auth.keygen import keygen

  keygen('path/to/adbkey')
