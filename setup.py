"""setup.py file for the adb_shell package."""

from setuptools import setup

with open("README.rst") as f:
    readme = f.read()

setup(
    name="adb-shell-wifi",
    version="0.5.0",
    description="Fork of adb-shell with ADB Wi-Fi (TLS) pairing, TLS transport, and mDNS discovery added.",
    long_description=readme,
    long_description_content_type="text/x-rst",
    keywords=["adb", "android", "wifi", "tls"],
    url="https://github.com/jasonanovak/adb_shell",
    author="Jason Novak",
    author_email="jason@nvkmail.com",
    packages=[
        "adb_shell_wifi",
        "adb_shell_wifi.auth",
        "adb_shell_wifi.mdns",
        "adb_shell_wifi.pairing",
        "adb_shell_wifi.transport",
    ],
    install_requires=["cryptography", "pyasn1", "rsa"],
    tests_require=["pycryptodome", "libusb1>=1.0.16"],
    extras_require={
        "usb": ["libusb1>=1.0.16"],
        "async": ["aiofiles>=0.4.0", "async_timeout>=3.0.0"],
        "wifi": ["spake2-cffi>=1.0.0", "pyOpenSSL>=22.0.0", "zeroconf>=0.39"],
    },
    classifiers=[
        "Operating System :: OS Independent",
        "License :: OSI Approved :: Apache Software License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 2",
    ],
    test_suite="tests",
)
