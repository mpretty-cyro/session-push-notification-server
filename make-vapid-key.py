#!/usr/bin/python3

import base64
import os
import sys
from os.path import isfile

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

usage = f"""Usage:
    {sys.argv[0]} FILENAME         -- writes a new VAPID (P-256) private key to FILENAME
    {sys.argv[0]} --show FILENAME  -- prints the public key of an existing VAPID key file

The public key is printed base64url-encoded (the "applicationServerKey" form), which is what the
UnifiedPush client passes to its distributor when registering."""


def public_key_b64url(key):
    raw = key.public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
    )
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


args = sys.argv[1:]
show = bool(args) and args[0] == "--show"
if show:
    args = args[1:]

if len(args) != 1 or not args[0] or args[0].startswith("-"):
    print(usage)
    sys.exit(1)

filename = args[0]

if show:
    with open(filename, "rb") as f:
        key = serialization.load_pem_private_key(f.read(), password=None)
    if not isinstance(key, ec.EllipticCurvePrivateKey) or not isinstance(key.curve, ec.SECP256R1):
        print(f"{filename} is not a P-256 private key")
        sys.exit(2)
    print(public_key_b64url(key))
    sys.exit(0)

if isfile(filename):
    print(f"Refusing to overwrite existing file {filename}")
    sys.exit(2)

key = ec.generate_private_key(ec.SECP256R1())
pem = key.private_bytes(
    serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
)
fd = os.open(filename, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(fd, "wb") as f:
    f.write(pem)

print(f"Generated new VAPID private key in {filename}; corresponding public key is:", end="\n\t")
print(public_key_b64url(key))
