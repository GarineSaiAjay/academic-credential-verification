#!/usr/bin/env python3
"""Prints the 6-digit authenticator-app code for a base32 secret. Usage: scripts/totp.py SECRET [STEP_OFFSET]"""
import base64, hashlib, hmac, struct, sys, time

secret = sys.argv[1].upper()
secret += "=" * (-len(secret) % 8)
counter = int(time.time()) // 30 + (int(sys.argv[2]) if len(sys.argv) > 2 else 0)
h = hmac.new(base64.b32decode(secret), struct.pack(">Q", counter), hashlib.sha1).digest()
o = h[-1] & 15
print("%06d" % ((struct.unpack(">I", h[o:o + 4])[0] & 0x7FFFFFFF) % 1000000))
