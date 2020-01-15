#!/usr/bin/env python3
import base64
import sys

if len(sys.argv) > 1:
    h = sys.argv[1]
else:
    h = input("Enter hex to convert: ")

b = bytes.fromhex(h)
b64 = base64.b64encode(b).decode("ascii")

print(b64)
