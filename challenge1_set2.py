#!/usr/bin/env python3

# Fixed XOR

import sys

if len(sys.argv) > 1:
    h1 = sys.argv[1]
else:
    h1 = input("Enter hex1 to XOR: ")

if len(sys.argv) > 2:
    h2 = sys.argv[2]
else:
    h2 = input("Enter hex2 to XOR: ")

b1 = bytes.fromhex(h1)
b2 = bytes.fromhex(h2)

length = len(b1)
b3 = [None] * length
for i in range(length):
    b3[i] = b1[i] ^ b2[i]

h3 = bytes(b3).hex()
print(h3)
