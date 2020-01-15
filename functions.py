#!/usr/bin/env python3

import base64

def _test():
    assert hex2base64("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d") == "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
    assert xor_hex("1c0111001f010100061a024b53535009181c", "686974207468652062756c6c277320657965") == "746865206b696420646f6e277420706c6179"

def hex2base64(hex_str):
    b = bytes.fromhex(hex_str)
    return base64.b64encode(b).decode("ascii")

def xor_hex(hex_str1, hex_str2):
    b1 = bytes.fromhex(hex_str1)
    b2 = bytes.fromhex(hex_str2)
    b3 = bytes(a ^ b for (a, b) in zip(b1, b2))
    return b3.hex()

if __name__ == "__main__":
    _test()
