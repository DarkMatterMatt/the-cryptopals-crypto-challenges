#!/usr/bin/env python3
import base64
import hashlib
import requests
from Crypto import Random
from Crypto.Cipher import AES

class AESCipher(object):
    def __init__(self, key): 
        self.key = key

    def encrypt(self, raw):
        raw = self._pad(raw)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_ECB, iv)
        return base64.b64encode(iv + cipher.encrypt(raw.encode()))

    def decrypt(self, enc):
        enc = base64.b64decode(enc)
        iv = enc[:AES.block_size]
        cipher = AES.new(self.key, AES.MODE_ECB, iv)
        return self._unpad(cipher.decrypt(enc[AES.block_size:])).decode("utf8")

    @staticmethod
    def _pad(s):
        padding = AES.block_size - len(s) % AES.block_size
        return s + chr(padding) * padding

    @staticmethod
    def _unpad(s):
        padding = ord(s[-1:])
        return s[:-padding]

r = requests.get("https://cryptopals.com/static/challenge-data/7.txt")
print(AESCipher("YELLOW SUBMARINE").decrypt(r.text))
