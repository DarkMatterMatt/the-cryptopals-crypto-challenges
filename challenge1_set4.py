#!/usr/bin/env python3
import requests
import sys
from functions import string_score

r = requests.get("https://cryptopals.com/static/challenge-data/4.txt")
text = r.text

scores = []
for line_hex in text.splitlines():
    line_bytes = bytes.fromhex(line_hex)

    for i in range(256):
        string = "".join(chr(b ^ i) for b in line_bytes)
        score = string_score(string)
        scores.append((score, string))

scores.sort(key=lambda x: x[0], reverse=True)

scores.insert(0, ("Score", "Result"))
for score in scores[:6]:
    print(f"{score[0]:>7} | {score[1]}")
