#!/usr/bin/env python3
import base64
import requests
import sys
from functions import chunks, hamming_distance_bytes, solve_xor_keysize_bytes

MAX_KEY_SIZE = 40

r = requests.get("https://cryptopals.com/static/challenge-data/6.txt")
bytes_to_process = base64.b64decode(r.text)

if len(bytes_to_process) < MAX_KEY_SIZE * 2:
    raise ValueError("Not enough data to decrypt")

key_size_scores = []
for key_size in range(1, MAX_KEY_SIZE + 1):
    b = bytes_to_process[:len(bytes_to_process)//key_size*key_size]
    chunked = chunks(b, key_size)

    score = 0
    chunks_hammed = 0
    chunk1 = next(chunked)
    for chunk2 in chunked:
        score += hamming_distance_bytes(chunk1, chunk2)
        chunk1 = chunk2
        chunks_hammed += 1

    key_size_scores.append((score / key_size / chunks_hammed, key_size))

key_size_scores.sort(key=lambda x: x[0])

print("Score | KeySize")
for score in key_size_scores[:3]:
    print(f"{score[0]:5.2f} | {score[1]}")
print()

solved_scores = []
for _, key_size in key_size_scores[:3]:
    key, score, decrypted = solve_xor_keysize_bytes(bytes_to_process, key_size)
    solved_scores.append((key_size, key, score, decrypted))

solved_scores.sort(key=lambda x: x[2], reverse=True)

print("Key:", solved_scores[0][1])
print()
print(solved_scores[0][3])
