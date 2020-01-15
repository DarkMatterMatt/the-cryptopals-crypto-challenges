#!/usr/bin/env python3
import sys

# http://pi.math.cornell.edu/~mec/2003-2004/cryptography/subs/frequencies.html
FREQ_TABLE = {
    "E": 12.02,
    "T": 9.10,
    "A": 8.12,
    "O": 7.68,
    "I": 7.31,
    "N": 6.95,
    "S": 6.28,
    "R": 6.02,
    "H": 5.92,
    "D": 4.32,
    "L": 3.98,
    "U": 2.88,
    "C": 2.71,
    "M": 2.61,
    "F": 2.30,
    "Y": 2.11,
    "W": 2.09,
    "G": 2.03,
    "P": 1.82,
    "B": 1.49,
    "V": 1.11,
    "K": 0.69,
    "X": 0.17,
    "Q": 0.11,
    "J": 0.10,
    "Z": 0.07,
}

if len(sys.argv) > 1:
    h1 = sys.argv[1]
else:
    h1 = input("Enter hex string to single character XOR decrypt: ")

b1 = bytes.fromhex(h1)
scores = [[i, 0, ""] for i in range(256)]
for i in range(255):
    for b in b1:
        c = chr(b ^ i)
        if not c.isprintable():
            scores[i][1] = 0
            break

        scores[i][2] += c
        if c.upper() in FREQ_TABLE:
            scores[i][1] += FREQ_TABLE[c.upper()]
        
scores.sort(key=lambda x: x[1], reverse=True)

for score in scores[:5]:
    print(f"{round(score[1], 2):>7}) {score[2]}")
