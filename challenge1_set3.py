#!/usr/bin/env python3
import sys

# http://www.fitaly.com/board/domper3/posts/136.html
FREQ_TABLE = {
    "INVALID": -80000,
    "\r": 0,        "\n": 20000,    "\t": 136,      " ": 407934,    "!": 170,
    "\"": 5804,     "#": 425,       "$": 1333,      "%": 380,       "&": 536,
    "'": 5816,      "(": 5176,      ")": 5307,      "*": 1493,      "+": 511,
    ",": 17546,     "-": 32638,     ".": 35940,     "/": 3681,      "0": 13109,
    "1": 10916,     "2": 7894,      "3": 4389,      "4": 3204,      "5": 3951,
    "6": 2739,      "7": 2448,      "8": 2505,      "9": 2433,      ":": 10347,
    ";": 2884,      "<": 2911,      "=": 540,       ">": 2952,      "?": 3503,
    "@": 173,       "A": 7444,      "B": 5140,      "C": 9283,      "D": 7489,
    "E": 6351,      "F": 3365,      "G": 4459,      "H": 5515,      "I": 7631,
    "J": 4102,      "K": 1633,      "L": 4476,      "M": 8386,      "N": 4954,
    "O": 4378,      "P": 6211,      "Q": 751,       "R": 5986,      "S": 9512,
    "T": 7895,      "U": 1934,      "V": 2119,      "W": 6005,      "X": 815,
    "Y": 722,       "Z": 180,       "[": 205,       "\\": 37,       "]": 210,
    "^": 8,         "_": 2755,      "`": 21,        "a": 123287,    "b": 24227,
    "c": 50211,     "d": 59577,     "e": 203824,    "f": 32616,     "g": 37064,
    "h": 65217,     "i": 116488,    "j": 2061,      "k": 16047,     "l": 75450,
    "m": 39060,     "n": 118108,    "o": 137119,    "p": 36791,     "q": 1774,
    "r": 101201,    "s": 103814,    "t": 151376,    "u": 49901,     "v": 20109,
    "w": 30974,     "x": 4635,      "y": 26924,     "z": 1417,      "{": 62,
    "|": 16,        "}": 61,        "~": 8,         "ƒ": 1,         "•": 15233,
    "·": 23,        "ß": 1,         "â": 1,         "å": 1,         "æ": 1,         "í": 1,
}

if len(sys.argv) > 1:
    h1 = sys.argv[1]
else:
    h1 = input("Enter hex string to single character XOR decrypt: ")

b1 = bytes.fromhex(h1)
scores = [[i, 0, ""] for i in range(256)]
for i in range(255):
    for b in b1:
        char = chr(b ^ i)
        scores[i][2] += char
        scores[i][1] += FREQ_TABLE[char if char in FREQ_TABLE else "INVALID"]
        
scores.sort(key=lambda x: x[1], reverse=True)

scores.insert(0, ("XOR", "Score", "Result"))
for score in scores[:6]:
    print(f"{score[1]:>7} | {score[0]:>3} | {score[2]}")
