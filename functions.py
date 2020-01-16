#!/usr/bin/env python3

import base64

# http://www.fitaly.com/board/domper3/posts/136.html
_FREQ_TABLE = {
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

def _test():
    TEST_STRING = "The quick brown fox jumped over the lazy dog."
    assert base642hex("SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t") == "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
    assert hamming_distance_strings("jake", "fire") == 6
    assert hamming_distance_strings("this is a test", "wokka wokka!!!") == 37
    assert hex2base64("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d") == "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
    assert solve_xor_bytes(xor_strings(TEST_STRING, "Z", decode=False)) == (ord("Z"), string_score(TEST_STRING), TEST_STRING)
    assert solve_xor_keysize_bytes(xor_strings(TEST_STRING, "TEST", decode=False), 4) == ('TEST', 6095550, TEST_STRING)
    assert string_score(TEST_STRING) == 6131490
    assert xor_hex("1c0111001f010100061a024b53535009181c", "686974207468652062756c6c277320657965") == "746865206b696420646f6e277420706c6179"
    assert xor_bytes(bytearray("Burning 'em, if you ain't quick and nimble", "utf8"), bytes("ICE", "utf8")).hex() == "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20"
    assert xor_bytes(bytearray("I go crazy when I hear a cymbal", "utf8"), bytes("ICE", "utf8")).hex() == "0063222663263b223f30633221262b690a652126243b632469203c24212425"
    print("Tests passed successfully")

# https://stackoverflow.com/a/312464/6595777
def chunks(lst, n):
    """Yield successive n-sized chunks from lst."""
    for i in range(0, len(lst), n):
        yield lst[i:i + n]

def hex2base64(hex_str):
    b = bytes.fromhex(hex_str)
    return base64.b64encode(b).decode("ascii")

def base642hex(base64_str):
    b = base64.b64decode(base64_str)
    return b.hex()

def xor_strings(str1, str2, decode=True):
    xor = xor_bytes(bytearray(str1, "utf8"), bytes(str2, "utf8"))
    if decode:
        return xor.decode("utf8")
    return xor

def xor_hex(hex1, hex2, decode=True):
    xor = xor_bytes(bytearray.fromhex(hex1), bytes.fromhex(hex2))
    if decode:
        return xor.hex()
    return xor

def xor_bytes(b_str, b_key):
    key_len = len(b_key)
    for i in range(len(b_str)):
        b_str[i] ^= b_key[i % key_len]
    return b_str

def string_score(string):
    score = 0
    for char in string:
        score += _FREQ_TABLE[char if char in _FREQ_TABLE else "INVALID"]
    return score

def solve_xor_bytes(bytes_to_process):
    best = (-1, -1e6, "") # XOR, score, decrypted
    for i in range(256):
        string = "".join(chr(b ^ i) for b in bytes_to_process)
        score = string_score(string)
        if score > best[1]:
            best = i, score, string
    return best

def solve_xor_keysize_bytes(bytes_to_process, key_size):
    b = bytes_to_process[:len(bytes_to_process)//key_size*key_size]
    chunked = chunks(b, key_size)
    transposed = map(bytes, zip(*chunked))

    key, score, decrypted = b"", 0, ""
    for row in transposed:
        row_xor, row_score, row_decrypted = solve_xor_bytes(row)
        key += bytes((row_xor,))
        score += row_score
        decrypted += row_decrypted

    return key.decode("utf8"), score, xor_bytes(bytes_to_process, key).decode("utf8")

def hamming_distance_bytes(s1, s2):
    b_diff = xor_bytes(s1, s2)
    return sum(bin(x).count("1") for x in b_diff)

def hamming_distance_strings(s1, s2):
    b_diff = xor_strings(s1, s2, decode=False)
    return sum(bin(x).count("1") for x in b_diff)

if __name__ == "__main__":
    _test()
