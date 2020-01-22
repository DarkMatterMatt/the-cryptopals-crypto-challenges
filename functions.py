#!/usr/bin/env python3

import base64
from pprint import pprint

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
    assert AES.forward_sbox(0x9a) == 0xb8
    assert AES.reverse_sbox(0xb8) == 0x9a
    assert hamming_distance_strings("jake", "fire") == 6
    assert hamming_distance_strings("this is a test", "wokka wokka!!!") == 37
    assert hex2base64("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d") == "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
    assert AES.rot_bytes(bytes([0, 1, 2, 3])) == bytes([1, 2, 3, 0])
    assert solve_xor_bytes(xor_strings(TEST_STRING, "Z", decode=False)) == (ord("Z"), string_score(TEST_STRING), TEST_STRING)
    assert solve_xor_keysize_bytes(xor_strings(TEST_STRING, "TEST", decode=False), 4) == ('TEST', 6095550, TEST_STRING)
    assert string_score(TEST_STRING) == 6131490
    assert xor_hex("1c0111001f010100061a024b53535009181c", "686974207468652062756c6c277320657965") == "746865206b696420646f6e277420706c6179"
    assert xor_bytes(bytes("Burning 'em, if you ain't quick and nimble", "utf8"), bytes("ICE", "utf8")).hex() == "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20"
    assert xor_bytes(bytes("I go crazy when I hear a cymbal", "utf8"), bytes("ICE", "utf8")).hex() == "0063222663263b223f30633221262b690a652126243b632469203c24212425"
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
    xor = xor_bytes(bytes(str1, "utf8"), bytes(str2, "utf8"))
    if decode:
        return xor.decode("utf8")
    return xor

def xor_hex(hex1, hex2, decode=True):
    xor = xor_bytes(bytes.fromhex(hex1), bytes.fromhex(hex2))
    if decode:
        return xor.hex()
    return xor

def xor_bytes(b_str, b_key):
    xor = bytearray(b_str)
    key_len = len(b_key)
    for i in range(len(b_str)):
        xor[i] ^= b_key[i % key_len]
    return xor

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

    key, score = [], 0
    for row in transposed:
        row_xor, row_score, _ = solve_xor_bytes(row)
        key.append(row_xor)
        score += row_score

    key = bytes(key)
    decrypted = xor_bytes(bytes_to_process, key).decode("utf8")
    return key.decode("utf8"), score, decrypted

def hamming_distance_bytes(s1, s2):
    b_diff = xor_bytes(s1, s2)
    return sum(bin(x).count("1") for x in b_diff)

def hamming_distance_strings(s1, s2):
    b_diff = xor_strings(s1, s2, decode=False)
    return sum(bin(x).count("1") for x in b_diff)

class AES:
    _FORWARD_SBOX = (
        (0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76),
        (0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0),
        (0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15),
        (0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75),
        (0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84),
        (0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF),
        (0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8),
        (0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2),
        (0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73),
        (0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB),
        (0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79),
        (0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08),
        (0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A),
        (0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E),
        (0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF),
        (0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16),
    )

    _REVERSE_SBOX = (
        (0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB),
        (0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB),
        (0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E),
        (0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25),
        (0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92),
        (0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84),
        (0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06),
        (0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B),
        (0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73),
        (0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E),
        (0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B),
        (0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4),
        (0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F),
        (0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF),
        (0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61),
        (0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D),
    )

    _ROUND_CONSTANTS = (
        0x8D, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D, 0x9A,
        0x2F, 0x5E, 0xBC, 0x63, 0xC6, 0x97, 0x35, 0x6A, 0xD4, 0xB3, 0x7D, 0xFA, 0xEF, 0xC5,
    )

    def __init__(self, key, key_length, rounds, block_size, state=(0, 0, 0, 0)):
        self.k = key
        self.n = key_length # length in 32bit words
        self.r = rounds
        self.bs = block_size
        self.s = state

    @staticmethod
    def xor(b1, b2):
        return [a ^ b for a, b in zip(b1, b2)]

    @staticmethod
    def forward_sbox(byte):
        return AES._FORWARD_SBOX[byte >> 4 & 0xF][byte & 0xF]

    @staticmethod
    def reverse_sbox(byte):
        return AES._REVERSE_SBOX[byte >> 4 & 0xF][byte & 0xF]

    @staticmethod
    def rot_bytes(bytes_, count=1):
        return bytes_[count:] + bytes_[:count]

    @staticmethod
    def sub_bytes(bytes_):
        return [AES.forward_sbox(b) for b in bytes_]

    @staticmethod
    def pkcs7_pad_bytes(block_size, bytes_to_pad):
        padding = block_size - len(bytes_to_pad) % block_size
        return bytes_to_pad + bytes([padding]) * padding

    @staticmethod
    def pkcs7_unpad_bytes(bytes_to_unpad):
        padding = bytes_to_unpad[-1]
        return bytes_to_unpad[:-padding]

    @staticmethod
    def word_to_bytes(word):
        return bytes((
            word >> 24 & 0xFF,
            word >> 16 & 0xFF,
            word >>  8 & 0xFF,
            word >>  0 & 0xFF,
        ))

    @staticmethod
    def bytes_to_word(bytes_):
        return sum((
            bytes_[0] << 24,
            bytes_[1] << 16,
            bytes_[2] <<  8,
            bytes_[3] <<  0,
        ))

    # https://en.wikipedia.org/wiki/Rijndael_MixColumns
    @staticmethod
    def gmul(a, b):
        p = 0
        for _ in range(8):
            if b & 1:
                p ^= a
            high_bit_set = a & 0x80 != 0
            a <<= 1
            if high_bit_set:
                a ^= 0x1B
            b >>= 1
        return p

    @staticmethod
    def get_word(lst, i):
        return lst[i * 4 : i * 4 + 4]

    def key_expansion(self):
        e = list(self.k)

        for i in range(self.n, self.r * self.bs):
            tmp = AES.get_word(e, i - 1)
            if i % self.n == 0:
                tmp =  AES.xor(AES.sub_bytes(AES.rot_bytes(tmp)), (AES._ROUND_CONSTANTS[i // self.n], 0, 0, 0))
            elif self.n > 6 and i % self.n == 4:
                tmp = AES.sub_bytes(tmp)
            e.extend(AES.xor(tmp, AES.get_word(e, i - self.n)))

        return e

    def enc_add_round_key(self, key):
        for i in range(4):
            self.s[i] = AES.xor(self.s[i], key)

    def enc_sub_bytes(self):
        for y in range(4):
            for x in range(self.n):
                self.s[y][x] = AES.forward_sbox(self.s[y][x])

    def enc_shift_rows(self):
        for y in range(1, 4):
            self.s[y] = AES.rot_bytes(self.s[y], y)

    def enc_mix_columns(self):
        result = [[] for _ in range(4)]
        for x in range(self.n):
            result[0].append(AES.gmul(0x02, self.s[0][x]) ^ AES.gmul(0x03, self.s[1][x]) ^                self.s[2][x]  ^                self.s[3][x] )
            result[1].append(               self.s[0][x]  ^ AES.gmul(0x02, self.s[1][x]) ^ AES.gmul(0x03, self.s[2][x]) ^                self.s[3][x] )
            result[2].append(               self.s[0][x]  ^                self.s[1][x]  ^ AES.gmul(0x02, self.s[2][x]) ^ AES.gmul(0x03, self.s[3][x]))
            result[3].append(AES.gmul(0x03, self.s[0][x]) ^                self.s[1][x]  ^                self.s[2][x]  ^ AES.gmul(0x02, self.s[3][x]))
        self.s = result

    def enc_mix_columns2(self):
        ss = []
        for x in range(self.n):
            col = [self.s[0][x], self.s[1][x], self.s[2][x], self.s[3][x]]
            ss.append((
                AES.gmul(0x02, col[0]) ^ AES.gmul(0x03, col[1]) ^                col[2]  ^                col[3] ,
                               col[0]  ^ AES.gmul(0x02, col[1]) ^ AES.gmul(0x03, col[2]) ^                col[3] ,
                               col[0]  ^                col[1]  ^ AES.gmul(0x02, col[2]) ^ AES.gmul(0x03, col[3]),
                AES.gmul(0x03, col[0]) ^                col[1]  ^                col[2]  ^ AES.gmul(0x02, col[3]),
            ))
        self.s = ss

    def bytes_to_state(self, bytes_):
        i = 0
        self.s = [[] for _ in range(4)]
        for _ in range(self.n):
            for y in range(4):
                self.s[y].append(bytes_[i])
                i += 1

    def state_to_bytes(self):
        b = bytearray()
        for x in range(self.n):
            for y in range(4):
                b.append(self.s[y][x])
        return b

    def encrypt(self, data):
        self.bytes_to_state(data)
        e = self.key_expansion()
        self.enc_add_round_key(AES.get_word(e, 0))
        for i in range(1, self.r):
            self.enc_sub_bytes()
            self.enc_shift_rows()
            self.enc_mix_columns()
            self.enc_add_round_key(AES.get_word(e, i))
        self.enc_sub_bytes()
        self.enc_shift_rows()
        self.enc_add_round_key(AES.get_word(e, self.r))
        return self.state_to_bytes()

def _test_aes():
    key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
    check = (
        ("6bc1bee22e409f96e93d7e117393172a", "3ad77bb40d7a3660a89ecaf32466ef97"),
        ("ae2d8a571e03ac9c9eb76fac45af8e51", "f5d3d58503b9699de785895a96fdbaaf"),
        ("30c81c46a35ce411e5fbc1191a0a52ef", "43b1cd7f598ece23881b00e3ed030688"),
        ("f69f2445df4f9b17ad2b417be66c3710", "7b0c785e27e8ad3f8223207104725dd4"),
    )
    aes = AES(key, 4, 10, 4)
    for k, v in check:
        kb = bytes.fromhex(k)
        vb = bytes.fromhex(v)
        tmp = aes.encrypt(kb).hex()
        if tmp == vb:
            print("yay!")
        else:
            print(":(", v, "!=", tmp)
        break

if __name__ == "__main__":
    _test()
    _test_aes()

