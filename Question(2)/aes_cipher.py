import base64
import os
from hashlib import sha256

# S-box for AES
s_box = [
    # 0     1    2     3     4    5     6     7     8    9     A     B     C     D     E     F
    0x63,
    0x7C,
    0x77,
    0x7B,
    0xF2,
    0x6B,
    0x6F,
    0xC5,
    0x30,
    0x01,
    0x67,
    0x2B,
    0xFE,
    0xD7,
    0xAB,
    0x76,
    0xCA,
    0x82,
    0xC9,
    0x7D,
    0xFA,
    0x59,
    0x47,
    0xF0,
    0xAD,
    0xD4,
    0xA2,
    0xAF,
    0x9C,
    0xA4,
    0x72,
    0xC0,
    0xB7,
    0xFD,
    0x93,
    0x26,
    0x36,
    0x3F,
    0xF7,
    0xCC,
    0x34,
    0xA5,
    0xE5,
    0xF1,
    0x71,
    0xD8,
    0x31,
    0x15,
    0x04,
    0xC7,
    0x23,
    0xC3,
    0x18,
    0x96,
    0x05,
    0x9A,
    0x07,
    0x12,
    0x80,
    0xE2,
    0xEB,
    0x27,
    0xB2,
    0x75,
    0x09,
    0x83,
    0x2C,
    0x1A,
    0x1B,
    0x6E,
    0x5A,
    0xA0,
    0x52,
    0x3B,
    0xD6,
    0xB3,
    0x29,
    0xE3,
    0x2F,
    0x84,
    0x53,
    0xD1,
    0x00,
    0xED,
    0x20,
    0xFC,
    0xB1,
    0x5B,
    0x6A,
    0xCB,
    0xBE,
    0x39,
    0x4A,
    0x4C,
    0x58,
    0xCF,
    0xD0,
    0xEF,
    0xAA,
    0xFB,
    0x43,
    0x4D,
    0x33,
    0x85,
    0x45,
    0xF9,
    0x02,
    0x7F,
    0x50,
    0x3C,
    0x9F,
    0xA8,
    0x51,
    0xA3,
    0x40,
    0x8F,
    0x92,
    0x9D,
    0x38,
    0xF5,
    0xBC,
    0xB6,
    0xDA,
    0x21,
    0x10,
    0xFF,
    0xF3,
    0xD2,
    0xCD,
    0x0C,
    0x13,
    0xEC,
    0x5F,
    0x97,
    0x44,
    0x17,
    0xC4,
    0xA7,
    0x7E,
    0x3D,
    0x64,
    0x5D,
    0x19,
    0x73,
    0x60,
    0x81,
    0x4F,
    0xDC,
    0x22,
    0x2A,
    0x90,
    0x88,
    0x46,
    0xEE,
    0xB8,
    0x14,
    0xDE,
    0x5E,
    0x0B,
    0xDB,
    0xE0,
    0x32,
    0x3A,
    0x0A,
    0x49,
    0x06,
    0x24,
    0x5C,
    0xC2,
    0xD3,
    0xAC,
    0x62,
    0x91,
    0x95,
    0xE4,
    0x79,
    0xE7,
    0xC8,
    0x37,
    0x6D,
    0x8D,
    0xD5,
    0x4E,
    0xA9,
    0x6C,
    0x56,
    0xF4,
    0xEA,
    0x65,
    0x7A,
    0xAE,
    0x08,
    0xBA,
    0x78,
    0x25,
    0x2E,
    0x1C,
    0xA6,
    0xB4,
    0xC6,
    0xE8,
    0xDD,
    0x74,
    0x1F,
    0x4B,
    0xBD,
    0x8B,
    0x8A,
    0x70,
    0x3E,
    0xB5,
    0x66,
    0x48,
    0x03,
    0xF6,
    0x0E,
    0x61,
    0x35,
    0x57,
    0xB9,
    0x86,
    0xC1,
    0x1D,
    0x9E,
    0xE1,
    0xF8,
    0x98,
    0x11,
    0x69,
    0xD9,
    0x8E,
    0x94,
    0x9B,
    0x1E,
    0x87,
    0xE9,
    0xCE,
    0x55,
    0x28,
    0xDF,
    0x8C,
    0xA1,
    0x89,
    0x0D,
    0xBF,
    0xE6,
    0x42,
    0x68,
    0x41,
    0x99,
    0x2D,
    0x0F,
    0xB0,
    0x54,
    0xBB,
    0x16,
]

# Rcon for AES
rcon = [
    0x00,
    0x01,
    0x02,
    0x04,
    0x08,
    0x10,
    0x20,
    0x40,
    0x80,
    0x1B,
    0x36,
    0x6C,
    0xD8,
    0xAB,
    0x4D,
    0x9A,
    0x2F,
    0x5E,
    0xBC,
    0x63,
    0xC6,
    0x97,
    0x35,
    0x6A,
    0xD4,
    0xB3,
    0x7D,
    0xFA,
    0xEF,
    0xC5,
    0x91,
]


# Helper functions for AES
def xor_bytes(a, b):
    return bytes(i ^ j for i, j in zip(a, b))


def sub_bytes(state):
    return bytes(s_box[b] for b in state)


def shift_rows(state):
    return bytes(
        [
            state[0],
            state[5],
            state[10],
            state[15],
            state[4],
            state[9],
            state[14],
            state[3],
            state[8],
            state[13],
            state[2],
            state[7],
            state[12],
            state[1],
            state[6],
            state[11],
        ]
    )


def mix_columns(state):
    def xtime(a):
        return (((a << 1) ^ 0x1B) & 0xFF) if (a & 0x80) else (a << 1)

    def mix_single_column(a):
        t = a[0] ^ a[1] ^ a[2] ^ a[3]
        u = a[0]
        a[0] ^= t ^ xtime(a[0] ^ a[1])
        a[1] ^= t ^ xtime(a[1] ^ a[2])
        a[2] ^= t ^ xtime(a[2] ^ a[3])
        a[3] ^= t ^ xtime(a[3] ^ u)
        return a

    state = bytearray(state)
    for i in range(4):
        column = state[i::4]
        state[i::4] = mix_single_column(column)
    return bytes(state)


def add_round_key(state, key):
    return xor_bytes(state, key)


def expand_key(key):
    key_columns = 4
    expanded_key_columns = 44
    key_size = 16
    expanded_key = bytearray(key)
    current_size = key_columns
    rcon_iteration = 1

    while current_size < expanded_key_columns:
        t = expanded_key[-4:]

        if current_size % key_columns == 0:
            t = sub_bytes(t[1:] + t[:1])
            t = bytearray(t)
            t[0] ^= rcon[rcon_iteration]
            t = bytes(t)
            rcon_iteration += 1

        expanded_key += xor_bytes(t, expanded_key[-key_size:])
        current_size += 1

    return expanded_key


class AES_Cipher:
    def __init__(self, key):
        """Initialize AES cipher with the given key."""
        self.key = sha256(key.encode()).digest()[:16]  # Hash key to 128 bits
        self.expanded_key = expand_key(self.key)

    def encrypt_block(self, plaintext):
        state = plaintext
        state = add_round_key(state, self.expanded_key[:16])

        for i in range(1, 10):
            state = sub_bytes(state)
            state = shift_rows(state)
            state = mix_columns(state)
            state = add_round_key(state, self.expanded_key[i * 16 : (i + 1) * 16])

        state = sub_bytes(state)
        state = shift_rows(state)
        state = add_round_key(state, self.expanded_key[160:])
        return state

    def decrypt_block(self, ciphertext):
        state = ciphertext
        state = add_round_key(state, self.expanded_key[160:])
        state = inv_shift_rows(state)
        state = inv_sub_bytes(state)

        for i in range(9, 0, -1):
            state = add_round_key(state, self.expanded_key[i * 16 : (i + 1) * 16])
            state = inv_mix_columns(state)
            state = inv_shift_rows(state)
            state = inv_sub_bytes(state)

        state = add_round_key(state, self.expanded_key[:16])
        return state

    def encrypt(self, plaintext):
        """Encrypt using AES-CBC mode with padding."""
        iv = os.urandom(16)  # Generate a random IV
        plaintext = pad(plaintext.encode(), 16)
        ciphertext = b""

        previous_block = iv
        for i in range(0, len(plaintext), 16):
            block = plaintext[i : i + 16]
            block = xor_bytes(block, previous_block)
            encrypted_block = self.encrypt_block(block)
            ciphertext += encrypted_block
            previous_block = encrypted_block

        return base64.b64encode(iv + ciphertext).decode()

    def decrypt(self, ciphertext):
        """Decrypt AES-CBC encrypted data."""
        ciphertext = base64.b64decode(ciphertext)
        iv = ciphertext[:16]
        ciphertext = ciphertext[16:]
        plaintext = b""

        previous_block = iv
        for i in range(0, len(ciphertext), 16):
            block = ciphertext[i : i + 16]
            decrypted_block = self.decrypt_block(block)
            plaintext_block = xor_bytes(decrypted_block, previous_block)
            plaintext += plaintext_block
            previous_block = block

        return unpad(plaintext).decode()


def pad(data, block_size):
    padding_len = block_size - len(data) % block_size
    padding = bytes([padding_len] * padding_len)
    return data + padding


def unpad(data):
    padding_len = data[-1]
    return data[:-padding_len]


def inv_sub_bytes(state):
    inv_s_box = [s_box.index(x) for x in range(256)]
    return bytes(inv_s_box[b] for b in state)


def inv_shift_rows(state):
    return bytes(
        [
            state[0],
            state[13],
            state[10],
            state[7],
            state[4],
            state[1],
            state[14],
            state[11],
            state[8],
            state[5],
            state[2],
            state[15],
            state[12],
            state[9],
            state[6],
            state[3],
        ]
    )


def inv_mix_columns(state):
    def xtime(a):
        return (((a << 1) ^ 0x1B) & 0xFF) if (a & 0x80) else (a << 1)

    def inv_mix_single_column(a):
        u = xtime(xtime(a[0] ^ a[2]))
        v = xtime(xtime(a[1] ^ a[3]))
        a[0] ^= u
        a[1] ^= v
        a[2] ^= u
        a[3] ^= v

        t = a[0] ^ a[1] ^ a[2] ^ a[3]
        u = a[0]
        a[0] ^= t ^ xtime(a[0] ^ a[1])
        a[1] ^= t ^ xtime(a[1] ^ a[2])
        a[2] ^= t ^ xtime(a[2] ^ a[3])
        a[3] ^= t ^ xtime(a[3] ^ u)
        return a

    state = bytearray(state)
    for i in range(4):
        column = state[i::4]
        state[i::4] = inv_mix_single_column(column)
    return bytes(state)
