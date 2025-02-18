import base64
import os
from hashlib import sha256
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad


class AES_Cipher:
    def __init__(self, key):
        """Initialize AES cipher with the given key."""
        self.key = sha256(key.encode()).digest()  # Hash key to 256 bits

    def encrypt(self, plaintext):
        """Encrypt using AES-CBC mode with padding."""
        iv = os.urandom(16)  # Generate a random IV
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        padded_plaintext = pad(plaintext.encode(), AES.block_size)
        ciphertext = cipher.encrypt(padded_plaintext)
        return base64.b64encode(iv + ciphertext).decode()  # IV is prepended

    def decrypt(self, ciphertext):
        """Decrypt AES-CBC encrypted data."""
        raw_data = base64.b64decode(ciphertext)
        iv, encrypted_msg = raw_data[:16], raw_data[16:]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        decrypted_data = unpad(cipher.decrypt(encrypted_msg), AES.block_size)
        return decrypted_data.decode()
