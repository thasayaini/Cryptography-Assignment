import os

class KeyExchange:
    def __init__(self, rsa_A, rsa_B):
        self.rsa_A = rsa_A
        self.rsa_B = rsa_B

    def generate_and_exchange_aes_key(self):
        self.aes_key = os.urandom(32)  # Generate a 32-byte (256-bit) random AES key
        encrypted_aes_key = self.rsa_B.encrypt(int.from_bytes(self.aes_key, 'big'))
        decrypted_aes_key = self.rsa_B.decrypt(encrypted_aes_key).to_bytes(len(self.aes_key), 'big')
        return self.aes_key, encrypted_aes_key, decrypted_aes_key