import base64
import random
import tkinter as tk
from tkinter import scrolledtext
from rsa_key_generator import RSA
from key_exchange import KeyExchange
from aes_cipher import AES_Cipher
from Crypto.Cipher import AES

class CryptoApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Hybrid Cryptosystem (RSA + AES)")
        self.root.geometry("800x500")
        self.root.configure(bg="#2c3e50")

        main_frame = tk.Frame(root, bg="#2c3e50")
        main_frame.pack(fill="both", expand=True)

        # Left Panel (RSA Key Exchange)
        left_frame = tk.Frame(main_frame, bg="#34495e", padx=10, pady=10)
        left_frame.pack(side="left", fill="both", expand=True, padx=10, pady=10)

        tk.Label(left_frame, text="RSA Key Exchange", font=("Arial", 12, "bold"), fg="white", bg="#34495e").pack(pady=5)

        self.btn_generate_keys = tk.Button(left_frame, text="Generate RSA Keys & Exchange AES Key", command=self.generate_rsa_keys, bg="#27ae60", fg="white", font=("Arial", 10, "bold"))
        self.btn_generate_keys.pack(pady=10)

        self.rsa_text = scrolledtext.ScrolledText(left_frame, height=20, width=50, bg="#ecf0f1")
        self.rsa_text.pack()

        # Right Panel (AES Encryption/Decryption)
        right_frame = tk.Frame(main_frame, bg="#34495e", padx=10, pady=10)
        right_frame.pack(side="right", fill="both", expand=True, padx=10, pady=10)

        tk.Label(right_frame, text="AES Encryption & Decryption", font=("Arial", 12, "bold"), fg="white", bg="#34495e").pack(pady=5)

        tk.Label(right_frame, text="Enter Message:", bg="#34495e", fg="white").pack()
        self.input_message = tk.Entry(right_frame, width=50, font=("Arial", 10))
        self.input_message.pack(pady=6)

        self.btn_encrypt = tk.Button(right_frame, text="Encrypt", command=self.encrypt_message, bg="#2980b9", fg="white", font=("Arial", 10, "bold"))
        self.btn_encrypt.pack(pady=6)

        tk.Label(right_frame, text="Encrypted Text:", bg="#34495e", fg="white").pack()
        self.encrypted_text = tk.Entry(right_frame, width=50, font=("Arial", 10))
        self.encrypted_text.pack(pady=6)

        self.btn_tamper = tk.Button(right_frame, text="Tamper Encrypted Data", command=self.tamper_encrypted_data, bg="#f39c12", fg="white", font=("Arial", 10, "bold"))
        self.btn_tamper.pack(pady=6)

        self.btn_decrypt = tk.Button(right_frame, text="Decrypt", command=self.decrypt_message, bg="#e74c3c", fg="white", font=("Arial", 10, "bold"))
        self.btn_decrypt.pack(pady=6)

        tk.Label(right_frame, text="Decrypted Text:", bg="#34495e", fg="white").pack()
        self.decrypted_text = tk.Entry(right_frame, width=50, font=("Arial", 10))
        self.decrypted_text.pack(pady=6)

    def generate_rsa_keys(self):
        self.rsa_text.delete("1.0", tk.END)
        self.rsa_text.insert(tk.END, "Generating RSA key pairs...\n")

        self.rsa_A = RSA()
        self.rsa_B = RSA()

        self.rsa_text.insert(tk.END, "Person A (RSA_A) Keys:\n")
        self.rsa_text.insert(tk.END, f"Public Key (e, n): ({self.rsa_A.e}, {self.rsa_A.n})\n") 
        self.rsa_text.insert(tk.END, f"Private Key (d, n): ({self.rsa_A.d}, {self.rsa_A.n})\n\n")

        self.rsa_text.insert(tk.END, "Person B (RSA_B) Keys:\n")
        self.rsa_text.insert(tk.END, f"Public Key (e, n): ({self.rsa_B.e}, {self.rsa_B.n})\n")
        self.rsa_text.insert(tk.END, f"Private Key (d, n): ({self.rsa_B.d}, {self.rsa_B.n})\n\n")

        self.key_exchange = KeyExchange(self.rsa_A, self.rsa_B)
        self.aes_key, encrypted_aes_key, decrypted_aes_key = self.key_exchange.generate_and_exchange_aes_key()

        self.aes_cipher = AES_Cipher(decrypted_aes_key.hex())

        self.rsa_text.insert(tk.END, f"Generated AES Key (Random): {self.aes_key.hex()}\n")
        self.rsa_text.insert(tk.END, f"Encrypted AES Key (Sent to B): {encrypted_aes_key}\n")
        self.rsa_text.insert(tk.END, f"Decrypted AES Key (By B): {decrypted_aes_key.hex()}\n")

    def encrypt_message(self):
        plaintext = self.input_message.get().strip()
        if plaintext:
            ciphertext = self.aes_cipher.encrypt(plaintext)
            self.encrypted_text.delete(0, tk.END)
            self.encrypted_text.insert(0, ciphertext)

    def tamper_encrypted_data(self):
        """Tamper with the encrypted data by flipping a few bits."""
        encrypted_data = self.encrypted_text.get().strip()
        if encrypted_data:
            # Convert the encrypted data to a byte array
            encrypted_bytes = bytearray(base64.b64decode(encrypted_data))
            # Flip a few random bits
            for _ in range(random.randint(1, 5)):  # Flip 1 to 5 bits
                byte_index = random.randint(0, len(encrypted_bytes) - 1)
                bit_index = random.randint(0, 7)
                encrypted_bytes[byte_index] ^= (1 << bit_index)
            # Update the encrypted text field
            tampered_data = base64.b64encode(encrypted_bytes).decode()
            self.encrypted_text.delete(0, tk.END)
            self.encrypted_text.insert(0, tampered_data)

    def decrypt_message(self):
     encrypted_text = self.encrypted_text.get().strip()
     if encrypted_text:
        try:
            decrypted_text = self.aes_cipher.decrypt(encrypted_text)
            self.decrypted_text.delete(0, tk.END)
            self.decrypted_text.insert(0, decrypted_text)
        except Exception as e:
            try:
                # Attempt to recover as much data as possible
                raw_data = base64.b64decode(encrypted_text)
                iv, encrypted_msg = raw_data[:16], raw_data[16:]
                cipher = AES.new(self.aes_cipher.key, AES.MODE_CBC, iv)
                decrypted_data = cipher.decrypt(encrypted_msg)
                
                # Attempt to decode, replacing undecodable characters with placeholders
                garbled_text = decrypted_data.decode(errors="replace")  
                self.decrypted_text.delete(0, tk.END)
                self.decrypted_text.insert(0, garbled_text)
            except Exception as e:
                # If all attempts fail, show corrupted text as best as possible
                self.decrypted_text.delete(0, tk.END)
                self.decrypted_text.insert(0, decrypted_data.hex() if 'decrypted_data' in locals() else "Decryption Failed")
