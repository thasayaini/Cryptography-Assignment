import tkinter as tk
from tkinter import scrolledtext, messagebox
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import base64

class CryptoApp:
    def __init__(self, root):
        # Initialize the main application window
        self.root = root
        self.root.title("Hybrid Cryptosystem (RSA + AES)")
        self.root.geometry("800x500")
        self.root.configure(bg="#2c3e50")

        # Initialize tampered flag to False
        self.tampered = False

        # Create main frame
        main_frame = tk.Frame(root, bg="#2c3e50")
        main_frame.pack(fill="both", expand=True)

        # Left Panel for RSA Key Exchange
        left_frame = tk.Frame(main_frame, bg="#34495e", padx=10, pady=10)
        left_frame.pack(side="left", fill="both", expand=True, padx=10, pady=10)

        tk.Label(left_frame, text="RSA Key Exchange", font=("Arial", 12, "bold"), fg="white", bg="#34495e").pack(pady=5)

        self.btn_generate_keys = tk.Button(left_frame, text="Generate RSA Keys & Exchange AES Key", command=self.generate_rsa_keys, bg="#27ae60", fg="white", font=("Arial", 10, "bold"))
        self.btn_generate_keys.pack(pady=10)

        self.rsa_text = scrolledtext.ScrolledText(left_frame, height=20, width=50, bg="#ecf0f1")
        self.rsa_text.pack()

        # Right Panel for AES Encryption/Decryption
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

        self.btn_decrypt = tk.Button(right_frame, text="Decrypt", command=self.decrypt_message, bg="#e74c3c", fg="white", font=("Arial", 10, "bold"))
        self.btn_decrypt.pack(pady=6)

        tk.Label(right_frame, text="Decrypted Text:", bg="#34495e", fg="white").pack()
        self.decrypted_text = tk.Entry(right_frame, width=50, font=("Arial", 10))
        self.decrypted_text.pack(pady=6)

        # Button to tamper with the encrypted data
        self.btn_tamper = tk.Button(right_frame, text="Tamper Encrypted Data", command=self.tamper_encrypted_data, bg="#f39c12", fg="white", font=("Arial", 10, "bold"))
        self.btn_tamper.pack(pady=6)

    def generate_rsa_keys(self):
        self.rsa_text.delete("1.0", tk.END)
        self.rsa_text.insert(tk.END, "Generating RSA key pairs...\n")

        self.private_key_A, self.public_key_A = self.create_rsa_keys()
        self.private_key_B, self.public_key_B = self.create_rsa_keys()

        self.rsa_text.insert(tk.END, "User A Private Key:\n" + self.private_key_A.decode()[:200] + "...\n\n")
        self.rsa_text.insert(tk.END, "User A Public Key:\n" + self.public_key_A.decode()[:200] + "...\n\n")

        self.rsa_text.insert(tk.END, "User B Private Key:\n" + self.private_key_B.decode()[:200] + "...\n\n")
        self.rsa_text.insert(tk.END, "User B Public Key:\n" + self.public_key_B.decode()[:200] + "...\n\n")

        self.aes_key = get_random_bytes(32)
        self.rsa_text.insert(tk.END, "Generated AES Key: " + base64.b64encode(self.aes_key).decode() + "\n\n")

        encrypted_aes_key = self.encrypt_aes_key(self.aes_key, self.public_key_B)
        self.rsa_text.insert(tk.END, "Encrypting AES Key with User B's Public Key...\n")
        self.rsa_text.insert(tk.END, "Encrypted AES Key: " + base64.b64encode(encrypted_aes_key).decode() + "\n\n")

        decrypted_aes_key = self.decrypt_aes_key(encrypted_aes_key, self.private_key_B)
        self.rsa_text.insert(tk.END, "User B Decrypts AES Key using Private Key...\n")
        self.rsa_text.insert(tk.END, "Decrypted AES Key: " + base64.b64encode(decrypted_aes_key).decode() + "\n")

    def create_rsa_keys(self):
        key = RSA.generate(2048)
        return key.export_key(), key.publickey().export_key()

    def encrypt_aes_key(self, aes_key, public_key):
        rsa_key = RSA.import_key(public_key)
        cipher_rsa = PKCS1_OAEP.new(rsa_key)
        return cipher_rsa.encrypt(aes_key)

    def decrypt_aes_key(self, encrypted_aes_key, private_key):
        rsa_key = RSA.import_key(private_key)
        cipher_rsa = PKCS1_OAEP.new(rsa_key)
        return cipher_rsa.decrypt(encrypted_aes_key)

    def encrypt_message(self):
        plaintext = self.input_message.get().strip()
        if not plaintext:
            messagebox.showerror("Error", "Enter a message!")
            return

        cipher = AES.new(self.aes_key, AES.MODE_CBC)
        ciphertext = cipher.iv + cipher.encrypt(pad(plaintext.encode(), AES.block_size))

        self.encrypted_text.delete(0, tk.END)
        self.encrypted_text.insert(0, base64.b64encode(ciphertext).decode())

        # Reset tampering flag & re-enable tamper button
        self.tampered = False
        self.btn_tamper.config(state=tk.NORMAL)  # Re-enable tamper button

    def decrypt_message(self):
        encrypted_text = self.encrypted_text.get().strip()
        if not encrypted_text:
            messagebox.showerror("Error", "No encrypted message found!")
            return
        try:
            ciphertext = base64.b64decode(encrypted_text)
            iv = ciphertext[:AES.block_size]
            cipher = AES.new(self.aes_key, AES.MODE_CBC, iv)
            decrypted_text = unpad(cipher.decrypt(ciphertext[AES.block_size:]), AES.block_size).decode()
            self.decrypted_text.delete(0, tk.END)
            self.decrypted_text.insert(0, decrypted_text)
        except Exception:
            # If decryption fails, try to display the raw decrypted bytes (garbled text)
            try:
                ciphertext = base64.b64decode(encrypted_text)
                iv = ciphertext[:AES.block_size]
                cipher = AES.new(self.aes_key, AES.MODE_CBC, iv)
                raw_decrypted_bytes = cipher.decrypt(ciphertext[AES.block_size:])
                garbled_text = raw_decrypted_bytes.decode('latin-1')  # Use 'latin-1' to avoid UnicodeDecodeError
                self.decrypted_text.delete(0, tk.END)
                self.decrypted_text.insert(0, garbled_text)
            except Exception:
                messagebox.showerror("Decryption Error", "Failed to decrypt the message.")

    def tamper_encrypted_data(self):
        encrypted_text = self.encrypted_text.get().strip()
        if not encrypted_text:
            return  # Do nothing if no encrypted text is found

        try:
            ciphertext = bytearray(base64.b64decode(encrypted_text))
            if len(ciphertext) > AES.block_size:
                ciphertext[len(ciphertext) // 2] ^= 0xFF  # Flip a random byte in the middle
            
            tampered_text = base64.b64encode(ciphertext).decode()
            
            self.encrypted_text.delete(0, tk.END)
            self.encrypted_text.insert(0, tampered_text)
            
            # Prevent further tampering
            self.tampered = True  # Set flag to prevent multiple tamper actions
            self.btn_tamper.config(state=tk.DISABLED)  # Disable button after first tamper
        except Exception:
            pass  # Ignore errors silently


if __name__ == "__main__":
    root = tk.Tk()
    app = CryptoApp(root)
    root.mainloop()