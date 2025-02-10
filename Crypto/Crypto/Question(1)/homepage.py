import tkinter as tk
from tkinter import ttk
import subprocess
import os
import sys

# Function to open encryption.py and restart homepage.py after closing it
def open_encryption():
    root.destroy()  # Close homepage
    file_path = os.path.join("Question(1)", "encryption.py")
    if os.path.exists(file_path):
        subprocess.run([sys.executable, file_path])  # Wait for encryption.py to finish
    subprocess.run([sys.executable, os.path.abspath(__file__)])  # Restart homepage.py

# Function to open decryption.py and restart homepage.py after closing it
def open_decryption():
    root.destroy()  # Close homepage
    file_path = os.path.join("Question(1)", "decryption.py")
    if os.path.exists(file_path):
        subprocess.run([sys.executable, file_path])  # Wait for decryption.py to finish
    subprocess.run([sys.executable, os.path.abspath(__file__)])  # Restart homepage.py

# Create the main window
root = tk.Tk()
root.title("Encryption & Decryption")
root.geometry("500x300")
root.configure(bg="#2C3E50")  # Dark blue-gray background

# Style configuration
style = ttk.Style()
style.configure("TButton", font=("Arial", 12, "bold"), padding=10, borderwidth=3)
style.map("TButton", background=[("active", "#2980B9")])

# Heading Label
label = tk.Label(root, text="Choose an Option", font=("Arial", 16, "bold"), fg="white", bg="#2C3E50")
label.pack(pady=20)

# Encrypt Button
encrypt_button = ttk.Button(root, text="Encrypt", command=open_encryption, style="TButton")
encrypt_button.pack(pady=10, ipadx=20)

# Decrypt Button
decrypt_button = ttk.Button(root, text="Decrypt", command=open_decryption, style="TButton")
decrypt_button.pack(pady=10, ipadx=20)

# Footer Label
footer = tk.Label(root, text="Secure Your Data", font=("Arial", 10, "italic"), fg="white", bg="#2C3E50")
footer.pack(side="bottom", pady=10)

# Run the application
root.mainloop()
