import tkinter as tk
from tkinter import messagebox
import subprocess
import os

class CryptoHomepage:
    def __init__(self, root):
        self.root = root
        self.root.title("Cryptography Techniques")
        self.root.geometry("600x400")
        self.root.configure(bg="#1e272e")

        # Title Label with Styling
        title_label = tk.Label(root, text="🔐 Cryptography Techniques 🔐", font=("Arial", 20, "bold"), 
                               fg="white", bg="#1e272e", pady=10)
        title_label.pack(pady=20)

        # Buttons with Modern Styling
        self.create_button("Classical Symmetric Ciphers", self.open_classical_cipher, "#ff793f").pack(pady=15)
        self.create_button("Hybrid Modern Cipher", self.open_hybrid_cipher, "#2ecc71").pack(pady=15)

    def create_button(self, text, command, color):
        return tk.Button(self.root, text=text, command=command, font=("Arial", 14, "bold"), 
                         fg="white", bg=color, activebackground="#ffdd59", width=30, height=2, 
                         relief="flat", cursor="hand2", bd=5, highlightthickness=3, highlightbackground="white")

    def open_classical_cipher(self):
        file_path = os.path.join("Question(1)", "homepageQ1.py")
        self.navigate_to_script(file_path)

    def open_hybrid_cipher(self):
        file_path = os.path.join("Question(2)", "homepageQ2.py")
        self.navigate_to_script(file_path)

    def navigate_to_script(self, file_path):
        """ Closes homepage.py, runs the target script, and reopens homepage.py after closing. """
        if os.path.exists(file_path):
            self.root.withdraw()  # Hide the homepage
            subprocess.Popen(["python", file_path]).wait()  # Wait for the script to close
            self.root.deiconify()  # Show homepage again
        else:
            messagebox.showerror("Error", f"File not found: {file_path}")

if __name__ == "__main__":
    root = tk.Tk()
    app = CryptoHomepage(root)
    root.mainloop()
