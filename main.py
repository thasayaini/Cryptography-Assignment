import tkinter as tk
from tkinter import messagebox
import subprocess
import os
import sys


class CryptoHomepage:
    def __init__(self, root):
        self.root = root
        self.root.title("Cryptography Techniques")
        self.root.geometry("600x400")
        self.root.configure(bg="#1e272e")

        # Title Label with Styling
        title_label = tk.Label(
            root,
            text="🔐 Cryptography Techniques 🔐",
            font=("Arial", 20, "bold"),
            fg="white",
            bg="#1e272e",
            pady=10,
        )
        title_label.pack(pady=20)

        # Buttons with Modern Styling
        self.create_button(
            "Classical Symmetric Ciphers", self.open_classical_cipher, "#ff793f"
        ).pack(pady=15)
        self.create_button(
            "Hybrid Modern Cipher", self.open_hybrid_cipher, "#2ecc71"
        ).pack(pady=15)

    def create_button(self, text, command, color):
        """Creates a styled button."""
        return tk.Button(
            self.root,
            text=text,
            command=command,
            font=("Arial", 14, "bold"),
            fg="white",
            bg=color,
            activebackground="#ffdd59",
            width=30,
            height=2,
            relief="flat",
            cursor="hand2",
            bd=5,
            highlightthickness=3,
            highlightbackground="white",
        )

    def open_classical_cipher(self):
        """Opens the Classical Symmetric Ciphers page."""
        self.navigate_to_script("Question(1)", "homepageQ1.py")

    def open_hybrid_cipher(self):
        """Opens the Hybrid Modern Cipher page."""
        self.navigate_to_script("Question(2)", "homepageQ2.py")

    def navigate_to_script(self, folder, filename):
        """Closes homepage.py, runs the target script, and reopens homepage.py after closing."""
        script_dir = os.path.dirname(
            os.path.abspath(__file__)
        )  # Get current script directory
        file_path = os.path.join(
            script_dir, folder, filename
        )  # Construct absolute path

        if os.path.exists(file_path):
            self.root.withdraw()  # Hide homepage window
            subprocess.run(["python", file_path], check=True)  # Run the target script
            self.root.deiconify()  # Show homepage again after script closes
        else:
            messagebox.showerror("Error", f"File not found:\n{file_path}")


if __name__ == "__main__":
    root = tk.Tk()
    app = CryptoHomepage(root)
    root.mainloop()
