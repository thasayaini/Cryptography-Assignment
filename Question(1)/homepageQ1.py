import tkinter as tk
from tkinter import ttk, messagebox
import subprocess
import sys
from pathlib import Path

# Define base directory (already inside Question(1))
BASE_DIR = Path(__file__).resolve().parent


def open_script(script_name):
    """Runs a script and returns to homepage after execution."""
    script_path = BASE_DIR / script_name  # No extra subfolder needed

    if not script_path.exists():
        messagebox.showerror("Error", f"File not found:\n{script_path}")
        return

    root.withdraw()  # Hide homepage

    try:
        subprocess.run([sys.executable, str(script_path)], check=True)  # Run script
    except subprocess.CalledProcessError as e:
        messagebox.showerror("Execution Error", f"Error running {script_name}:\n{e}")
    except Exception as e:
        messagebox.showerror("Unexpected Error", f"An error occurred:\n{e}")

    root.deiconify()  # Show homepage again


# Create main window
root = tk.Tk()
root.title("Encryption & Decryption")
root.geometry("500x300")
root.configure(bg="#2C3E50")  # Dark blue-gray background

# Configure button style
style = ttk.Style()
style.configure("TButton", font=("Arial", 12, "bold"), padding=10, borderwidth=3)
style.map("TButton", background=[("active", "#2980B9")])

# Title label
title_label = tk.Label(
    root,
    text="🔐 Choose an Option 🔐",
    font=("Arial", 16, "bold"),
    fg="white",
    bg="#2C3E50",
)
title_label.pack(pady=20)

# Encrypt & Decrypt Buttons
ttk.Button(
    root, text="Encrypt", command=lambda: open_script("encryption.py"), style="TButton"
).pack(pady=10, ipadx=20)
ttk.Button(
    root, text="Decrypt", command=lambda: open_script("decryption.py"), style="TButton"
).pack(pady=10, ipadx=20)

# Footer label
footer = tk.Label(
    root,
    text="Secure Your Data",
    font=("Arial", 10, "italic"),
    fg="white",
    bg="#2C3E50",
)
footer.pack(side="bottom", pady=10)

# Run application
root.mainloop()
