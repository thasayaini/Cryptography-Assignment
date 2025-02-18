import tkinter as tk
from tkinter import  messagebox
import numpy as np
import time

# Playfair Cipher Functions
def generate_playfair_matrix(key):
    key = key.replace("J", "I").upper()
    matrix = []
    seen = set()

    for char in key + "ABCDEFGHIKLMNOPQRSTUVWXYZ":
        if char not in seen:
            seen.add(char)
            matrix.append(char)

    return np.array(matrix).reshape(5, 5)

def find_position(matrix, char):
    idx = np.where(matrix == char)
    return idx[0][0], idx[1][0]

def prepare_playfair_text(plaintext):
    plaintext = plaintext.replace("J", "I").upper().replace(" ", "")
    pairs = []
    i = 0
    while i < len(plaintext):
        if i == len(plaintext) - 1:
            pairs.append(plaintext[i] + "X")
            break
        if plaintext[i] == plaintext[i + 1]:
            pairs.append(plaintext[i] + "X")
            i += 1
        else:
            pairs.append(plaintext[i] + plaintext[i + 1])
            i += 2
    return pairs

def playfair_encrypt(plaintext, key):
    matrix = generate_playfair_matrix(key)
    pairs = prepare_playfair_text(plaintext)
    ciphertext = ""

    for a, b in pairs:
        row1, col1 = find_position(matrix, a)
        row2, col2 = find_position(matrix, b)

        if row1 == row2:
            ciphertext += matrix[row1, (col1 + 1) % 5] + matrix[row2, (col2 + 1) % 5]
        elif col1 == col2:
            ciphertext += matrix[(row1 + 1) % 5, col1] + matrix[(row2 + 1) % 5, col2]
        else:
            ciphertext += matrix[row1, col2] + matrix[row2, col1]

    return ciphertext

# Rail Fence Cipher Functions
def rail_fence_encrypt(plaintext, depth):
    rails = [''] * depth
    row, step = 0, 1

    for char in plaintext:
        rails[row] += char
        row += step
        if row == depth - 1 or row == 0:
            step *= -1

    return ''.join(rails)

# Function to Encrypt and Display the Result
def encrypt_text():
    plaintext = entry_plaintext.get().upper().replace(" ", "")
    key = entry_key.get().upper().replace(" ", "")
    try:
        depth = int(entry_depth.get())
        if depth < 2:
            messagebox.showerror("Error", "Rail Fence depth must be at least 2")
            return
    except ValueError:
        messagebox.showerror("Error", "Depth must be a number")
        return

    start_time = time.perf_counter()
    playfair_text = playfair_encrypt(plaintext, key)
    rail_fence_text = rail_fence_encrypt(playfair_text, depth)
    end_time = time.perf_counter()
    elapsed_time = end_time - start_time

    playfair_label.config(text=f"🔹 Playfair Output: {playfair_text}")
    result_label.config(text=f"🔒 Final Encrypted Text: {rail_fence_text}")
    time_label.config(text=f"⏱ Encryption Time: {elapsed_time:.10f} seconds")

# GUI Setup
root = tk.Tk()
root.title("🔐 Product Cipher Encryption")
root.geometry("800x450")
root.configure(bg="#2C3E50")

# Heading Label
title_label = tk.Label(root, text="🔐 Product Cipher Encryption", font=("Arial", 18, "bold"), fg="white", bg="#2C3E50")
title_label.pack(pady=10)

# Frame for input fields
frame = tk.Frame(root, bg="#34495E", padx=0, pady=20)
frame.pack(pady=10)

# Entry Styles
entry_style = {"font": ("Arial", 12), "bg": "#ECF0F1", "bd": 2, "relief": "solid", "width": 50}  # Increased width

# Labels and Entry Fields
tk.Label(frame, text="Enter Plaintext:", font=("Arial", 12, "bold"), fg="white", bg="#34495E").grid(row=0, column=0, sticky="w")
entry_plaintext = tk.Entry(frame, **entry_style)
entry_plaintext.grid(row=0, column=1, pady=5, padx=10)

tk.Label(frame, text="Enter Playfair Key:", font=("Arial", 12, "bold"), fg="white", bg="#34495E").grid(row=1, column=0, sticky="w")
entry_key = tk.Entry(frame, **entry_style)
entry_key.grid(row=1, column=1, pady=5, padx=10)

tk.Label(frame, text="Enter Rail Fence Depth:", font=("Arial", 12, "bold"), fg="white", bg="#34495E").grid(row=2, column=0, sticky="w")
entry_depth = tk.Entry(frame, **entry_style)
entry_depth.grid(row=2, column=1, pady=5, padx=10)


# Encrypt Button with hover effect
def on_enter(e):
    encrypt_button.config(bg="#1ABC9C", fg="black")

def on_leave(e):
    encrypt_button.config(bg="#16A085", fg="white")

encrypt_button = tk.Button(root, text="🔒 Encrypt", font=("Arial", 14, "bold"), bg="#16A085", fg="white", width=20, command=encrypt_text, relief="raised", bd=3)
encrypt_button.pack(pady=15)
encrypt_button.bind("<Enter>", on_enter)
encrypt_button.bind("<Leave>", on_leave)

# Result Labels
playfair_label = tk.Label(root, text="", bg="#2C3E50", fg="white", font=("Arial", 12, "italic"))
playfair_label.pack(pady=5)

result_label = tk.Label(root, text="", bg="#2C3E50", fg="lightgreen", font=("Arial", 12, "bold"))
result_label.pack(pady=5)

time_label = tk.Label(root, text="", bg="#2C3E50", fg="white", font=("Arial", 12, "italic"))
time_label.pack(pady=5)

# Footer Label
footer_label = tk.Label(root, text="🔹 Secure Your Data with Encryption 🔹", font=("Arial", 10, "bold"), fg="white", bg="#2C3E50")
footer_label.pack(pady=10)

# Run the Application
root.mainloop()
