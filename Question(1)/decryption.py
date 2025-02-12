import tkinter as tk
from tkinter import messagebox
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

def playfair_decrypt(ciphertext, key):
    if len(ciphertext) % 2 != 0:  # Ensure even length
        ciphertext += 'X'  # Assuming 'X' was used for padding during encryption

    matrix = generate_playfair_matrix(key)
    plaintext = ""

    for i in range(0, len(ciphertext), 2):
        a, b = ciphertext[i], ciphertext[i + 1]
        row1, col1 = find_position(matrix, a)
        row2, col2 = find_position(matrix, b)

        if row1 == row2:
            plaintext += matrix[row1, (col1 - 1) % 5] + matrix[row2, (col2 - 1) % 5]
        elif col1 == col2:
            plaintext += matrix[(row1 - 1) % 5, col1] + matrix[(row2 - 1) % 5, col2]
        else:
            plaintext += matrix[row1, col2] + matrix[row2, col1]

    return plaintext

# Rail Fence Cipher Functions
def rail_fence_decrypt(ciphertext, depth):
    rail_length = [0] * depth
    row, step = 0, 1

    for _ in ciphertext:
        rail_length[row] += 1
        row += step
        if row == depth - 1 or row == 0:
            step *= -1

    rails = []
    index = 0
    for length in rail_length:
        rails.append(ciphertext[index:index + length])
        index += length

    plaintext = ''
    row, step = 0, 1
    rail_pointers = [0] * depth

    for _ in ciphertext:
        plaintext += rails[row][rail_pointers[row]]
        rail_pointers[row] += 1
        row += step
        if row == depth - 1 or row == 0:
            step *= -1

    return plaintext

# Decryption Order: Rail Fence → Playfair
def product_cipher_decrypt(ciphertext, key, depth):
    rail_fence_text = rail_fence_decrypt(ciphertext, depth)  # Step 1: Rail Fence Decrypt
    if len(rail_fence_text) % 2 != 0:
        rail_fence_text += 'X'  # Ensure even length for Playfair

    decrypted_text = playfair_decrypt(rail_fence_text, key)  # Step 2: Playfair Decrypt
    return rail_fence_text, decrypted_text

# Function to Decrypt and Display the Result
def decrypt_text():
    ciphertext = entry_ciphertext.get().upper().replace(" ", "")
    key = entry_key.get().upper().replace(" ", "")
    
    try:
        depth = int(entry_depth.get())
        if depth < 2:
            messagebox.showerror("Error", "Rail Fence depth must be at least 2")
            return
    except ValueError:
        messagebox.showerror("Error", "Depth must be a number")
        return

    if not ciphertext or not key:
        messagebox.showerror("Error", "All fields must be filled!")
        return

    start_time = time.perf_counter()
    rail_fence_text, decrypted_text = product_cipher_decrypt(ciphertext, key, depth)
    end_time = time.perf_counter()
    elapsed_time = end_time - start_time

    playfair_label.config(text=f"🔹 Rail Fence Output: {rail_fence_text}")
    result_label.config(text=f"🔓 Final Decrypted Text: {decrypted_text}")
    time_label.config(text=f"⏱ Decryption Time: {elapsed_time:.10f} seconds")

# GUI Setup
root = tk.Tk()
root.title("🔓 Product Cipher Decryption")
root.geometry("800x450")
root.configure(bg="#2C3E50")

# Heading Label
title_label = tk.Label(root, text="🔓 Product Cipher Decryption", font=("Arial", 18, "bold"), fg="white", bg="#2C3E50")
title_label.pack(pady=10)

# Frame for input fields
frame = tk.Frame(root, bg="#34495E", padx=0, pady=20)
frame.pack(pady=10)

# Entry Styles
entry_style = {"font": ("Arial", 12), "bg": "#ECF0F1", "bd": 2, "relief": "solid", "width": 50}  # Increased width

# Labels and Entry Fields
tk.Label(frame, text="Enter Ciphertext:", font=("Arial", 12, "bold"), fg="white", bg="#34495E").grid(row=0, column=0, sticky="w")
entry_ciphertext = tk.Entry(frame, **entry_style)
entry_ciphertext.grid(row=0, column=1, pady=5, padx=10)

tk.Label(frame, text="Enter Playfair Key:", font=("Arial", 12, "bold"), fg="white", bg="#34495E").grid(row=1, column=0, sticky="w")
entry_key = tk.Entry(frame, **entry_style)
entry_key.grid(row=1, column=1, pady=5, padx=10)

tk.Label(frame, text="Enter Rail Fence Depth:", font=("Arial", 12, "bold"), fg="white", bg="#34495E").grid(row=2, column=0, sticky="w")
entry_depth = tk.Entry(frame, **entry_style)
entry_depth.grid(row=2, column=1, pady=5, padx=10)

# Decrypt Button with hover effect
def on_enter(e):
    decrypt_button.config(bg="#E74C3C", fg="black")

def on_leave(e):
    decrypt_button.config(bg="#C0392B", fg="white")

decrypt_button = tk.Button(root, text="🔓 Decrypt", font=("Arial", 12, "bold"), bg="#C0392B", fg="white", command=decrypt_text)
decrypt_button.pack(pady=10)
decrypt_button.bind("<Enter>", on_enter)
decrypt_button.bind("<Leave>", on_leave)

# Result Labels
playfair_label = tk.Label(root, text="", bg="#2C3E50", fg="white", font=("Arial", 12, "bold"))
playfair_label.pack(pady=5)

result_label = tk.Label(root, text="", bg="#2C3E50", fg="white", font=("Arial", 12, "bold"))
result_label.pack(pady=5)

time_label = tk.Label(root, text="", bg="#2C3E50", fg="white", font=("Arial", 12))
time_label.pack(pady=5)

# Run the Application
root.mainloop()
