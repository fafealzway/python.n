import tkinter as tk
from tkinter import messagebox, PhotoImage
from cryptography.fernet import Fernet

# Generate a key for encryption
key = Fernet.generate_key()
cipher = Fernet(key)

# Function to encrypt the message
def encrypt_message():
    message = entry_message.get()
    if message:
        encrypted = cipher.encrypt(message.encode())
        entry_encrypted.delete(0, tk.END)
        entry_encrypted.insert(0, encrypted.decode())
    else:
        messagebox.showerror("Error", "Please enter a message to encrypt.")

# Function to decrypt the message
def decrypt_message():
    encrypted_message = entry_encrypted.get()
    if encrypted_message:
        try:
            decrypted = cipher.decrypt(encrypted_message.encode())
            entry_decrypted.delete(0, tk.END)
            entry_decrypted.insert(0, decrypted.decode())
        except Exception as e:
            messagebox.showerror("Error", "Invalid encrypted message.")
    else:
        messagebox.showerror("Error", "Please enter a message to decrypt.")

# Create the UI
root = tk.Tk()
root.title("Colorful Message Encryption App")
root.geometry("500x400")
root.configure(bg="#f0f8ff")

# Title Label
title_label = tk.Label(root, text="Message Encryption App", font=("Arial", 20), bg="#f0f8ff", fg="#4b0082")
title_label.pack(pady=20)

# Message Entry
label_message = tk.Label(root, text="Enter your message:", bg="#f0f8ff", fg="#4b0082")
label_message.pack(pady=5)

entry_message = tk.Entry(root, width=50, font=("Arial", 14), bd=2)
entry_message.pack(pady=10)

# Encrypt Button
button_encrypt = tk.Button(root, text="Encrypt", command=encrypt_message, bg="#4b0082", fg="white", font=("Arial", 14))
button_encrypt.pack(pady=10)

# Encrypted Message Entry
label_encrypted = tk.Label(root, text="Encrypted message:", bg="#f0f8ff", fg="#4b0082")
label_encrypted.pack(pady=5)

entry_encrypted = tk.Entry(root, width=50, font=("Arial", 14), bd=2)
entry_encrypted.pack(pady=10)

# Decrypt Button
button_decrypt = tk.Button(root, text="Decrypt", command=decrypt_message, bg="#4b0082", fg="white", font=("Arial", 14))
button_decrypt.pack(pady=10)

# Decrypted Message Entry
label_decrypted = tk.Label(root, text="Decrypted message:", bg="#f0f8ff", fg="#4b0082")
label_decrypted.pack(pady=5)

entry_decrypted = tk.Entry(root, width=50, font=("Arial", 14), bd=2)
entry_decrypted.pack(pady=10)

# Run the application
root.mainloop()
