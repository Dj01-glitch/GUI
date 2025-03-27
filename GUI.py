import tkinter as tk
from tkinter import messagebox
from Crypto.Cipher import DES
import base64

# Padding function to ensure data is a multiple of 8 bytes
def pad(text):
    while len(text) % 8 != 0:
        text += " "
    return text

# Encryption function
def encrypt():
    key = key_entry.get().encode()[:8]  # Ensure 8-byte key
    if len(key) < 8:
        messagebox.showerror("Error", "Key must be 8 bytes long")
        return

    plaintext = pad(input_text.get("1.0", tk.END).strip()).encode()
    cipher = DES.new(key, DES.MODE_CBC, b"12345678")  # 8-byte IV
    ciphertext = cipher.encrypt(plaintext)
    encoded_text = base64.b64encode(ciphertext).decode()
    output_text.delete("1.0", tk.END)
    output_text.insert(tk.END, encoded_text)

# Decryption function
def decrypt():
    key = key_entry.get().encode()[:8]  # Ensure 8-byte key
    if len(key) < 8:
        messagebox.showerror("Error", "Key must be 8 bytes long")
        return

    try:
        encrypted_text = base64.b64decode(input_text.get("1.0", tk.END).strip())
        cipher = DES.new(key, DES.MODE_CBC, b"12345678")  # 8-byte IV
        decrypted_text = cipher.decrypt(encrypted_text).decode().strip()
        output_text.delete("1.0", tk.END)
        output_text.insert(tk.END, decrypted_text)
    except Exception as e:
        messagebox.showerror("Error", "Invalid ciphertext or key")

# GUI Setup
root = tk.Tk()
root.title("DES CBC Cipher GUI")
root.geometry("400x400")

tk.Label(root, text="Enter Text:").pack()
input_text = tk.Text(root, height=4, width=40)
input_text.pack()

tk.Label(root, text="Enter 8-byte Key:").pack()
key_entry = tk.Entry(root)
key_entry.pack()

encrypt_button = tk.Button(root, text="Encrypt", command=encrypt)
encrypt_button.pack()

decrypt_button = tk.Button(root, text="Decrypt", command=decrypt)
decrypt_button.pack()

tk.Label(root, text="Output:").pack()
output_text = tk.Text(root, height=4, width=40)
output_text.pack()

root.mainloop()
