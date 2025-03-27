# GUI
Project Report for CyberSecurity Mini Project
Title: GUI-Based Cipher-Decipher Application using DES Cipher-Decipher Block Chaining Algorithm
Abstract: This project aims to develop a Graphical User Interface (GUI)-based application for encryption and decryption using the Data Encryption Standard (DES) with Cipher Block Chaining (CBC) mode. The application is built using Python and the Tkinter library, allowing users to securely encrypt and decrypt text messages with an 8-byte secret key. The project provides a user-friendly interface for secure communication and demonstrates the working of symmetric key cryptography.
Introduction: Encryption is a crucial technique in modern data security, ensuring that sensitive information is protected from unauthorized access. The DES algorithm is a symmetric key encryption method that encrypts and decrypts data using the same key. In this project, we implement DES with the CBC mode, which enhances security by incorporating an Initialization Vector (IV) to ensure that identical plaintext blocks produce different ciphertext blocks.
Objectives:
•	Develop a GUI-based application for text encryption and decryption using DES-CBC.
•	Provide an intuitive interface for users to enter plaintext and secret keys.
•	Ensure secure encryption and decryption by handling key and text validations.
•	Demonstrate the practical implementation of cryptographic principles.
Methodology:
1.	Tools and Technologies:
o	Programming Language: Python
o	Libraries Used: Tkinter (for GUI), PyCryptodome (for DES encryption), Base64 (for encoding)
2.	Encryption Process:
o	The user enters plaintext and an 8-byte secret key.
o	The text is padded to make its length a multiple of 8 bytes.
o	A DES cipher in CBC mode is initialized with an 8-byte IV.
o	The plaintext is encrypted and converted into Base64 format for better readability.
3.	Decryption Process:
o	The user enters the encrypted text and the same 8-byte secret key.
o	The encrypted text is decoded from Base64 and decrypted using DES-CBC.
o	The decrypted text is displayed after removing padding.
Implementation Details:
•	GUI Design:
o	Text input box for entering plaintext.
o	Entry field for an 8-byte secret key.
o	Buttons for encryption and decryption.
o	Text output box for displaying results.
•	Error Handling:
o	Ensuring the key length is exactly 8 bytes.
o	Handling incorrect ciphertext or key inputs to prevent decryption errors.
Code Implementation:
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
Results and Observations: The application successfully encrypts and decrypts text messages using DES-CBC. Users can securely transmit and retrieve information using the generated ciphertext. The project effectively demonstrates the principles of symmetric cryptography and block chaining.
Conclusion: This project provides a practical implementation of the DES encryption algorithm with CBC mode in a user-friendly GUI. It highlights the importance of cryptographic techniques in secure communication and offers insights into data encryption using block ciphers.
Future Enhancements:
•	Implement AES encryption for enhanced security.
•	Add file encryption and decryption features.
•	Improve UI/UX for better user experience.
References:
1.	William Stallings, "Cryptography and Network Security: Principles and Practice."
2.	PyCryptodome Documentation: https://pycryptodome.readthedocs.io/

