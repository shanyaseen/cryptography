import os
import tkinter as tk
from tkinter import messagebox, scrolledtext
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.backends import default_backend

class AESCipher:
    def __init__(self, key: bytes):
        self.key = key
        self.backend = default_backend()
        self.block_size = algorithms.AES.block_size // 8

    def encrypt(self, plaintext: bytes) -> bytes:
        iv = os.urandom(self.block_size)
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), backend=self.backend)
        encryptor = cipher.encryptor()
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(plaintext) + padder.finalize()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        return iv + ciphertext

    def decrypt(self, ciphertext: bytes) -> bytes:
        iv = ciphertext[:self.block_size]
        actual_ciphertext = ciphertext[self.block_size:]
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), backend=self.backend)
        decryptor = cipher.decryptor()
        padded_plaintext = decryptor.update(actual_ciphertext) + decryptor.finalize()
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
        return plaintext

class RSACipher:
    def __init__(self, private_key=None, public_key=None):
        self.private_key = private_key
        self.public_key = public_key

    def generate_keys(self, key_size=2048):
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=default_backend()
        )
        self.public_key = self.private_key.public_key()

    def encrypt(self, plaintext: bytes, public_key=None) -> bytes:
        public_key = public_key or self.public_key
        ciphertext = public_key.encrypt(
            plaintext,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return ciphertext

    def decrypt(self, ciphertext: bytes, private_key=None) -> bytes:
        private_key = private_key or self.private_key
        plaintext = private_key.decrypt(
            ciphertext,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return plaintext

    def serialize_public_key(self):
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def serialize_private_key(self):
        return self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )

class EncryptionApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Encryption App")

        self.method_var = tk.StringVar(value="AES")

        tk.Label(root, text="Select Encryption Method:").pack(pady=5)
        tk.Radiobutton(root, text="AES", variable=self.method_var, value="AES").pack(anchor='w')
        tk.Radiobutton(root, text="RSA", variable=self.method_var, value="RSA").pack(anchor='w')

        tk.Label(root, text="Enter message:").pack(pady=5)
        self.message_entry = scrolledtext.ScrolledText(root, wrap=tk.WORD, width=40, height=5)
        self.message_entry.pack(pady=5)

        tk.Button(root, text="Encrypt", command=self.encrypt_message).pack(pady=5)
        tk.Button(root, text="Decrypt", command=self.decrypt_message).pack(pady=5)

        tk.Label(root, text="Ciphertext:").pack(pady=5)
        self.ciphertext_entry = scrolledtext.ScrolledText(root, wrap=tk.WORD, width=40, height=5)
        self.ciphertext_entry.pack(pady=5)

        tk.Label(root, text="Decrypted message:").pack(pady=5)
        self.decrypted_entry = scrolledtext.ScrolledText(root, wrap=tk.WORD, width=40, height=5)
        self.decrypted_entry.pack(pady=5)

        self.aes_key = None
        self.rsa_cipher = RSACipher()

    def encrypt_message(self):
        method = self.method_var.get()
        plaintext = self.message_entry.get("1.0", tk.END).strip().encode()

        if method == "AES":
            if not self.aes_key:
                self.aes_key = os.urandom(32)  # AES-256
            aes_cipher = AESCipher(self.aes_key)
            ciphertext = aes_cipher.encrypt(plaintext)
            self.ciphertext_entry.delete("1.0", tk.END)
            self.ciphertext_entry.insert(tk.END, ciphertext.hex())
            messagebox.showinfo("AES Key", f"Your AES Key (hex): {self.aes_key.hex()}")

        elif method == "RSA":
            if not self.rsa_cipher.private_key or not self.rsa_cipher.public_key:
                self.rsa_cipher.generate_keys()
            ciphertext = self.rsa_cipher.encrypt(plaintext)
            self.ciphertext_entry.delete("1.0", tk.END)
            self.ciphertext_entry.insert(tk.END, ciphertext.hex())
            messagebox.showinfo("RSA Keys", f"Public Key (PEM): {self.rsa_cipher.serialize_public_key().decode()}\n"
                                            f"Private Key (PEM): {self.rsa_cipher.serialize_private_key().decode()}")

    def decrypt_message(self):
        method = self.method_var.get()
        ciphertext_hex = self.ciphertext_entry.get("1.0", tk.END).strip()
        ciphertext = bytes.fromhex(ciphertext_hex)

        if method == "AES":
            if not self.aes_key:
                messagebox.showerror("Error", "AES key is not set.")
                return
            aes_cipher = AESCipher(self.aes_key)
            try:
                plaintext = aes_cipher.decrypt(ciphertext)
                self.decrypted_entry.delete("1.0", tk.END)
                self.decrypted_entry.insert(tk.END, plaintext.decode())
            except Exception as e:
                messagebox.showerror("Error", f"Decryption failed: {e}")

        elif method == "RSA":
            try:
                plaintext = self.rsa_cipher.decrypt(ciphertext)
                self.decrypted_entry.delete("1.0", tk.END)
                self.decrypted_entry.insert(tk.END, plaintext.decode())
            except Exception as e:
                messagebox.showerror("Error", f"Decryption failed: {e}")

if __name__ == "__main__":
    root = tk.Tk()
    app = EncryptionApp(root)
    root.mainloop()
