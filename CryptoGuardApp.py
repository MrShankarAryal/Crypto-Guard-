#!/usr/bin/env python3
"""
Project Name: CryptoGuard
Objective    : File Encryption GUI App
Credit       : Shankar Aryal
Date         : 8/2/2024 at 1:08 AM
"""

import os
import hashlib
import tkinter as tk
import customtkinter as ctk
from tkinter import filedialog, messagebox
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes


class CryptoGuard:
    def __init__(self, user_file, user_key):
        """
        Initialize the CryptoGuard class with user file and key.
        """
        self.user_file = user_file
        self.input_file_size = os.path.getsize(self.user_file)
        self.chunk_size = 1024
        self.total_chunks = (self.input_file_size // self.chunk_size) + 1
        self.user_key = bytes(user_key, "utf-8")
        self.user_salt = hashlib.sha256(self.user_key).digest()
        self.file_extension = self.user_file.split(".")[-1]
        self.hash_type = "SHA256"
        self.encrypt_output_file = self.user_file + ".CryptoGuard"
        self.decrypt_output_file = self.user_file.replace(".CryptoGuard", "")
        self.hashed_key_salt = {}
        self.hash_key_salt()

    def read_in_chunks(self, file_object, chunk_size=1024):
        """
        Lazy function (generator) to read a file piece by piece.
        Default chunk size: 1k.
        """
        while True:
            data = file_object.read(chunk_size)
            if not data:
                break
            yield data

    def hash_key_salt(self):
        """
        Hash the user_key and user_salt using the hash type and return the first 16 bits.
        """
        self.hashed_key_salt['key'] = hashlib.new(self.hash_type, self.user_key).digest()[:32]
        self.hashed_key_salt['salt'] = hashlib.new(self.hash_type, self.user_salt).digest()[:16]

    def generate_file_hash(self, file_path):
        """
        Generate SHA-256 hash of the file.
        """
        hash_sha256 = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in self.read_in_chunks(f):
                hash_sha256.update(chunk)
        return hash_sha256.hexdigest()

    def encrypt(self):
        """
        Encrypt the given file using the user_key and user_salt.
        """
        encrypt_cipher = AES.new(self.hashed_key_salt['key'], AES.MODE_GCM, self.hashed_key_salt['salt'])
        file_hash = self.generate_file_hash(self.user_file)
        with open(self.user_file, "rb") as f_input:
            with open(self.encrypt_output_file, "wb") as f_output:
                f_output.write(self.hashed_key_salt['salt'])
                f_output.write(file_hash.encode('utf-8'))  # Store the hash at the beginning of the file
                for chunk in self.read_in_chunks(f_input, self.chunk_size):
                    encrypted_chunk = encrypt_cipher.encrypt(chunk)
                    f_output.write(encrypted_chunk)
                    yield 100 * (f_input.tell() / self.input_file_size)

    def verify_file_hash(self, file_path, original_hash):
        """
        Verify the SHA-256 hash of the file.
        """
        current_hash = self.generate_file_hash(file_path)
        return current_hash == original_hash

    def decrypt(self):
        """
        Decrypt the given file using the user_key and user_salt.
        """
        with open(self.user_file, "rb") as f_input:
            salt = f_input.read(16)
            original_hash = f_input.read(64).decode('utf-8')  # Read the stored hash
            decrypt_cipher = AES.new(self.hashed_key_salt['key'], AES.MODE_GCM, salt)
            with open(self.decrypt_output_file, "wb") as f_output:
                for chunk in self.read_in_chunks(f_input, self.chunk_size):
                    decrypted_chunk = decrypt_cipher.decrypt(chunk)
                    f_output.write(decrypted_chunk)
                    yield 100 * (f_input.tell() / self.input_file_size)
        
        # Verify the hash of the decrypted file
        if not self.verify_file_hash(self.decrypt_output_file, original_hash):
            os.remove(self.decrypt_output_file)
            raise ValueError("Decryption failed: File integrity check failed.")

    def abort(self):
        """
        Delete the output file and exit the program.
        """
        if os.path.exists(self.encrypt_output_file):
            os.remove(self.encrypt_output_file)
        if os.path.exists(self.decrypt_output_file):
            os.remove(self.decrypt_output_file)


class MainWindow:
    def __init__(self, root):
        """
        Initialize the main window of the application.
        """
        self.root = root
        self.root.title("CryptoGuard")
        self.root.geometry("450x280")
        self.root.iconbitmap('C:\\Users\\Shankar Aryal\\Desktop\\CryptoGuard\\assets\\icon.ico')
        self._file_url = tk.StringVar()
        self._secret_key = tk.StringVar()
        self._status = tk.StringVar()
        self.should_cancel = False
        self._cipher = None
        self.create_widgets()

    def create_widgets(self):
        """
        Create and layout the GUI components.
        """
        self.menu_bar = tk.Menu(self.root, relief=tk.FLAT)
        self.menu_bar.add_command(label="Help !", command=self.show_help_callback)
        self.menu_bar.add_command(label="About!", command=self.show_about_callback)
        self.root.config(menu=self.menu_bar)

        self.root.grid_columnconfigure(1, weight=1)
        self.root.grid_columnconfigure(0, minsize=0)
        self.root.grid_columnconfigure(2, minsize=0)

        ctk.CTkLabel(self.root, text="File URL:").grid(row=0, column=0, pady=5, padx=0, sticky="w")
        ctk.CTkEntry(self.root, textvariable=self._file_url, width=290, height=25, font=('Arial', 15), corner_radius=50, state="normal").grid(row=0, column=1, padx=0, pady=5, sticky="ew")
        ctk.CTkButton(self.root, text="Select", command=self.select_file, font=('Arial', 15), corner_radius=15, height=20, width=75).grid(row=0, column=2, padx=0, pady=5, sticky="w")

        ctk.CTkLabel(self.root, text="Secret Key:").grid(row=1, column=0, pady=5, padx=0, sticky="w")
        ctk.CTkEntry(self.root, textvariable=self._secret_key, width=290, height=25, font=('Arial', 15), corner_radius=50, state="normal").grid(row=1, column=1, padx=0, pady=5)

        ctk.CTkButton(self.root, text="Encrypt", command=self.encrypt_file, corner_radius=15, width=120, font=('Arial', 15)).grid(row=2, column=0, columnspan=1, padx=(20, 0), pady=(5, 5), sticky="w")
        ctk.CTkButton(self.root, text="Decrypt", command=self.decrypt_file, corner_radius=15, width=120, font=('Arial', 15)).grid(row=2, column=1, columnspan=1, padx=(0, 0), pady=(5, 5))
        ctk.CTkButton(self.root, text="Reset", command=self.reset_callback, corner_radius=15, width=120, font=('Arial', 15)).grid(row=3, column=0, columnspan=1, padx=(20, 0), pady=(5, 5), sticky="w")
        ctk.CTkButton(self.root, text="Cancel", command=self.cancel_callback, corner_radius=15, width=120, font=('Arial', 15)).grid(row=3, column=1, columnspan=1, padx=(0, 0), pady=(5, 5))

        ctk.CTkLabel(self.root, text="Status:").grid(row=6, column=0, padx=(3, 0), sticky="w")
        self.status_label = ctk.CTkLabel(self.root, textvariable=self._status)
        self.status_label.grid(row=6, column=1, columnspan=2)

    def select_file(self):
        """
        Open a file dialog to select a file.
        """
        file_path = filedialog.askopenfilename()
        if file_path:
            self._file_url.set(file_path)

    def encrypt_file(self):
        """
        Encrypt the selected file.
        """
        try:
            if not self._file_url.get():
                messagebox.showerror("Error", "Please select a file.")
                return
            if not self._secret_key.get():
                messagebox.showerror("Error", "Secret key cannot be blank.")
                return

            self.freeze_controls()
            self._status.set("Encrypting...")
            self._cipher = CryptoGuard(self._file_url.get(), self._secret_key.get())
            for percentage in self._cipher.encrypt():
                if self.should_cancel:
                    break
                percentage = "{0:.2f}%".format(percentage)
                self._status.set(percentage)
                self.status_label.update()
            self._status.set("File Encrypted!")
            if self.should_cancel:
                self._cipher.abort()
                self._status.set("Cancelled!")
            self._cipher = None
            self.should_cancel = False
        except Exception as e:
            self._status.set(e)

        self.unfreeze_controls()

    def decrypt_file(self):
        """
        Decrypt the selected file.
        """
        try:
            if not self._file_url.get():
                messagebox.showerror("Error", "Please select a file.")
                return
            if not self._secret_key.get():
                messagebox.showerror("Error", "Secret key cannot be blank.")
                return

            self.freeze_controls()
            self._status.set("Decrypting...")
            self._cipher = CryptoGuard(self._file_url.get(), self._secret_key.get())
            for percentage in self._cipher.decrypt():
                if self.should_cancel:
                    break
                percentage = "{0:.2f}%".format(percentage)
                self._status.set(percentage)
                self.status_label.update()
            self._status.set("File Decrypted!")
            if self.should_cancel:
                self._cipher.abort()
                self._status.set("Cancelled!")
            self._cipher = None
            self.should_cancel = False
        except ValueError as e:
            messagebox.showerror("Error", str(e))
            self._status.set("Decryption failed!")
        except Exception as e:
            self._status.set(e)

        self.unfreeze_controls()

    def freeze_controls(self):
        """
        Disable all input controls.
        """
        for child in self.root.winfo_children():
            if isinstance(child, tk.Entry) or isinstance(child, tk.Button):
                child.configure(state='disabled')

    def unfreeze_controls(self):
        """
        Enable all input controls.
        """
        for child in self.root.winfo_children():
            if isinstance(child, tk.Entry) or isinstance(child, tk.Button):
                child.configure(state='normal')

    def reset_callback(self):
        """
        Reset all input fields and status.
        """
        self._cipher = None
        self._file_url.set("")
        self._secret_key.set("")
        self._status.set("---")

    def cancel_callback(self):
        """
        Set the flag to cancel the current operation.
        """
        self.should_cancel = True

    def show_help_callback(self):
        """
        Show the help message.
        """
        messagebox.showinfo(
            "Help",
            """1. Open the App and Click SELECT FILE Button and select your file e.g. "abc.jpg".
2. Enter your Secret Key (This can be any alphanumeric letters).
3. Click ENCRYPT Button to encrypt. A new encrypted file with ".CryptoGuard" extension e.g. "abc.jpg.CryptoGuard" will be created in the same directory where the "abc.jpg" is.
4. When you want to Decrypt a file you, will select the file with the ".CryptoGuard" extension and Enter your Secret Key which you chose at the time of Encryption. Click DECRYPT Button to decrypt. The decrypted file will be of the same name as before without any suffix or prefix.
5. Click RESET Button to reset the input fields and status bar.
6. You can also Click CANCEL Button during Encryption/Decryption to stop the process."""
        )

    def show_about_callback(self):
        """
        Show the about message.
        """
        messagebox.showinfo(
            "About",
            "CryptoGuard\nVersion 1.1.2 \nDeveloped by Shankar Aryal"
        )


if __name__ == "__main__":
    ROOT = ctk.CTk()
    MAIN_WINDOW = MainWindow(ROOT)
    ROOT.mainloop()
