#!/usr/bin/env python3
"""
    Project Name: CryptoGuard
    OBJECTIVE   : File Encryption GUI App
    Credit      : Shankar Aryal
    Date        : 8/2/2024 at 1:08 AM
"""

import os
import hashlib
import tkinter as tk
import customtkinter as ctk
from tkinter import filedialog, messagebox
from tkinter import PhotoImage  #  for icon
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes



class CryptoGuard:
    """ "EncryptionTool" class from "github.com/nsk89" for file encryption.
    (Has been modified a bit.) """
    def __init__(self, user_file, user_key):
        # get the path to input file
        self.user_file = user_file

        self.input_file_size = os.path.getsize(self.user_file)
        self.chunk_size = 1024
        self.total_chunks = (self.input_file_size // self.chunk_size) + 1

        # convert the key to bytes
        self.user_key = bytes(user_key, "utf-8")

        # derive salt from the key
        self.user_salt = hashlib.sha256(self.user_key).digest()

        # get the file extension
        self.file_extension = self.user_file.split(".")[-1]

        # hash type for hashing key and salt
        self.hash_type = "SHA256"

        # encrypted file name
        self.encrypt_output_file = self.user_file + ".CryptoGuard"

        # decrypted file name
        self.decrypt_output_file = self.user_file.replace(".CryptoGuard", "")

        # dictionary to store hashed key and salt
        self.hashed_key_salt = dict()

        # hash key and salt into 16 bit hashes
        self.hash_key_salt()

    def read_in_chunks(self, file_object, chunk_size=1024):
        """Lazy function (generator) to read a file piece by piece.
        Default chunk size: 1k.
        Code Courtesy: https://stackoverflow.com/questions/519633/lazy-method-for-reading-big-file-in-python
        """
        while True:
            data = file_object.read(chunk_size)
            if not data:
                break
            yield data

    def hash_key_salt(self):
        """Hash the user_key and user_salt using the hash type and return the first 16 bits"""
        self.hashed_key_salt['key'] = hashlib.new(self.hash_type, self.user_key).digest()[:32]
        self.hashed_key_salt['salt'] = hashlib.new(self.hash_type, self.user_salt).digest()[:16]

    def encrypt(self):
        """Encrypt the given file using the user_key and user_salt"""
        encrypt_cipher = AES.new(self.hashed_key_salt['key'], AES.MODE_GCM, self.hashed_key_salt['salt'])
        with open(self.user_file, "rb") as f_input:
            with open(self.encrypt_output_file, "wb") as f_output:
                f_output.write(self.hashed_key_salt['salt'])
                for chunk in self.read_in_chunks(f_input, self.chunk_size):
                    encrypted_chunk = encrypt_cipher.encrypt(chunk)
                    f_output.write(encrypted_chunk)
                    yield 100 * (f_input.tell() / self.input_file_size)

    def decrypt(self):
        """Decrypt the given file using the user_key and user_salt"""
        with open(self.user_file, "rb") as f_input:
            salt = f_input.read(16)
            decrypt_cipher = AES.new(self.hashed_key_salt['key'], AES.MODE_GCM, salt)
            with open(self.decrypt_output_file, "wb") as f_output:
                for chunk in self.read_in_chunks(f_input, self.chunk_size):
                    decrypted_chunk = decrypt_cipher.decrypt(chunk)
                    f_output.write(decrypted_chunk)
                    yield 100 * (f_input.tell() / self.input_file_size)

    def abort(self):
        """Delete the output file and exit the program"""
        if os.path.exists(self.encrypt_output_file):
            os.remove(self.encrypt_output_file)
        if os.path.exists(self.decrypt_output_file):
            os.remove(self.decrypt_output_file)


class MainWindow:
    def __init__(self, root):
        self.root = root
        self.root.title("CryptoGuard")
        self.root.geometry("450x280")  # Set the width x the height pixels
        #self.root.configure(bg="#eeeeee")
        ##########################icon
        root.iconbitmap( 'C:\\Users\\Shankar Aryal\\Desktop\\CryptoGuard\\assets\\icon.ico')
        ###############################
        # Initialize variables
        self._file_url = tk.StringVar()
        self._secret_key = tk.StringVar()
        self._status = tk.StringVar()
        self.should_cancel = False
        self._cipher = None

        # Create GUI components
        self.create_widgets()
       
    def create_widgets(self):
         ############################
        
        self.menu_bar = tk.Menu(
            self.root,
            #bg="#eeeeee",
            relief=tk.FLAT
        )
        self.menu_bar.add_command(
            label="Help !",
            command=self.show_help_callback
        )
        
        self.menu_bar.add_command(
            label="About!",
            command=self.show_about_callback
        )
        self.root.config(menu=self.menu_bar)
  #######################
    
      





        #self.root.grid_columnconfigure(0, weight=1)
        #self.root.grid_columnconfigure(2,weight=0)

        #self.root.grid_columnconfigure(1, weight=1)


         #############################
        #tk.Label(self.root, text="File URL:").grid(row=0, column=0,pady=5,)
        # Assuming self.root is defined and other setup is done
        self.root.grid_columnconfigure(1, weight=1)
        self.root.grid_columnconfigure(0, minsize=0)
        self.root.grid_columnconfigure(2, minsize=0)

        ctk.CTkLabel(self.root, text="File URL:").grid(row=0, column=0, pady=5, padx=0, sticky="w")
        ctk.CTkEntry(self.root, textvariable=self._file_url, width=290, height=25, font=('Arial', 15), corner_radius=50, state="normal").grid(row=0, column=1, padx=0, pady=5, sticky="ew")
        ctk.CTkButton(self.root, text="Select", command=self.select_file, font=('Arial', 15), corner_radius=15, height=20, width=75).grid(row=0, column=2, padx=0, pady=5, sticky="w")

        ctk.CTkLabel(self.root, text="Secret Key:").grid(row=1, column=0, pady=5, padx=0, sticky="w")

        ctk.CTkLabel(self.root, text="Secret Key:").grid(row=1,column=0, pady=5,padx=(0,10),sticky="w")
        ctk.CTkEntry(self.root, textvariable=self._secret_key,width=290,height=25 ,font=('Arial', 15),corner_radius=50,state="normal").grid(
            row=1, 
            column=1,
             padx=(0,0), pady=5,
            )

        #tk.Button(self.root, text="Encrypt", command=self.encrypt_file).grid(row=4, column=1,pady=10,)
        #tk.Button(self.root, text="Decrypt", command=self.decrypt_file).grid(row=4, column=2)
        ctk.CTkButton(self.root, text="Encrypt", command=self.encrypt_file, corner_radius=15, width=120,font=('Arial',15)).grid(row=2, column=0, columnspan=1, padx=(20, 0), pady=(5, 5),sticky="w")
        ctk.CTkButton(self.root, text="Decrypt", command=self.decrypt_file, corner_radius=15, width=120,font=('Arial',15)).grid(row=2, column=1, columnspan=1, padx=(0, 0), pady=(5, 5), )
        ctk.CTkButton(self.root, text="Reset", command=self.reset_callback, corner_radius=15, width=120,font=('Arial',15)).grid(row=3, column=0, columnspan=1, padx=(20, 0), pady=(5, 5), sticky="w")
        ctk.CTkButton(self.root, text="Cancel", command=self.cancel_callback, corner_radius=15, width=120,font=('Arial',15)).grid(row=3, column=1, columnspan=1, padx=(0, 0), pady=(5, 5), )
        #ctk.CTkButton.grid_columnconfigure(1, minsize=200)
        #tk.Button(self.root, text="Reset", command=self.reset_callback).grid(row=5, column=1)
        #tk.Button(self.root, text="Cancel", command=self.cancel_callback).grid(row=5, column=2)

        ctk.CTkLabel(self.root, text="Status:").grid(row=6, column=0,padx=(3,0),sticky="w")
        self.status_label =  ctk.CTkLabel(self.root, textvariable=self._status)
        self.status_label.grid(row=6, column=1, columnspan=2)

        #tk.Button(self.root, text="Help", command=self.show_help_callback).grid(row=6, column=1, columnspan=2)

    def select_file(self):
        file_path = filedialog.askopenfilename()
        if file_path:
            self._file_url.set(file_path)

    def encrypt_file(self):
        try:
            if not self._file_url.get():
                messagebox.showerror("Error", "Please select a file.")
                return
            if not self._secret_key.get():
                messagebox.showerror("Error", "Secret key cannot be blank.")
                return

            self.freeze_controls()
            self._status.set("Encrypting...")
            self._cipher = CryptoGuard(
                self._file_url.get(),
                self._secret_key.get()
            )
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
        try:
            if not self._file_url.get():
                messagebox.showerror("Error", "Please select a file.")
                return
            if not self._secret_key.get():
                messagebox.showerror("Error", "Secret key cannot be blank.")
                return

            self.freeze_controls()
            self._status.set("Decrypting...")
            self._cipher = CryptoGuard(
                self._file_url.get(),
                self._secret_key.get()
            )
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
        except Exception as e:
            self._status.set(e)
        
        self.unfreeze_controls()

    def freeze_controls(self):
        for child in self.root.winfo_children():
            if isinstance(child, tk.Entry) or isinstance(child, tk.Button):
                child.configure(state='disabled')

    def unfreeze_controls(self):
        for child in self.root.winfo_children():
            if isinstance(child, tk.Entry) or isinstance(child, tk.Button):
                child.configure(state='normal')

    def reset_callback(self):
        self._cipher = None
        self._file_url.set("")
        self._secret_key.set("")
        self._status.set("---")
    
    def cancel_callback(self):
        self.should_cancel = True

    def show_help_callback(self):
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
        messagebox.showinfo(
            "About",
            "CryptoGuard\nVersion 1.0\nDeveloped by Shankar Aryal"
        )

if __name__ == "__main__":
    #ROOT = tk.Tk()
    ROOT = ctk.CTk()
    MAIN_WINDOW = MainWindow(ROOT)
    ROOT.mainloop()
