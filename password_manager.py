import tkinter as tk
from tkinter import messagebox, ttk, simpledialog, filedialog
import sqlite3
import os
import base64
import subprocess
import sys
import logging
from functools import partial
import secrets
import threading
import pyperclip
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Set up logging
logging.basicConfig(filename='password_manager.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Initialize Argon2 PasswordHasher with secure parameters
ph = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4)

def generate_key(password: str, salt: bytes = None) -> tuple:
    if salt is None:
        salt = secrets.token_bytes(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return Fernet(key), salt

def encrypt_password(password: str, master_password: str) -> tuple:
    fernet, salt = generate_key(master_password)
    return fernet.encrypt(password.encode()), salt

def decrypt_password(encrypted_password: bytes, master_password: str, salt: bytes) -> str:
    fernet, _ = generate_key(master_password, salt)
    return fernet.decrypt(encrypted_password).decode()

def hash_master_password(password: str) -> str:
    return ph.hash(password)

def verify_master_password(stored_password: str, provided_password: str) -> bool:
    try:
        return ph.verify(stored_password, provided_password)
    except VerifyMismatchError:
        return False

class PasswordDatabase:
    def __init__(self, db_name: str = "passwords.db"):
        self.db_name = db_name
        self.create_table()

    def create_table(self):
        with sqlite3.connect(self.db_name) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS passwords (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    email TEXT NOT NULL,
                    platform_key TEXT NOT NULL,
                    encrypted_password TEXT NOT NULL,
                    salt TEXT NOT NULL
                )
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS master_password (
                    id INTEGER PRIMARY KEY CHECK (id = 1),
                    hashed_password TEXT NOT NULL,
                    salt TEXT NOT NULL
                )
            """)
            logging.info("Database tables created successfully")

    def store_password(self, email: str, platform_key: str, encrypted_password: bytes, salt: bytes):
        with sqlite3.connect(self.db_name) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO passwords (email, platform_key, encrypted_password, salt) VALUES (?, ?, ?, ?)",
                (email, platform_key, base64.b64encode(encrypted_password).decode(), base64.b64encode(salt).decode())
            )
            logging.info(f"Password stored for {email} on {platform_key}")

    def retrieve_password(self, email: str, platform_key: str) -> tuple:
        with sqlite3.connect(self.db_name) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT encrypted_password, salt FROM passwords WHERE email=? AND platform_key=?", (email, platform_key))
            result = cursor.fetchone()
            if result:
                return base64.b64decode(result[0]), base64.b64decode(result[1])
            return None, None

    def get_all_passwords(self):
        with sqlite3.connect(self.db_name) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT email, platform_key FROM passwords")
            return cursor.fetchall()

    def export_passwords(self, file_path: str, master_password: str):
        data = []
        with sqlite3.connect(self.db_name) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT email, platform_key, encrypted_password, salt FROM passwords")
            data = cursor.fetchall()
        if data:
            with open(file_path, 'wb') as file:
                fernet, salt = generate_key(master_password)
                encrypted_data = fernet.encrypt(str(data).encode())
                file.write(encrypted_data)
                logging.info("Passwords exported successfully")

    def import_passwords(self, file_path: str, master_password: str):
        with open(file_path, 'rb') as file:
            encrypted_data = file.read()
        fernet, _ = generate_key(master_password)
        decrypted_data = fernet.decrypt(encrypted_data).decode()
        passwords = eval(decrypted_data)
        for email, platform_key, encrypted_password, salt in passwords:
            self.store_password(email, platform_key, base64.b64decode(encrypted_password), base64.b64decode(salt))
        logging.info("Passwords imported successfully")

class PasswordManager:
    def __init__(self, master):
        self.master = master
        self.db = PasswordDatabase()
        self.master_password = None
        self.setup_ui()
        self.auto_clear_clipboard = True

    def setup_ui(self):
        self.master.title("Secure Password Manager")
        self.master.geometry("600x450")
        self.master.bind('<Control-n>', lambda e: self.add_password())  # Ctrl+N for adding password
        self.master.bind('<Control-r>', lambda e: self.get_password())  # Ctrl+R for retrieving password
        self.master.bind('<Control-e>', lambda e: self.export_passwords())  # Ctrl+E for exporting passwords
        self.master.bind('<Control-i>', lambda e: self.import_passwords())  # Ctrl+I for importing passwords

        style = ttk.Style()
        style.theme_use('clam')
        style.configure('TButton', font=('Arial', 10, 'bold'))
        style.configure('TLabel', font=('Arial', 12))
        style.configure('TEntry', font=('Arial', 10))

        self.notebook = ttk.Notebook(self.master)
        self.notebook.pack(expand=1, fill="both", padx=10, pady=10)

        self.setup_master_password_tab()
        self.setup_add_password_tab()
        self.setup_get_password_tab()
        self.setup_view_passwords_tab()

    def setup_master_password_tab(self):
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="Master Password")
        ttk.Label(tab, text="Enter Master Password:").pack(pady=10)
        self.master_password_entry = ttk.Entry(tab, show="*")
        self.master_password_entry.pack(pady=10)
        ttk.Button(tab, text="Set/Verify Master Password", command=self.handle_master_password).pack(pady=10)

    def setup_add_password_tab(self):
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="Add Password")
        ttk.Label(tab, text="Email:").pack(pady=5)
        self.add_email_entry = ttk.Entry(tab)
        self.add_email_entry.pack(pady=5)
        ttk.Label(tab, text="Platform:").pack(pady=5)
        self.add_platform_entry = ttk.Entry(tab)
        self.add_platform_entry.pack(pady=5)
        ttk.Label(tab, text="Password:").pack(pady=5)
        self.add_password_entry = ttk.Entry(tab, show="*")
        self.add_password_entry.pack(pady=5)
        ttk.Button(tab, text="Store Password", command=self.add_password).pack(pady=10)

    def setup_get_password_tab(self):
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="Get Password")
        ttk.Label(tab, text="Email:").pack(pady=5)
        self.get_email_entry = ttk.Entry(tab)
        self.get_email_entry.pack(pady=5)
        ttk.Label(tab, text="Platform:").pack(pady=5)
        self.get_platform_entry = ttk.Entry(tab)
        self.get_platform_entry.pack(pady=5)
        ttk.Button(tab, text="Retrieve Password", command=self.get_password).pack(pady=10)
        ttk.Label(tab, text="Password:").pack(pady=5)
        self.retrieved_password_label = ttk.Label(tab, text="")
        self.retrieved_password_label.pack(pady=5)
        ttk.Button(tab, text="Copy Password to Clipboard", command=self.copy_password_to_clipboard).pack(pady=10)

    def setup_view_passwords_tab(self):
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="View Passwords")
        self.passwords_tree = ttk.Treeview(tab, columns=("Email", "Platform"), show="headings")
        self.passwords_tree.heading("Email", text="Email")
        self.passwords_tree.heading("Platform", text="Platform")
        self.passwords_tree.pack(expand=1, fill="both", padx=10, pady=10)
        ttk.Button(tab, text="Refresh", command=self.refresh_password_list).pack(pady=10)
        ttk.Button(tab, text="Export Passwords", command=self.export_passwords).pack(pady=10)
        ttk.Button(tab, text="Import Passwords", command=self.import_passwords).pack(pady=10)

    def handle_master_password(self):
        master_password = self.master_password_entry.get()
        stored_password, salt = self.db.get_master_password()
        if stored_password is None:
            hashed_password = hash_master_password(master_password)
            _, salt = generate_key(master_password)  # Generate a new salt for storing the master password
            self.db.store_master_password(hashed_password, salt)
            messagebox.showinfo("Info", "Master password set successfully!")
            self.master_password = master_password
        elif verify_master_password(stored_password, master_password):
            messagebox.showinfo("Info", "Master password verified successfully!")
            self.master_password = master_password
        else:
            messagebox.showerror("Error", "Incorrect master password!")

    def add_password(self):
        if not self.master_password:
            messagebox.showerror("Error", "Please set/verify master password first!")
            return
        email = self.add_email_entry.get()
        platform_key = self.add_platform_entry.get()
        password = self.add_password_entry.get()
        if not email or not platform_key or not password:
            messagebox.showerror("Error", "All fields are required!")
            return
        encrypted_password, salt = encrypt_password(password, self.master_password)
        self.db.store_password(email, platform_key, encrypted_password, salt)
        messagebox.showinfo("Info", "Password stored successfully!")
        self.add_email_entry.delete(0, tk.END)
        self.add_platform_entry.delete(0, tk.END)
        self.add_password_entry.delete(0, tk.END)

    def get_password(self):
        if not self.master_password:
            messagebox.showerror("Error", "Please set/verify master password first!")
            return
        email = self.get_email_entry.get()
        platform_key = self.get_platform_entry.get()
        if not email or not platform_key:
            messagebox.showerror("Error", "All fields are required!")
            return
        encrypted_password, salt = self.db.retrieve_password(email, platform_key)
        if encrypted_password and salt:
            password = decrypt_password(encrypted_password, self.master_password, salt)
            self.retrieved_password_label.config(text=password)
        else:
            messagebox.showerror("Error", "No matching password found!")

    def copy_password_to_clipboard(self):
        password = self.retrieved_password_label.cget("text")
        if password:
            pyperclip.copy(password)
            messagebox.showinfo("Info", "Password copied to clipboard!")
            if self.auto_clear_clipboard:
                threading.Timer(10.0, self.clear_clipboard).start()

    def clear_clipboard(self):
        pyperclip.copy("")
        messagebox.showinfo("Info", "Clipboard cleared automatically for security!")

    def refresh_password_list(self):
        for item in self.passwords_tree.get_children():
            self.passwords_tree.delete(item)
        passwords = self.db.get_all_passwords()
        for email, platform in passwords:
            self.passwords_tree.insert("", "end", values=(email, platform))

    def export_passwords(self):
        file_path = filedialog.asksaveasfilename(defaultextension=".enc", filetypes=[("Encrypted Files", "*.enc")])
        if file_path:
            self.db.export_passwords(file_path, self.master_password)
            messagebox.showinfo("Info", "Passwords exported successfully!")

    def import_passwords(self):
        file_path = filedialog.askopenfilename(filetypes=[("Encrypted Files", "*.enc")])
        if file_path:
            self.db.import_passwords(file_path, self.master_password)
            messagebox.showinfo("Info", "Passwords imported successfully!")
            self.refresh_password_list()

if __name__ == "__main__":
    root = tk.Tk()
    PasswordManager(root)
    root.mainloop()