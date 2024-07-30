import tkinter as tk
from tkinter import messagebox, simpledialog, ttk, filedialog
import sqlite3
import os
import base64
import subprocess
import secrets
import threading
import pyperclip
import hashlib
import shutil
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Set up logging (optional)
import logging
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

def encrypt_data(data: str, master_password: str) -> tuple:
    fernet, salt = generate_key(master_password)
    encrypted_data = fernet.encrypt(data.encode())
    return encrypted_data, salt

def decrypt_data(encrypted_data: bytes, master_password: str, salt: bytes) -> str:
    fernet, _ = generate_key(master_password, salt)
    return fernet.decrypt(encrypted_data).decode()

def hash_master_password(password: str) -> str:
    return ph.hash(password)

def verify_master_password(stored_password: str, provided_password: str) -> bool:
    try:
        return ph.verify(stored_password, provided_password)
    except VerifyMismatchError:
        return False

def calculate_checksum(file_path: str) -> str:
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

class Database:
    def __init__(self, db_name: str = "secure_data.db"):
        self.db_name = db_name
        self.create_tables()

    def create_tables(self):
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
                CREATE TABLE IF NOT EXISTS notes (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    title TEXT NOT NULL,
                    encrypted_content TEXT NOT NULL,
                    salt BLOB NOT NULL
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

    def store_note(self, title: str, encrypted_content: bytes, salt: bytes):
        with sqlite3.connect(self.db_name) as conn:
            cursor = conn.cursor()
            cursor.execute("INSERT INTO notes (title, encrypted_content, salt) VALUES (?, ?, ?)",
                           (title, base64.b64encode(encrypted_content).decode(), base64.b64encode(salt).decode()))
            logging.info(f"Note stored: {title}")

    def retrieve_notes(self):
        with sqlite3.connect(self.db_name) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT title, encrypted_content, salt FROM notes")
            return cursor.fetchall()

    def backup_data(self, backup_path: str):
        if os.path.exists(self.db_name):
            shutil.copyfile(self.db_name, backup_path)
            logging.info(f"Backup created at {backup_path}")
        else:
            logging.error("Database file does not exist")

    def restore_data(self, backup_path: str):
        if os.path.exists(backup_path):
            shutil.copyfile(backup_path, self.db_name)
            logging.info(f"Data restored from {backup_path}")
        else:
            logging.error("Backup file does not exist")

class SecureNotesApp:
    def __init__(self, master):
        self.master = master
        self.db = Database()
        self.master_password = None
        self.setup_ui()

    def setup_ui(self):
        self.master.title("Secure Password and Notes Manager")
        self.master.geometry("600x450")

        self.notebook = ttk.Notebook(self.master)
        self.notebook.pack(expand=1, fill="both", padx=10, pady=10)

        self.setup_master_password_tab()
        self.setup_add_password_tab()
        self.setup_get_password_tab()
        self.setup_view_passwords_tab()
        self.setup_add_note_tab()
        self.setup_view_notes_tab()
        self.setup_backup_tab()
        self.setup_recovery_tab()

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

    def setup_add_note_tab(self):
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="Add Note")
        ttk.Label(tab, text="Title:").pack(pady=5)
        self.note_title_entry = ttk.Entry(tab)
        self.note_title_entry.pack(pady=5)
        ttk.Label(tab, text="Content:").pack(pady=5)
        self.note_content_entry = tk.Text(tab, height=10)
        self.note_content_entry.pack(pady=5)
        ttk.Button(tab, text="Save Note", command=self.save_note).pack(pady=10)

    def setup_view_notes_tab(self):
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="View Notes")
        self.notes_list = tk.Listbox(tab)
        self.notes_list.pack(expand=1, fill="both", padx=10, pady=10)
        ttk.Button(tab, text="View Selected Note", command=self.view_selected_note).pack(pady=10)
        self.refresh_notes_list()

    def setup_backup_tab(self):
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="Backup Data")
        ttk.Label(tab, text="Select Backup Location:").pack(pady=10)
        self.backup_location_entry = ttk.Entry(tab)
        self.backup_location_entry.pack(pady=10)
        ttk.Button(tab, text="Browse", command=self.browse_backup_location).pack(pady=10)
        ttk.Button(tab, text="Create Backup", command=self.create_backup).pack(pady=10)
        ttk.Label(tab, text="Checksum:").pack(pady=5)
        self.backup_checksum_label = ttk.Label(tab, text="")
        self.backup_checksum_label.pack(pady=5)

    def setup_recovery_tab(self):
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="Recover Data")
        ttk.Label(tab, text="Select Backup File:").pack(pady=10)
        self.recovery_file_entry = ttk.Entry(tab)
        self.recovery_file_entry.pack(pady=10)
        ttk.Button(tab, text="Browse", command=self.browse_recovery_file).pack(pady=10)
        ttk.Button(tab, text="Restore Data", command=self.restore_data).pack(pady=10)
        ttk.Label(tab, text="Checksum:").pack(pady=5)
        self.recovery_checksum_label = ttk.Label(tab, text="")
        self.recovery_checksum_label.pack(pady=5)

    def handle_master_password(self):
        master_password = self.master_password_entry.get()
        if not self.master_password:
            hashed_password = hash_master_password(master_password)
            self.master_password = master_password
            messagebox.showinfo("Info", "Master password set successfully!")
        elif verify_master_password(hash_master_password(self.master_password), master_password):
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
        encrypted_password, salt = encrypt_data(password, self.master_password)
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
            password = decrypt_data(encrypted_password, self.master_password, salt)
            self.retrieved_password_label.config(text=password)
        else:
            messagebox.showerror("Error", "No matching password found!")

    def copy_password_to_clipboard(self):
        password = self.retrieved_password_label.cget("text")
        if password:
            pyperclip.copy(password)
            messagebox.showinfo("Info", "Password copied to clipboard!")

    def refresh_password_list(self):
        for item in self.passwords_tree.get_children():
            self.passwords_tree.delete(item)
        # Fetch all passwords and update the tree view
        passwords = self.db.get_all_passwords()
        for email, platform in passwords:
            self.passwords_tree.insert("", "end", values=(email, platform))

    def save_note(self):
        if not self.master_password:
            messagebox.showerror("Error", "Please set/verify master password first!")
            return
        title = self.note_title_entry.get()
        content = self.note_content_entry.get("1.0", tk.END).strip()
        if not title or not content:
            messagebox.showerror("Error", "Both title and content are required!")
            return
        encrypted_content, salt = encrypt_data(content, self.master_password)
        self.db.store_note(title, encrypted_content, salt)
        messagebox.showinfo("Success", "Note saved successfully!")
        self.note_title_entry.delete(0, tk.END)
        self.note_content_entry.delete("1.0", tk.END)
        self.refresh_notes_list()

    def refresh_notes_list(self):
        self.notes_list.delete(0, tk.END)
        notes = self.db.retrieve_notes()
        for title, _, _ in notes:
            self.notes_list.insert(tk.END, title)

    def view_selected_note(self):
        selected_index = self.notes_list.curselection()
        if not selected_index:
            messagebox.showwarning("Warning", "No note selected!")
            return
        note = self.db.retrieve_notes()[selected_index[0]]
        title, encrypted_content, salt = note
        content = decrypt_data(base64.b64decode(encrypted_content), self.master_password, base64.b64decode(salt))
        messagebox.showinfo(title, content)

    def browse_backup_location(self):
        backup_location = filedialog.asksaveasfilename(defaultextension=".db", filetypes=[("Database files", "*.db")])
        if backup_location:
            self.backup_location_entry.delete(0, tk.END)
            self.backup_location_entry.insert(0, backup_location)

    def create_backup(self):
        backup_location = self.backup_location_entry.get()
        if not backup_location:
            messagebox.showerror("Error", "Please select a backup location!")
            return
        self.db.backup_data(backup_location)
        checksum = calculate_checksum(backup_location)
        self.backup_checksum_label.config(text=checksum)
        messagebox.showinfo("Success", "Backup created successfully!")

    def browse_recovery_file(self):
        recovery_file = filedialog.askopenfilename(defaultextension=".db", filetypes=[("Database files", "*.db")])
        if recovery_file:
            self.recovery_file_entry.delete(0, tk.END)
            self.recovery_file_entry.insert(0, recovery_file)
            checksum = calculate_checksum(recovery_file)
            self.recovery_checksum_label.config(text=checksum)

    def restore_data(self):
        recovery_file = self.recovery_file_entry.get()
        if not recovery_file:
            messagebox.showerror("Error", "Please select a backup file!")
            return
        self.db.restore_data(recovery_file)
        messagebox.showinfo("Success", "Data restored successfully!")

if __name__ == "__main__":
    root = tk.Tk()
    SecureNotesApp(root)
    root.mainloop()
