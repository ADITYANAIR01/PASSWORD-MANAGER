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
import sys
import json
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas

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

def install_requirements():
    requirements = [
        'argon2-cffi',
        'cryptography',
        'pyperclip',
        'reportlab'
    ]
    for package in requirements:
        subprocess.check_call([sys.executable, '-m', 'pip', 'install', package])

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
                    salt BLOB NOT NULL,
                    category TEXT,
                    tags TEXT
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

    def store_note(self, title: str, encrypted_content: bytes, salt: bytes, category: str, tags: str):
        with sqlite3.connect(self.db_name) as conn:
            cursor = conn.cursor()
            cursor.execute("INSERT INTO notes (title, encrypted_content, salt, category, tags) VALUES (?, ?, ?, ?, ?)",
                           (title, base64.b64encode(encrypted_content).decode(), base64.b64encode(salt).decode(), category, tags))
            logging.info(f"Note stored: {title}")

    def retrieve_notes(self):
        with sqlite3.connect(self.db_name) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT title, encrypted_content, salt, category, tags FROM notes")
            return cursor.fetchall()

    def delete_note(self, title: str):
        with sqlite3.connect(self.db_name) as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM notes WHERE title=?", (title,))
            logging.info(f"Note deleted: {title}")

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
        self.dark_mode = tk.BooleanVar(value=False)
        self.setup_ui()
        self.install_dependencies()

    def install_dependencies(self):
        install_requirements()

    def setup_ui(self):
        self.master.title("Secure Password and Notes Manager")
        self.master.geometry("1000x700")

        self.menu_bar = tk.Menu(self.master)
        self.master.config(menu=self.menu_bar)

        self.file_menu = tk.Menu(self.menu_bar, tearoff=0)
        self.file_menu.add_command(label="Exit", command=self.master.quit)
        self.menu_bar.add_cascade(label="File", menu=self.file_menu)

        self.settings_menu = tk.Menu(self.menu_bar, tearoff=0)
        self.settings_menu.add_checkbutton(label="Dark Mode", variable=self.dark_mode, command=self.toggle_dark_mode)
        self.menu_bar.add_cascade(label="Settings", menu=self.settings_menu)

        self.help_menu = tk.Menu(self.menu_bar, tearoff=0)
        self.help_menu.add_command(label="About", command=self.show_about)
        self.menu_bar.add_cascade(label="Help", menu=self.help_menu)

        self.notebook = ttk.Notebook(self.master)
        self.notebook.pack(expand=1, fill="both", padx=10, pady=10)

        self.setup_master_password_tab()
        self.setup_add_password_tab()
        self.setup_get_password_tab()
        self.setup_view_passwords_tab()
        self.setup_notes_tab()
        self.setup_backup_tab()
        self.setup_recovery_tab()

        self.status_bar = ttk.Label(self.master, text="Ready", relief=tk.SUNKEN, anchor=tk.W)
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)

        self.toggle_dark_mode()

    def show_about(self):
        messagebox.showinfo("About", "Secure Password and Notes Manager\nVersion 1.0\nMADE WITH 🤎 BY ADITYA")

    def toggle_dark_mode(self):
        if self.dark_mode.get():
            self.master.tk_setPalette(background='#2e2e2e', foreground='white', activeBackground='#4a4a4a', activeForeground='white')
            style = ttk.Style()
            style.theme_use('clam')
            style.configure("TLabel", background='#2e2e2e', foreground='white')
            style.configure("TButton", background='#4a4a4a', foreground='white')
            style.configure("TEntry", fieldbackground='#4a4a4a', foreground='white')
            style.configure("TNotebook", background='#2e2e2e', foreground='white')
            style.configure("TNotebook.Tab", background='#4a4a4a', foreground='white')
            style.configure("TFrame", background='#2e2e2e')
            style.configure("Treeview", background='#2e2e2e', foreground='white', fieldbackground='#2e2e2e')
            style.configure("Treeview.Heading", background='#4a4a4a', foreground='white')
            style.configure("TProgressbar", background='#4a4a4a', troughcolor='#2e2e2e')
        else:
            self.master.tk_setPalette(background='#f0f0f0', foreground='black', activeBackground='#e0e0e0', activeForeground='black')
            style = ttk.Style()
            style.theme_use('clam')
            style.configure("TLabel", background='#f0f0f0', foreground='black')
            style.configure("TButton", background='#e0e0e0', foreground='black')
            style.configure("TEntry", fieldbackground='#e0e0e0', foreground='black')
            style.configure("TNotebook", background='#f0f0f0', foreground='black')
            style.configure("TNotebook.Tab", background='#e0e0e0', foreground='black')
            style.configure("TFrame", background='#f0f0f0')
            style.configure("Treeview", background='#f0f0f0', foreground='black', fieldbackground='#f0f0f0')
            style.configure("Treeview.Heading", background='#e0e0e0', foreground='black')
            style.configure("TProgressbar", background='#e0e0e0', troughcolor='#f0f0f0')

    def setup_master_password_tab(self):
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="Master Password")
        ttk.Label(tab, text="Enter Master Password:").grid(row=0, column=0, pady=10, padx=10)
        self.master_password_entry = ttk.Entry(tab, show="*")
        self.master_password_entry.grid(row=0, column=1, pady=10, padx=10)
        ttk.Button(tab, text="Set/Verify Master Password", command=self.handle_master_password).grid(row=1, column=0, columnspan=2, pady=10)

    def setup_add_password_tab(self):
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="Add Password")
        ttk.Label(tab, text="Email:").grid(row=0, column=0, pady=5, padx=10)
        self.add_email_entry = ttk.Entry(tab)
        self.add_email_entry.grid(row=0, column=1, pady=5, padx=10)
        ttk.Label(tab, text="Platform:").grid(row=1, column=0, pady=5, padx=10)
        self.add_platform_entry = ttk.Entry(tab)
        self.add_platform_entry.grid(row=1, column=1, pady=5, padx=10)
        ttk.Label(tab, text="Password:").grid(row=2, column=0, pady=5, padx=10)
        self.add_password_entry = ttk.Entry(tab, show="*")
        self.add_password_entry.grid(row=2, column=1, pady=5, padx=10)
        ttk.Button(tab, text="Store Password", command=self.add_password).grid(row=3, column=0, columnspan=2, pady=10)

    def setup_get_password_tab(self):
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="Get Password")
        ttk.Label(tab, text="Email:").grid(row=0, column=0, pady=5, padx=10)
        self.get_email_entry = ttk.Entry(tab)
        self.get_email_entry.grid(row=0, column=1, pady=5, padx=10)
        ttk.Label(tab, text="Platform:").grid(row=1, column=0, pady=5, padx=10)
        self.get_platform_entry = ttk.Entry(tab)
        self.get_platform_entry.grid(row=1, column=1, pady=5, padx=10)
        ttk.Button(tab, text="Retrieve Password", command=self.get_password).grid(row=2, column=0, columnspan=2, pady=10)
        ttk.Label(tab, text="Password:").grid(row=3, column=0, pady=5, padx=10)
        self.retrieved_password_label = ttk.Label(tab, text="")
        self.retrieved_password_label.grid(row=3, column=1, pady=5, padx=10)
        ttk.Button(tab, text="Copy Password to Clipboard", command=self.copy_password_to_clipboard).grid(row=4, column=0, columnspan=2, pady=10)

    def setup_view_passwords_tab(self):
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="View Passwords")
        self.passwords_tree = ttk.Treeview(tab, columns=("Email", "Platform"), show="headings")
        self.passwords_tree.heading("Email", text="Email")
        self.passwords_tree.heading("Platform", text="Platform")
        self.passwords_tree.pack(expand=1, fill="both", padx=10, pady=10)
        ttk.Button(tab, text="Refresh", command=self.refresh_password_list).pack(pady=10)

    def setup_notes_tab(self):
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="Notes")

        self.notes_notebook = ttk.Notebook(tab)
        self.notes_notebook.pack(expand=1, fill="both", padx=10, pady=10)

        self.setup_add_note_tab(self.notes_notebook)
        self.setup_view_notes_tab(self.notes_notebook)
        self.setup_export_notes_tab(self.notes_notebook)
        self.setup_import_notes_tab(self.notes_notebook)
        self.setup_categories_tags_tab(self.notes_notebook)

    def setup_add_note_tab(self, parent):
        tab = ttk.Frame(parent)
        parent.add(tab, text="Add Note")
        ttk.Label(tab, text="Title:").grid(row=0, column=0, pady=5, padx=10)
        self.note_title_entry = ttk.Entry(tab)
        self.note_title_entry.grid(row=0, column=1, pady=5, padx=10)
        ttk.Label(tab, text="Content:").grid(row=1, column=0, pady=5, padx=10)
        self.note_content_entry = tk.Text(tab, height=10)
        self.note_content_entry.grid(row=1, column=1, pady=5, padx=10)
        ttk.Label(tab, text="Category:").grid(row=2, column=0, pady=5, padx=10)
        self.note_category_entry = ttk.Entry(tab)
        self.note_category_entry.grid(row=2, column=1, pady=5, padx=10)
        ttk.Label(tab, text="Tags (comma-separated):").grid(row=3, column=0, pady=5, padx=10)
        self.note_tags_entry = ttk.Entry(tab)
        self.note_tags_entry.grid(row=3, column=1, pady=5, padx=10)
        ttk.Button(tab, text="Save Note", command=self.save_note).grid(row=4, column=0, columnspan=2, pady=10)

    def setup_view_notes_tab(self, parent):
        tab = ttk.Frame(parent)
        parent.add(tab, text="View Notes")
        self.notes_list = tk.Listbox(tab)
        self.notes_list.pack(expand=1, fill="both", padx=10, pady=10)
        ttk.Button(tab, text="View Selected Note", command=self.view_selected_note).pack(pady=10)
        ttk.Button(tab, text="Edit Selected Note", command=self.edit_selected_note).pack(pady=10)
        ttk.Button(tab, text="Delete Selected Note", command=self.delete_selected_note).pack(pady=10)
        self.refresh_notes_list()

    def setup_export_notes_tab(self, parent):
        tab = ttk.Frame(parent)
        parent.add(tab, text="Export Notes")
        ttk.Label(tab, text="Select Export Location:").pack(pady=10)
        self.export_location_entry = ttk.Entry(tab)
        self.export_location_entry.pack(pady=10)
        ttk.Button(tab, text="Browse", command=self.browse_export_location).pack(pady=10)
        ttk.Button(tab, text="Export Notes", command=self.export_notes).pack(pady=10)

    def setup_import_notes_tab(self, parent):
        tab = ttk.Frame(parent)
        parent.add(tab, text="Import Notes")
        ttk.Label(tab, text="Select Import File:").pack(pady=10)
        self.import_file_entry = ttk.Entry(tab)
        self.import_file_entry.pack(pady=10)
        ttk.Button(tab, text="Browse", command=self.browse_import_file).pack(pady=10)
        ttk.Button(tab, text="Import Notes", command=self.import_notes).pack(pady=10)

    def setup_categories_tags_tab(self, parent):
        tab = ttk.Frame(parent)
        parent.add(tab, text="Search Notes")
        ttk.Label(tab, text="Category:").grid(row=0, column=0, pady=5, padx=10)
        self.search_category_entry = ttk.Entry(tab)
        self.search_category_entry.grid(row=0, column=1, pady=5, padx=10)
        ttk.Label(tab, text="Tag:").grid(row=1, column=0, pady=5, padx=10)
        self.search_tag_entry = ttk.Entry(tab)
        self.search_tag_entry.grid(row=1, column=1, pady=5, padx=10)
        ttk.Button(tab, text="Search Notes", command=self.search_notes).grid(row=2, column=0, columnspan=2, pady=10)

    def setup_backup_tab(self):
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="Backup Data")
        ttk.Label(tab, text="Select Backup Location:").grid(row=0, column=0, pady=10, padx=10)
        self.backup_location_entry = ttk.Entry(tab)
        self.backup_location_entry.grid(row=0, column=1, pady=10, padx=10)
        ttk.Button(tab, text="Browse", command=self.browse_backup_location).grid(row=1, column=0, columnspan=2, pady=10)
        ttk.Button(tab, text="Create Backup", command=self.create_backup).grid(row=2, column=0, columnspan=2, pady=10)
        ttk.Label(tab, text="Checksum:").grid(row=3, column=0, pady=5, padx=10)
        self.backup_checksum_label = ttk.Label(tab, text="")
        self.backup_checksum_label.grid(row=3, column=1, pady=5, padx=10)
        self.backup_progress = ttk.Progressbar(tab, orient="horizontal", length=200, mode="determinate")
        self.backup_progress.grid(row=4, column=0, columnspan=2, pady=10)

    def setup_recovery_tab(self):
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="Recover Data")
        ttk.Label(tab, text="Select Backup File:").grid(row=0, column=0, pady=10, padx=10)
        self.recovery_file_entry = ttk.Entry(tab)
        self.recovery_file_entry.grid(row=0, column=1, pady=10, padx=10)
        ttk.Button(tab, text="Browse", command=self.browse_recovery_file).grid(row=1, column=0, columnspan=2, pady=10)
        ttk.Button(tab, text="Restore Data", command=self.restore_data).grid(row=2, column=0, columnspan=2, pady=10)
        ttk.Label(tab, text="Checksum:").grid(row=3, column=0, pady=5, padx=10)
        self.recovery_checksum_label = ttk.Label(tab, text="")
        self.recovery_checksum_label.grid(row=3, column=1, pady=5, padx=10)
        self.recovery_progress = ttk.Progressbar(tab, orient="horizontal", length=200, mode="determinate")
        self.recovery_progress.grid(row=4, column=0, columnspan=2, pady=10)

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
        category = self.note_category_entry.get()
        tags = self.note_tags_entry.get()
        if not title or not content:
            messagebox.showerror("Error", "Both title and content are required!")
            return
        encrypted_content, salt = encrypt_data(content, self.master_password)
        self.db.store_note(title, encrypted_content, salt, category, tags)
        messagebox.showinfo("Success", "Note saved successfully!")
        self.note_title_entry.delete(0, tk.END)
        self.note_content_entry.delete("1.0", tk.END)
        self.note_category_entry.delete(0, tk.END)
        self.note_tags_entry.delete(0, tk.END)
        self.refresh_notes_list()

    def refresh_notes_list(self):
        self.notes_list.delete(0, tk.END)
        notes = self.db.retrieve_notes()
        for title, _, _, _, _ in notes:
            self.notes_list.insert(tk.END, title)

    def view_selected_note(self):
        selected_index = self.notes_list.curselection()
        if not selected_index:
            messagebox.showwarning("Warning", "No note selected!")
            return
        note = self.db.retrieve_notes()[selected_index[0]]
        title, encrypted_content, salt, category, tags = note
        content = decrypt_data(base64.b64decode(encrypted_content), self.master_password, base64.b64decode(salt))
        messagebox.showinfo(title, f"Content:\n{content}\n\nCategory: {category}\nTags: {tags}")

    def edit_selected_note(self):
        selected_index = self.notes_list.curselection()
        if not selected_index:
            messagebox.showwarning("Warning", "No note selected!")
            return
        note = self.db.retrieve_notes()[selected_index[0]]
        title, encrypted_content, salt, category, tags = note
        content = decrypt_data(base64.b64decode(encrypted_content), self.master_password, base64.b64decode(salt))
        self.note_title_entry.delete(0, tk.END)
        self.note_title_entry.insert(0, title)
        self.note_content_entry.delete("1.0", tk.END)
        self.note_content_entry.insert(tk.END, content)
        self.note_category_entry.delete(0, tk.END)
        self.note_category_entry.insert(0, category)
        self.note_tags_entry.delete(0, tk.END)
        self.note_tags_entry.insert(0, tags)
        self.notes_list.delete(selected_index)

    def delete_selected_note(self):
        selected_index = self.notes_list.curselection()
        if not selected_index:
            messagebox.showwarning("Warning", "No note selected!")
            return
        note_title = self.notes_list.get(selected_index)
        confirm = messagebox.askyesno("Confirm", f"Are you sure you want to delete the note '{note_title}'?")
        if confirm:
            self.notes_list.delete(selected_index)
            self.db.delete_note(note_title)
            messagebox.showinfo("Success", "Note deleted successfully!")

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
        threading.Thread(target=self.perform_backup, args=(backup_location,)).start()

    def perform_backup(self, backup_location):
        self.backup_progress.start(10)
        self.db.backup_data(backup_location)
        checksum = calculate_checksum(backup_location)
        self.backup_checksum_label.config(text=checksum)
        self.backup_progress.stop()
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
        threading.Thread(target=self.perform_restore, args=(recovery_file,)).start()

    def perform_restore(self, recovery_file):
        self.recovery_progress.start(10)
        self.db.restore_data(recovery_file)
        self.recovery_progress.stop()
        messagebox.showinfo("Success", "Data restored successfully!")

    def browse_export_location(self):
        export_location = filedialog.asksaveasfilename(defaultextension=".md", filetypes=[("Markdown files", "*.md")])
        if export_location:
            self.export_location_entry.delete(0, tk.END)
            self.export_location_entry.insert(0, export_location)

    def export_notes(self):
        export_location = self.export_location_entry.get()
        if not export_location:
            messagebox.showerror("Error", "Please select an export location!")
            return
        notes = self.db.retrieve_notes()
        with open(export_location, "w") as f:
            for title, encrypted_content, salt, category, tags in notes:
                content = decrypt_data(base64.b64decode(encrypted_content), self.master_password, base64.b64decode(salt))
                f.write(f"# {title}\n\n{content}\n\nCategory: {category}\nTags: {tags}\n\n---\n\n")
        messagebox.showinfo("Success", "Notes exported successfully!")

    def browse_import_file(self):
        import_file = filedialog.askopenfilename(defaultextension=".json", filetypes=[("JSON files", "*.json")])
        if import_file:
            self.import_file_entry.delete(0, tk.END)
            self.import_file_entry.insert(0, import_file)

    def import_notes(self):
        import_file = self.import_file_entry.get()
        if not import_file:
            messagebox.showerror("Error", "Please select an import file!")
            return
        with open(import_file, "r") as f:
            notes = json.load(f)
            for note in notes:
                title = note.get("title")
                content = note.get("content")
                category = note.get("category", "")
                tags = note.get("tags", "")
                encrypted_content, salt = encrypt_data(content, self.master_password)
                self.db.store_note(title, encrypted_content, salt, category, tags)
        messagebox.showinfo("Success", "Notes imported successfully!")

    def search_notes(self):
        category = self.search_category_entry.get()
        tag = self.search_tag_entry.get()
        notes = self.db.retrieve_notes()
        filtered_notes = [note for note in notes if (category in note[3] and tag in note[4])]
        self.notes_list.delete(0, tk.END)
        for title, _, _, _, _ in filtered_notes:
            self.notes_list.insert(tk.END, title)

if __name__ == "__main__":
    root = tk.Tk()
    root.title("Secure Password and Notes Manager")
    root.geometry("1000x700")
    app = SecureNotesApp(root)
    root.mainloop()

    #FULLY FUNCTIONAL AND MADE WITH 🤎 BY ADITYA
