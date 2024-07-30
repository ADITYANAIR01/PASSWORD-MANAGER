# Secure Notes App

A secure password and notes manager application built with Python and Tkinter.

## Features

- Secure storage of passwords and notes using encryption
- Master password protection
- Add and retrieve passwords
- Create and view secure notes
- Backup and restore functionality
- Password copying to clipboard
- Database management with SQLite

## Requirements

- Python 3.x
- tkinter
- sqlite3
- pyperclip
- argon2-cffi
- cryptography

## Installation

1. Clone the repository:
   ```
   git clone https://github.com/yourusername/secure-notes-app.git
   ```

2. Install the required packages:
   ```
   pip install pyperclip argon2-cffi cryptography
   ```

## Usage

Run the application:

```
python secure_notes_app.py
```

1. Set a master password when first running the application.
2. Use the different tabs to manage passwords and notes.
3. Create backups and restore data as needed.

## Security Features

- Argon2 password hashing
- AES encryption for stored data
- Secure key derivation using PBKDF2
- Salting for added security

## License

This project is licensed under the MIT License - see the [LICENSE.md](LICENSE.md) file for details.

## Disclaimer

This password manager is a demonstration project and has not undergone a professional security audit. Use at your own risk.
