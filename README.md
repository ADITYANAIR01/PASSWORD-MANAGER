# Secure Password Manager

A Python-based secure password manager with a graphical user interface using Tkinter. This application allows users to securely store, retrieve, and manage passwords for various platforms.

## Features

- Set and verify a master password
- Add new passwords for different platforms
- Retrieve stored passwords
- View all stored passwords
- Export and import encrypted password data
- Backup and restore the database
- Automatic clipboard clearing for enhanced security

## Dependencies

The application uses the following Python libraries:

- tkinter
- sqlite3
- argon2-cffi
- cryptography
- pyperclip

## Installation

1. Ensure you have Python 3.x installed on your system.
2. Clone this repository or download the source code.
3. Install the required packages:

```bash
pip install argon2-cffi cryptography pyperclip
```

## Usage

Run the script using Python:

```bash
python password_manager.py
```

The application will open a GUI with the following tabs:

1. **Master Password**: Set or verify the master password.
2. **Add Password**: Store a new password for a platform.
3. **Get Password**: Retrieve a stored password.
4. **View Passwords**: See all stored passwords and perform database operations.

## Security Features

- **Master Password**: Uses Argon2 for secure password hashing.
- **Password Encryption**: Employs Fernet symmetric encryption from the `cryptography` library.
- **Secure Key Derivation**: Utilizes PBKDF2HMAC for key derivation from the master password.
- **Automatic Clipboard Clearing**: Clears the clipboard after 10 seconds when a password is copied.

## Database

The application uses SQLite to store encrypted passwords and the hashed master password. The database file is named `passwords.db` by default.

## Exporting and Importing

Passwords can be exported to and imported from encrypted files (.enc). This feature allows for secure backups and transfers between devices.

## Backup and Restore

The entire database can be backed up and restored, ensuring data persistence and easy transfer between systems.

## Logging

The application logs important events to a file named `password_manager.log`.

## Security Considerations

- Always use a strong, unique master password.
- Keep the database file (`passwords.db`) and any exported files secure.
- Be cautious when using the clipboard on shared systems.

## Contributing

Contributions to improve the security, functionality, or user interface of this password manager are welcome. Please submit pull requests or open issues on the GitHub repository.

## Disclaimer

This password manager is a demonstration project and may not be suitable for production use without further security audits and enhancements.
