# Secure Password and Notes Manager

A robust desktop application for securely managing passwords and encrypted notes, built with Python and Tkinter.

## Features

### Password Management
- Store encrypted passwords with associated email and platform information
- Retrieve and decrypt stored passwords
- Copy retrieved passwords to clipboard
- View all stored password entries

### Secure Notes
- Create and store encrypted notes with titles, content, categories, and tags
- View, edit, and delete stored notes
- Search notes by category and tags
- Export notes to Markdown format
- Import notes from JSON format

### Security
- Master password protection for all operations
- Encryption using Fernet symmetric encryption
- Password hashing using Argon2
- Secure key derivation with PBKDF2

### Backup and Recovery
- Create encrypted backups of the database
- Restore data from backups
- Checksum verification for backups and restored data

### User Interface
- Tabbed interface for easy navigation between features
- Dark mode toggle for user preference

## Requirements

### Python
- Python 3.7 or higher

### Core Libraries
- tkinter: For the graphical user interface (usually comes pre-installed with Python)
- sqlite3: For database operations (usually comes pre-installed with Python)

### External Libraries
The following libraries are required and will be installed via pip:

- argon2-cffi
- cryptography
- pyperclip
- reportlab

## Installation

1. Ensure you have Python 3.7 or higher installed. You can download it from [python.org](https://www.python.org/downloads/).

2. Clone the repository:
   ```
   https://github.com/ADITYANAIR01/PASSWORD-MANAGER.git
   ```

3. Navigate to the project directory:
   ```
   cd secure-password-notes-manager
   ```

4. (Optional) Create and activate a virtual environment:
   ```
   python -m venv venv
   source venv/bin/activate  # On Windows, use `venv\Scripts\activate`
   ```

5. Install the required dependencies:
   ```
   pip install argon2-cffi cryptography pyperclip reportlab
   ```

   This command installs all the necessary external libraries as specified in the code.

6. If you're on Linux and encounter issues with tkinter, you may need to install it separately:
   - For Ubuntu/Debian:
     ```
     sudo apt-get install python3-tk
     ```
   - For Fedora:
     ```
     sudo dnf install python3-tkinter
     ```

## Usage

Run the application:
```
python secure_password_notes_manager.py
```

Upon first run, you'll be prompted to set a master password. This password will be required for all subsequent operations.

## Detailed Functionality

### Master Password
- Set and verify a master password for accessing the application
- Uses Argon2 for secure password hashing

### Password Management
- Add new passwords with associated email and platform information
- Retrieve stored passwords
- Copy retrieved passwords to clipboard
- View all stored passwords in a tree view

### Secure Notes
- Add new notes with title, content, category, and tags
- View, edit, and delete existing notes
- Search notes by category and tags
- Export notes to Markdown format
- Import notes from JSON format

### Backup and Recovery
- Create encrypted backups of the entire database
- Restore data from backups
- Verify integrity of backups and restored data using checksums

### User Interface
- Dark mode toggle for user preference
- Tabbed interface for easy navigation between features

## Security Measures

- All sensitive data is encrypted using Fernet symmetric encryption
- Master password is hashed using Argon2
- Secure key derivation using PBKDF2HMAC
- Salting is used for additional security
- Clipboard content is cleared after a short duration

## Troubleshooting

If you encounter any issues during installation or execution, try the following:

1. Ensure your Python version is 3.7 or higher:
   ```
   python --version
   ```

2. If you're using a virtual environment, make sure it's activated.

3. Verify that all dependencies are installed correctly:
   ```
   pip list
   ```

4. If you're on Windows and encounter DLL issues, ensure that you have the latest Microsoft Visual C++ Redistributable installed.

5. For Linux users, if you encounter "ModuleNotFoundError: No module named '_tkinter'", install the python3-tk package as mentioned in the installation steps.

## Improvements and Future Work

1. **Multi-factor Authentication**: Implement additional authentication methods for enhanced security.
2. **Cloud Sync**: Add the ability to securely sync data across devices.
3. **Password Strength Meter**: Incorporate a feature to evaluate and suggest improvements for password strength.
4. **Automatic Password Generation**: Include a secure random password generator.
5. **Audit Log**: Implement logging of all actions for security auditing.
6. **File Attachment**: Allow attaching encrypted files to notes.
7. **Mobile App**: Develop a companion mobile application for on-the-go access.
8. **Browser Extension**: Create a browser extension for easy password filling.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

