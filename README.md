# Secure Password Manager

A Python-based secure password manager with a graphical user interface using Tkinter.

## Features

- Secure storage of passwords using encryption
- Master password protection
- Add and retrieve passwords
- View all stored passwords
- Export and import password data
- Clipboard integration with auto-clear functionality
- Keyboard shortcuts for quick access to common functions

## Installation

1. Clone the repository:
   ```
   git clone https://github.com/yourusername/secure-password-manager.git
   ```

2. Install the required packages:
   ```
   pip install tkinter sqlite3 pyperclip argon2-cffi cryptography
   ```

## Usage

Run the script:

```
python password_manager.py
```

### Keyboard Shortcuts

- `Ctrl+N`: Add a new password
- `Ctrl+R`: Retrieve a password
- `Ctrl+E`: Export passwords
- `Ctrl+I`: Import passwords

## Security Features

- Master password hashed using Argon2
- Individual passwords encrypted using Fernet (AES-128 in CBC mode with PKCS7 padding)
- PBKDF2 key derivation for encryption key
- Automatic clipboard clearing after 10 seconds

## Code Structure

- `PasswordDatabase`: Handles database operations
- `PasswordManager`: Manages the GUI and user interactions

## Recent Improvements

1. Added keyboard shortcuts for common operations
2. Streamlined code by removing unnecessary package installation checks
3. Focused on core password management features by removing backup and restore functionality
4. Improved code organization and readability
5. Simplified UI setup for easier maintenance

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the [LICENSE.md](LICENSE.md) file for details.

## Disclaimer

This password manager is a demonstration project and has not undergone a professional security audit. Use at your own risk.
