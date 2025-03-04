# Secure File System (SFS)

A **Secure File System** project that offers:

- Encrypted file names and contents
- Unix-like group and permission model
- User authentication and access control
- Basic command-line operations (e.g., `pwd`, `ls`, `cd`, `mkdir`, `touch`, etc.)

## Features

- **Confidentiality**: All files and directories are stored in encrypted form.
- **Integrity**: Each file is protected from external tampering.
- **Multi-user Access**: Users can belong to groups and share files under Unix-like permissions.
- **CLI-Based**: Issue commands via a simple text-based interface.

## Technology Overview

- **Language**: Python
- **Encryption**: AES for content encryption, HMAC for integrity
- **Data Storage**: JSON, database, or file-based metadata (encrypted)
- **Authentication**: Password hashing (bcrypt or PBKDF2)

## Getting Started

1. **Clone** the repository.
2. **Install** dependencies as needed (`pip install -r requirements.txt` in Python).
3. **Run** the main application (`python sfs.py`).
4. **Create/Manage** users, groups, and files via CLI commands.

---

**Happy Securing!**
