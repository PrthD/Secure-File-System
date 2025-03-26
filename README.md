# Secure File System (SFS)

A secure file system with encryption, access control, and integrity verification. Supports multi-user groups, Unix-like permissions, and a CLI for secure file operations.

---

## 📂 Project Overview

The **Secure File System (SFS)** is a command-line based file management system designed for untrusted environments. It integrates robust cryptographic techniques with Unix-style permission controls to provide secure multi-user file operations.

Key security pillars include:

- 🔒 **Confidentiality**: File names, contents, and metadata are encrypted.
- 🛡️ **Integrity**: HMAC-based tamper detection alerts users of unauthorized modifications.
- 🔑 **Access Control**: Role-based access with support for user/group/other permission levels.
- 👤 **Authentication**: Secure password handling using bcrypt hashing.

---

## 👨‍💻 Team

**Group Name**: The ByteKnights

- Het Bharatkumar Patel (SID: 1742431, CCID: hetbhara)
- Parth Dadhania (SID: 1722612, CCID: pdadhani)

---

## 🚀 Features

- ✅ Encrypted file and directory names & contents (Fernet AES)
- ✅ CLI-based interface with commands like `login`, `mkdir`, `cd`, `ls`, `touch`, `cat`, `echo`, `mv`, etc.
- ✅ Unix-like permission model (`user`, `group`, `all`)
- ✅ Integrity verification with SHA-256 HMAC
- ✅ Secure password storage (bcrypt)
- ✅ Admin capabilities for creating users and groups
- ✅ Corruption alerting for external file tampering

---

## 🧰 Technologies Used

| Category        | Technology/Tool         |
| --------------- | ----------------------- |
| Language        | Python                  |
| Encryption      | `cryptography` (Fernet) |
| Integrity Check | HMAC (SHA-256)          |
| Authentication  | `bcrypt`                |
| Data Storage    | Encrypted JSON files    |
| Version Control | Git + GitHub            |
| Automation      | `run.sh` bash script    |

---

## ⚙️ Setup Instructions

### 🔧 Requirements

- Python 3.8 or above
- Git / Bash-compatible terminal (Linux/macOS/Windows Git Bash)

### 🚀 Quick Start

```bash
# Clone the repository
git clone https://github.com/PrthD/Secure-File-System.git
cd Secure-File-System

# Make run script executable (Linux/macOS)
chmod +x run.sh

# Run the app
./run.sh
```

This will:

- Create a virtual environment (if not already created)
- Install dependencies from `requirements.txt`
- Launch the Secure File System CLI

---

## 🧪 Default Admin Credentials

```bash
Username: admin
Password: adminpass
```

Use this account to create users and groups via the `adduser` and `addgroup` commands.

---

## 📘 Example Commands

```bash
login admin adminpass
addgroup team1
adduser alice password123 team1
mkdir secure_folder
touch notes.txt
echo notes.txt Hello world!
cat notes.txt
chmod notes.txt group
logout
```

---

## 🧑‍🏫 User Roles

- **Admin**: Can create users/groups
- **User**: Can create/manage personal files and directories
- **Group**: Enables collaborative access via permission settings

---

## 🛡️ Security Highlights

- All data stored on disk (including filenames) is encrypted.
- HMAC-based integrity check detects tampering from outside SFS.
- External users see only encrypted content, preserving confidentiality.
- Permission checks enforced before all read/write operations.

---

**Happy Securing! 🔐**
