"""
Module: filesystem.py
Description: Implements file/directory operations and includes a 'cd ..' feature plus
             showing unauthorized file names as encrypted names.
"""

import logging
from typing import List
from .models import User, Directory, FileEntity
from .permission import has_permission
from .disk_storage import (
    write_directory_to_disk,
    write_file_to_disk,
    remove_directory_from_disk,
    remove_file_from_disk,
    scan_directory_recursive
)
from .encryption import encrypt_data, decrypt_data
from .integrity import generate_hmac, verify_hmac

logger = logging.getLogger(__name__)


class FileSystem:
    def __init__(self, root_directory: Directory, key: bytes) -> None:
        self.root_directory = root_directory
        self.current_directory = root_directory
        self.key = key

    def pwd(self) -> str:
        # For a nicer approach, we could walk up parents to build a path like /home/User1/...
        # But for brevity, we only show "/<current_directory.dir_name>"
        return f"/{self.current_directory.dir_name}"

    def ls(self, user: User) -> List[str]:
        """
        Lists the contents of the current directory. If user has read permission on the directory,
        we show each subdirectory's plaintext name. For files:
          - If user has read permission on that file, we show the plaintext name.
          - Otherwise, we show the encrypted_file_name (like random gibberish).
        This matches the requirement that an unauthorized user sees encrypted names.
        """
        dir_obj = self.current_directory
        if not has_permission(user, dir_obj, "read"):
            return []  # no permission to even list

        # Build a list of names
        result = []
        # Subdirectories: we always show plaintext name if we can see the directory at all
        for sd in dir_obj.subdirectories:
            result.append(sd.dir_name + "/")

        # Files: show plaintext name if user has read permission; otherwise show encrypted
        for f in dir_obj.files:
            if has_permission(user, f, "read"):
                result.append(f.file_name)
            else:
                # fallback to the encrypted name if it exists
                if f.encrypted_file_name:
                    result.append(f.encrypted_file_name)
                else:
                    # if we haven't assigned an encrypted name yet, show placeholder
                    result.append("ENCRYPTED_FILE")
        return result

    def mkdir(self, user: User, dirname: str) -> bool:
        dir_obj = self.current_directory
        if not has_permission(user, dir_obj, "write"):
            return False
        new_dir = Directory(dirname, owner=user, permissions='user')
        dir_obj.add_subdirectory(new_dir)
        write_directory_to_disk(new_dir, self.key)
        return True

    def touch(self, user: User, filename: str) -> bool:
        dir_obj = self.current_directory
        if not has_permission(user, dir_obj, "write"):
            return False
        new_file = FileEntity(filename, user, permissions='user')
        dir_obj.add_file(new_file)
        # It's empty, so no content/HMAC
        write_file_to_disk(new_file, self.key, dir_obj)
        return True

    def cd(self, user: User, dirname: str) -> bool:
        """
        If dirname == "..", go up one level (if not at root).
        Otherwise, look for a subdirectory with name == dirname.
        """
        if dirname == "..":
            # If we have a parent and we are not already at root
            if self.current_directory.parent is not None:
                # Move up
                self.current_directory = self.current_directory.parent
                return True
            return False

        # normal cd
        for sd in self.current_directory.subdirectories:
            if sd.dir_name == dirname:
                if has_permission(user, sd, "read"):
                    self.current_directory = sd
                    return True
                return False
        return False

    def cat(self, user: User, filename: str) -> str:
        for f in self.current_directory.files:
            if f.file_name == filename:
                if not has_permission(user, f, "read"):
                    return "Access denied."
                if f.encrypted_content is None:
                    return "Empty File"
                if f.hmac and not verify_hmac(f.encrypted_content, f.hmac, self.key):
                    return f"Error: File '{filename}' is corrupted!"
                try:
                    return decrypt_data(f.encrypted_content, self.key)
                except Exception as e:
                    return f"Decryption error: {str(e)}"
        return f"File '{filename}' not found."

    def echo(self, user: User, filename: str, text: str) -> bool:
        for f in self.current_directory.files:
            if f.file_name == filename:
                if not has_permission(user, f, "write"):
                    return False
                enc_text = encrypt_data(text, self.key)
                hmac_val = generate_hmac(enc_text, self.key)
                f.encrypted_content = enc_text
                f.hmac = hmac_val
                write_file_to_disk(f, self.key, self.current_directory)
                return True
        return False

    def mv(self, user: User, old_name: str, new_name: str) -> bool:
        # rename file
        for f in self.current_directory.files:
            if f.file_name == old_name:
                if not has_permission(user, f, "write"):
                    return False
                remove_file_from_disk(f, self.current_directory)
                f.file_name = new_name
                f.encrypted_file_name = None
                f.file_name_hmac = None
                write_file_to_disk(f, self.key, self.current_directory)
                return True

        # rename directory
        for d in self.current_directory.subdirectories:
            if d.dir_name == old_name:
                if not has_permission(user, d, "write"):
                    return False
                remove_directory_from_disk(d)
                d.dir_name = new_name
                d.encrypted_dir_name = None
                d.dir_name_hmac = None
                write_directory_to_disk(d, self.key)
                # re-scan to restore its children
                scan_directory_recursive(d, self.key, {})
                return True

        return False

    def rm(self, user: User, filename: str) -> bool:
        for f in self.current_directory.files:
            if f.file_name == filename:
                if not has_permission(user, f, "write"):
                    return False
                self.current_directory.remove_file(f)
                remove_file_from_disk(f, self.current_directory)
                return True
        return False

    def rmdir(self, user: User, dirname: str) -> bool:
        for sd in self.current_directory.subdirectories:
            if sd.dir_name == dirname:
                if not has_permission(user, sd, "write"):
                    return False
                # Require empty
                if sd.files or sd.subdirectories:
                    return False
                self.current_directory.remove_subdirectory(sd)
                remove_directory_from_disk(sd)
                return True
        return False

    def check_user_home_integrity(self, user: User, user_home: Directory) -> None:
        """
        On login, re-scan the user's home directory from disk to detect tampering.
        If any file or directory disappeared (or was renamed), we warn the user.
        """
        from .disk_storage import scan_directory_recursive
        old_files = set(f.file_name for f in user_home.files)
        old_subdirs = set(d.dir_name for d in user_home.subdirectories)

        user_map = {user.username: user}  # minimal approach
        scan_directory_recursive(user_home, self.key, user_map)

        new_files = set(f.file_name for f in user_home.files)
        new_subdirs = set(d.dir_name for d in user_home.subdirectories)

        missing_files = old_files - new_files
        missing_dirs = old_subdirs - new_subdirs
        if missing_files or missing_dirs:
            print(
                "[!] Warning: Some files or directories in your home appear corrupted or renamed.")
            for mf in missing_files:
                print(f"  - Missing file: {mf}")
            for md in missing_dirs:
                print(f"  - Missing directory: {md}")
