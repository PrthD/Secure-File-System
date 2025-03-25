"""
Module: filesystem.py
Description: Implements file/directory operations, including:
  - 'cd ..' navigation,
  - permission checks,
  - automatic detection of tampering (HMAC mismatch) or
    legitimate changes (valid HMAC but different) by other users.

Notes:
  - We store a dictionary of last-known HMACs for each home directory
    in memory only (lost if SFS restarts).
  - If you want to persist this data, you'd store it in metadata on disk.
"""

import logging
from typing import List, Dict
from .models import User, Directory, FileEntity
from .permission import has_permission
from .disk_storage import (
    write_directory_to_disk,
    write_file_to_disk,
    remove_directory_from_disk,
    remove_file_from_disk,
    scan_directory_recursive,
    load_file_from_disk
)
from .encryption import encrypt_data, decrypt_data
from .integrity import generate_hmac, verify_hmac

logger = logging.getLogger(__name__)


class FileSystem:
    def __init__(self, root_directory: Directory, key: bytes) -> None:
        self.root_directory = root_directory
        self.current_directory = root_directory
        self.key = key

        # Ephemeral map to track last-known content HMACs for each user's home directory
        # Key: Directory object (the user's home), Value: dict of {filename: lastKnownHMAC}
        self.last_known_hmacs_map: Dict[Directory, Dict[str, str]] = {}

    def pwd(self) -> str:
        return f"/{self.current_directory.dir_name}"

    def ls(self, user: User) -> List[str]:
        if not has_permission(user, self.current_directory, "read"):
            return []
        result = []
        # Subdirectories
        for sd in self.current_directory.subdirectories:
            result.append(sd.dir_name + "/")
        # Files
        for f in self.current_directory.files:
            if has_permission(user, f, "read"):
                result.append(f.file_name)
            else:
                if f.encrypted_file_name:
                    result.append(f.encrypted_file_name)
                else:
                    result.append("ENCRYPTED_FILE")
        return result

    def mkdir(self, user: User, dirname: str) -> bool:
        if not has_permission(user, self.current_directory, "write"):
            return False
        dirname = dirname.strip()
        new_dir = Directory(dirname, owner=user, permissions='user')
        self.current_directory.add_subdirectory(new_dir)
        write_directory_to_disk(new_dir, self.key)
        return True

    def touch(self, user: User, filename: str) -> bool:
        if not has_permission(user, self.current_directory, "write"):
            return False
        filename = filename.strip()
        new_file = FileEntity(filename, user, permissions='user')
        self.current_directory.add_file(new_file)
        write_file_to_disk(new_file, self.key, self.current_directory)
        return True

    def cd(self, user: User, dirname: str) -> bool:
        if dirname == "..":
            if self.current_directory.parent is not None:
                self.current_directory = self.current_directory.parent
                return True
            return False
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
        filename = filename.strip()
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
        old_name, new_name = old_name.strip(), new_name.strip()
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
                scan_directory_recursive(d, self.key, {})
                return True
        return False

    def rm(self, user: User, filename: str) -> bool:
        filename = filename.strip()
        for f in self.current_directory.files:
            if f.file_name == filename:
                if not has_permission(user, f, "write"):
                    return False
                self.current_directory.remove_file(f)
                remove_file_from_disk(f, self.current_directory)
                return True
        return False

    def rmdir(self, user: User, dirname: str) -> bool:
        dirname = dirname.strip()
        for sd in self.current_directory.subdirectories:
            if sd.dir_name == dirname:
                if not has_permission(user, sd, "write"):
                    return False
                if sd.files or sd.subdirectories:
                    return False
                self.current_directory.remove_subdirectory(sd)
                remove_directory_from_disk(sd)
                return True
        return False

    # CHANGED: Entire function replaced with an updated merging approach so that
    # corrupt files do not vanish and only newly discovered items are added.
    def check_user_home_integrity(self, user: User, user_home: Directory) -> None:
        """
        On login, we do two things:
          1) Detect new/missing/corrupted files or directories.
          2) Detect legitimate changes by an authorized user (valid HMAC changed).
        We only warn about corrupted or changed files; we do *not* remove them from user_home.
        """
        from copy import deepcopy
        from .integrity import verify_hmac
        from .encryption import decrypt_data

        if user_home not in self.last_known_hmacs_map:
            self.last_known_hmacs_map[user_home] = {}
        known_hmacs = self.last_known_hmacs_map[user_home]

        old_files = {f.file_name for f in user_home.files}
        old_subdirs = {d.dir_name for d in user_home.subdirectories}

        # Make a dummy clone and discover what's on disk.
        dummy_clone = deepcopy(user_home)
        user_map = {user.username: user}
        new_subdirs, new_files = scan_directory_recursive(
            dummy_clone, self.key, user_map)

        new_fileset = {f.file_name for f in dummy_clone.files}
        new_subdirsset = {d.dir_name for d in dummy_clone.subdirectories}

        missing_files = old_files - new_fileset
        missing_dirs = old_subdirs - new_subdirsset

        from .disk_storage import load_file_from_disk
        changed_authorized = []
        corrupted = []

        # Check each old file for corruption or authorized changes
        for old_f in user_home.files:
            fname = old_f.file_name
            if fname not in new_fileset:
                # It's missing on disk, so skip deeper checks
                continue
            if not old_f.encrypted_file_name:
                # Possibly a new empty file not fully persisted yet
                continue
            parent_enc = user_home.encrypted_dir_name or "home"
            reloaded = load_file_from_disk(
                old_f.encrypted_file_name, parent_enc, self.key)
            if not reloaded:
                # We couldn't decrypt or verify metadata => corrupted
                corrupted.append(fname)
                continue

            # If reloaded, verify content HMAC
            if reloaded.encrypted_content and reloaded.hmac:
                if not verify_hmac(reloaded.encrypted_content, reloaded.hmac, self.key):
                    corrupted.append(fname)
                    continue
                # If valid but differs from known, it's changed by an authorized user
                old_hmac = known_hmacs.get(fname)
                if old_hmac and old_hmac != reloaded.hmac:
                    changed_authorized.append(fname)
                # Update known HMAC
                known_hmacs[fname] = reloaded.hmac

        # ADDED: Merge newly discovered items into user_home
        # so brand-new files/dirs from disk appear for the user.
        for new_f in dummy_clone.files:
            if new_f.file_name not in old_files:
                user_home.files.append(new_f)
        for new_d in dummy_clone.subdirectories:
            if new_d.dir_name not in old_subdirs:
                user_home.subdirectories.append(new_d)

        # Summarize warnings
        if missing_files or missing_dirs or corrupted or changed_authorized:
            print("[!] Updates in your home directory:")
            for mf in missing_files:
                print(f"   - Missing file: {mf}")
            for md in missing_dirs:
                print(f"   - Missing directory: {md}")
            for cf in corrupted:
                print(f"   - Corrupted file: {cf}")
            for ca in changed_authorized:
                print(f"   - File changed by authorized user: {ca}")
