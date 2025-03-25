"""
Module: disk_storage.py
Description: Writes/reads directories and files to disk, using encryption for subdirectories,
             but preserving a plaintext "home" folder under file_system/.
"""

import os
import json
import base64
import logging
from typing import Optional, Dict
from .models import User, FileEntity, Directory
from .encryption import encrypt_data, decrypt_data
from .integrity import generate_hmac, verify_hmac

logger = logging.getLogger(__name__)

SFS_DATA_FOLDER = "file_system"


def safe_b64encode(s: str) -> str:
    raw = s.encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("utf-8")


def safe_b64decode(s: str) -> str:
    raw = base64.urlsafe_b64decode(s.encode("utf-8"))
    return raw.decode("utf-8")


def encrypt_name(plaintext: str, key: bytes) -> str:
    """
    Encrypt the plaintext name, then base64-URL-encode it for safe filesystem usage.
    """
    ciphertext = encrypt_data(plaintext, key)
    return safe_b64encode(ciphertext)


def decrypt_name(enc: str, key: bytes) -> Optional[str]:
    """
    Reverse of encrypt_name: decode from base64, then decrypt with Fernet.
    """
    try:
        ct = safe_b64decode(enc)
        pt = decrypt_data(ct, key)
        return pt
    except Exception as e:
        logger.warning(f"Failed to decrypt name '{enc}': {e}")
        return None


def get_metadata_path(dir_path: str) -> str:
    return os.path.join(dir_path, ".meta.json")


def get_directory_on_disk_path(directory: Directory) -> str:
    """
    Recursively determine the on-disk path for 'directory'.
    - If directory is the root home (dir_name == 'home' and parent is None),
      we store it in file_system/home (plaintext).
    - Otherwise, we compute the parent's path, then join the directory's
      encrypted_dir_name.
    """
    # Base case: if it's the root home
    if directory.dir_name == "home" and directory.parent is None:
        return os.path.join(SFS_DATA_FOLDER, "home")

    # Otherwise, find the parent's on-disk path
    if directory.parent is None:
        # no parent => store in file_system/<encrypted_dir_name>
        # (this scenario is rare, but let's handle it)
        return os.path.join(SFS_DATA_FOLDER, directory.encrypted_dir_name or "unknown")

    parent_path = get_directory_on_disk_path(directory.parent)
    return os.path.join(parent_path, directory.encrypted_dir_name or "unknown")


def get_file_on_disk_path(file_entity: FileEntity, parent_dir: Directory) -> str:
    """
    Determine the on-disk path for this file, which is a subfolder named by
    file_entity.encrypted_file_name inside the parent's path.
    """
    parent_path = get_directory_on_disk_path(parent_dir)
    return os.path.join(parent_path, file_entity.encrypted_file_name or "unknown")


def write_directory_to_disk(directory: Directory, key: bytes) -> None:
    """
    If directory is the special root "home" with no parent, store as file_system/home (no encryption).
    Otherwise, encrypt its name and store it inside the parent's path.
    """
    # If this is the root directory named "home" (parent=None), skip encryption
    is_root_home = (directory.dir_name == "home" and directory.parent is None)

    if is_root_home:
        directory.encrypted_dir_name = "home"
        directory.dir_name_hmac = None
    else:
        if directory.encrypted_dir_name is None:
            directory.encrypted_dir_name = encrypt_name(
                directory.dir_name, key)
            directory.dir_name_hmac = generate_hmac(directory.dir_name, key)

    # Now create the folder
    dir_path = get_directory_on_disk_path(directory)
    os.makedirs(dir_path, exist_ok=True)

    meta = {
        "type": "directory",
        "permissions": directory.permissions,
        "owner": directory.owner.username if directory.owner else None,
        "dir_name_hmac": directory.dir_name_hmac
    }
    with open(get_metadata_path(dir_path), "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2)


def write_file_to_disk(file_entity: FileEntity, key: bytes, parent_dir: Directory) -> None:
    """
    Create a subfolder for the file, with .meta.json inside.
    The parent directory path is determined by get_directory_on_disk_path(...).
    """
    if file_entity.encrypted_file_name is None:
        file_entity.encrypted_file_name = encrypt_name(
            file_entity.file_name, key)
        file_entity.file_name_hmac = generate_hmac(file_entity.file_name, key)

    file_dir_path = get_file_on_disk_path(file_entity, parent_dir)
    os.makedirs(file_dir_path, exist_ok=True)

    meta = {
        "type": "file",
        "permissions": file_entity.permissions,
        "owner": file_entity.owner.username if file_entity.owner else None,
        "file_name_hmac": file_entity.file_name_hmac,
        "encrypted_content": file_entity.encrypted_content,
        "content_hmac": file_entity.hmac
    }
    with open(get_metadata_path(file_dir_path), "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2)


def remove_directory_from_disk(directory: Directory) -> None:
    import shutil
    if directory.encrypted_dir_name is None:
        return
    dir_path = get_directory_on_disk_path(directory)
    shutil.rmtree(dir_path, ignore_errors=True)


def remove_file_from_disk(file_entity: FileEntity, parent_dir: Directory) -> None:
    import shutil
    if not file_entity.encrypted_file_name:
        return
    file_path = get_file_on_disk_path(file_entity, parent_dir)
    shutil.rmtree(file_path, ignore_errors=True)


def load_directory_from_disk(encrypted_dir_name: str, key: bytes) -> Optional[Directory]:
    """
    If encrypted_dir_name == "home", we skip decryption and treat it as the root directory.
    Otherwise, decrypt & verify HMAC.
    """
    dir_path = os.path.join(SFS_DATA_FOLDER, encrypted_dir_name)
    meta_file = get_metadata_path(dir_path)
    if not os.path.exists(meta_file):
        return None
    try:
        with open(meta_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        if data.get("type") != "directory":
            return None

        # If it's "home", skip encryption checks
        if encrypted_dir_name == "home":
            d = Directory("home", owner=None,
                          permissions=data.get("permissions", "all"))
            d.encrypted_dir_name = "home"
            d.owner_name = data.get("owner")
            return d

        # Otherwise do normal decrypt
        ptname = decrypt_name(encrypted_dir_name, key)
        if not ptname:
            return None
        dir_hmac = data.get("dir_name_hmac", "")
        if not verify_hmac(ptname, dir_hmac, key):
            logger.warning(f"Directory HMAC mismatch for {encrypted_dir_name}")
            return None

        d = Directory(ptname, owner=None,
                      permissions=data.get("permissions", "user"))
        d.encrypted_dir_name = encrypted_dir_name
        d.dir_name_hmac = dir_hmac
        d.owner_name = data.get("owner")
        return d
    except Exception as e:
        logger.warning(f"Failed to load directory: {e}")
        return None


def load_file_from_disk(encrypted_file_name: str, parent_encrypted_dir: str, key: bytes) -> Optional[FileEntity]:
    file_dir = os.path.join(
        SFS_DATA_FOLDER, parent_encrypted_dir, encrypted_file_name)
    meta_file = get_metadata_path(file_dir)
    if not os.path.exists(meta_file):
        return None
    try:
        with open(meta_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        if data.get("type") != "file":
            return None
        ptname = decrypt_name(encrypted_file_name, key)
        if not ptname:
            return None
        fname_hmac = data.get("file_name_hmac", "")
        if not verify_hmac(ptname, fname_hmac, key):
            logger.warning(f"File name HMAC mismatch: {encrypted_file_name}")
            return None

        fe = FileEntity(ptname, owner=None,
                        permissions=data.get("permissions", "user"))
        fe.encrypted_file_name = encrypted_file_name
        fe.file_name_hmac = fname_hmac
        fe.encrypted_content = data.get("encrypted_content")
        fe.hmac = data.get("content_hmac")
        fe.owner_name = data.get("owner")
        return fe
    except Exception as e:
        logger.warning(f"Failed to load file: {e}")
        return None


def scan_directory_recursive(directory: Directory, key: bytes, user_map: Dict[str, User]) -> None:
    """
    Recursively load subdirectories/files from disk. We'll attach the correct .parent references.
    """
    if not directory.encrypted_dir_name:
        return

    if directory.encrypted_dir_name == "home" and directory.parent is None:
        dir_path = os.path.join(SFS_DATA_FOLDER, "home")
    else:
        parent_path = get_directory_on_disk_path(
            directory.parent) if directory.parent else SFS_DATA_FOLDER
        dir_path = os.path.join(parent_path, directory.encrypted_dir_name)

    if not os.path.isdir(dir_path):
        return

    # Clear out existing
    directory.files = []
    directory.subdirectories = []

    for item in os.listdir(dir_path):
        if item == ".meta.json":
            continue
        fullp = os.path.join(dir_path, item)
        meta_file = os.path.join(fullp, ".meta.json")
        if not os.path.exists(meta_file):
            continue
        with open(meta_file, "r", encoding="utf-8") as f:
            meta = json.load(f)
        ttype = meta.get("type")
        if ttype == "directory":
            subdir = load_directory_from_disk(item, key)
            if subdir:
                subdir.parent = directory
                if subdir.owner_name and subdir.owner_name in user_map:
                    subdir.owner = user_map[subdir.owner_name]
                directory.subdirectories.append(subdir)
                scan_directory_recursive(subdir, key, user_map)
        elif ttype == "file":
            fe = load_file_from_disk(item, directory.encrypted_dir_name, key)
            if fe:
                if fe.owner_name and fe.owner_name in user_map:
                    fe.owner = user_map[fe.owner_name]
                directory.files.append(fe)
        else:
            logger.warning(f"Unknown object type in {meta_file}")
