"""
Module: models.py
Description: Data models for the Secure File System (SFS).
"""

from typing import List, Optional


class User:
    def __init__(self, username: str, password_hash: str, is_admin: bool = False) -> None:
        self.username = username
        self.password_hash = password_hash
        self.group: Optional['Group'] = None
        self.is_admin = is_admin

    def set_password(self, new_password_hash: str) -> None:
        self.password_hash = new_password_hash

    def __repr__(self) -> str:
        return f"User(username={self.username}, admin={self.is_admin})"


class Group:
    def __init__(self, group_name: str) -> None:
        self.group_name = group_name
        self.members: List[User] = []

    def add_member(self, user: User) -> None:
        if user not in self.members:
            self.members.append(user)
            user.group = self

    def remove_member(self, user: User) -> None:
        if user in self.members:
            self.members.remove(user)
            user.group = None

    def __repr__(self) -> str:
        member_names = [u.username for u in self.members]
        return f"Group(name={self.group_name}, members={member_names})"


class FileEntity:
    def __init__(self, file_name: str, owner: 'User', permissions: str = 'user') -> None:
        self.file_name = file_name
        self.owner = owner
        self.permissions = permissions  # 'user', 'group', 'all'

        self.encrypted_content: Optional[str] = None
        self.hmac: Optional[str] = None
        self.encrypted_file_name: Optional[str] = None
        self.file_name_hmac: Optional[str] = None
        self.owner_name: Optional[str] = None  # for disk loading

    def set_content(self, encrypted_content: str, hmac: str) -> None:
        self.encrypted_content = encrypted_content
        self.hmac = hmac

    def __repr__(self) -> str:
        return f"FileEntity(name={self.file_name}, owner={self.owner.username}, perms={self.permissions})"


class Directory:
    def __init__(self, dir_name: str, owner: Optional['User'] = None, permissions: str = 'user') -> None:
        self.dir_name = dir_name
        self.owner = owner
        self.permissions = permissions  # 'user', 'group', 'all'

        self.files: List[FileEntity] = []
        self.subdirectories: List['Directory'] = []

        # For on-disk encryption
        self.encrypted_dir_name: Optional[str] = None
        self.dir_name_hmac: Optional[str] = None
        self.owner_name: Optional[str] = None

        # Added: reference to parent Directory for cd ..
        self.parent: Optional['Directory'] = None

    def add_file(self, file_entity: FileEntity) -> None:
        self.files.append(file_entity)

    def remove_file(self, file_entity: FileEntity) -> None:
        if file_entity in self.files:
            self.files.remove(file_entity)

    def add_subdirectory(self, subdir: 'Directory') -> None:
        subdir.parent = self
        self.subdirectories.append(subdir)

    def remove_subdirectory(self, subdir: 'Directory') -> None:
        if subdir in self.subdirectories:
            self.subdirectories.remove(subdir)

    def list_contents(self) -> List[str]:
        """
        Return the plaintext names of files/subdirectories in this directory.
        """
        file_names = [f.file_name for f in self.files]
        subdir_names = [d.dir_name for d in self.subdirectories]
        return file_names + subdir_names

    def __repr__(self) -> str:
        return f"Directory(name={self.dir_name}, files={len(self.files)}, subdirs={len(self.subdirectories)})"
