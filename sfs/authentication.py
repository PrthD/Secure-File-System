"""
Module: authentication.py
Description: Manages user authentication and group creation for the Secure File System.
             We allow an 'admin' user to create more users and groups.
"""

import bcrypt
import logging
from typing import Dict, Optional
from .models import User, Group

logger = logging.getLogger(__name__)


class AuthManager:
    """
    Manages user authentication and group management.
    """

    def __init__(self) -> None:
        self.users: Dict[str, User] = {}
        self.groups: Dict[str, Group] = {}

    def hash_password(self, password: str) -> str:
        hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        return hashed.decode('utf-8')

    def verify_password(self, plaintext: str, hashed: str) -> bool:
        return bcrypt.checkpw(plaintext.encode('utf-8'), hashed.encode('utf-8'))

    def create_user(self, username: str, password: str, group_name: Optional[str] = None, is_admin: bool = False) -> User:
        if username in self.users:
            raise ValueError(f"User '{username}' already exists.")

        password_hash = self.hash_password(password)
        new_user = User(username, password_hash, is_admin=is_admin)
        self.users[username] = new_user
        logger.info(f"User created: {new_user}")

        if group_name:
            grp = self.groups.get(group_name)
            if not grp:
                grp = self.create_group(group_name)
            grp.add_member(new_user)
            logger.info(f"Added user '{username}' to group '{group_name}'.")

        return new_user

    def login(self, username: str, password: str) -> bool:
        user = self.users.get(username)
        if not user:
            logger.warning(f"Login failed: User '{username}' not found.")
            return False
        if self.verify_password(password, user.password_hash):
            logger.info(f"User '{username}' logged in successfully.")
            return True
        else:
            logger.warning(
                f"Login failed: Incorrect password for user '{username}'.")
            return False

    def create_group(self, group_name: str) -> Group:
        if group_name in self.groups:
            raise ValueError(f"Group '{group_name}' already exists.")
        new_group = Group(group_name)
        self.groups[group_name] = new_group
        logger.info(f"Group created: {new_group}")
        return new_group

    def get_user(self, username: str) -> Optional[User]:
        return self.users.get(username)

    def get_group(self, group_name: str) -> Optional[Group]:
        return self.groups.get(group_name)
