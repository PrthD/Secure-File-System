"""
Module: permission.py
Description: Checks read/write permissions for files or directories,
             and allows changing permissions if you're the owner.
"""

import logging
from .models import FileEntity, Directory, User

logger = logging.getLogger(__name__)


def has_permission(user: User, entity, operation: str) -> bool:
    """
    If entity is a FileEntity or Directory, return whether 'user' can do 'read' or 'write'.
    Permission rules:
       'user'  => only owner
       'group' => owner or same group
       'all'   => any user
    """
    if operation not in ["read", "write"]:
        logger.error("Operation must be 'read' or 'write'.")
        return False

    if isinstance(entity, FileEntity):
        owner = entity.owner
        perm = entity.permissions
    elif isinstance(entity, Directory):
        owner = entity.owner
        perm = entity.permissions
    else:
        logger.error("Unknown entity type for permission check.")
        return False

    if not owner:
        logger.warning("Entity has no owner set; defaulting to deny.")
        return False

    if perm == "user":
        return (user.username == owner.username)
    elif perm == "group":
        if user.username == owner.username:
            return True
        if user.group and owner.group:
            return (user.group.group_name == owner.group.group_name)
        return False
    elif perm == "all":
        return True
    else:
        logger.warning(f"Invalid permission setting: {perm}")
        return False


def change_permission(entity, new_permission: str, user: User) -> bool:
    """
    Changes the permission of a file or directory if user is the owner.
    new_permission must be 'user', 'group', or 'all'.
    """
    if isinstance(entity, FileEntity):
        owner = entity.owner
    elif isinstance(entity, Directory):
        owner = entity.owner
    else:
        logger.error("Unknown entity type for permission change.")
        return False

    if user.username != owner.username:
        logger.warning("User is not the owner; cannot change permission.")
        return False

    new_perm = new_permission.lower()
    if new_perm not in ["user", "group", "all"]:
        logger.error(f"Invalid permission: {new_perm}")
        return False

    if isinstance(entity, FileEntity):
        entity.permissions = new_perm
        logger.info(
            f"File permission changed to {new_perm} by {user.username}")
    else:
        entity.permissions = new_perm
        logger.info(
            f"Directory permission changed to {new_perm} by {user.username}")
    return True
