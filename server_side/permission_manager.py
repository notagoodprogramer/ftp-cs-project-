import json
from pathlib import Path
from Config import PERMISSIONS_FILE

class PermissionManager:
    """
    Manages user permissions for file and directory access.

    Permissions are defined in a JSON file located inside each directory.
    Supports checking read/write/etc. access for both individual files and directories.
    """

    def __init__(self, username: str):
        """
        Initializes the manager with a username.

        Args:
            username (str): The current user's username.
        """
        self.username = username

    def has_permission(self, path: Path, permission: str) -> bool:
        """
        Checks if the user has a specific permission on a file or directory.

        Args:
            path (Path): The target file or directory.
            permission (str): The permission to check (e.g., 'read', 'write').

        Returns:
            bool: True if permission is granted, False otherwise.
        """
        permissions_file = (path if path.is_dir() else path.parent) / PERMISSIONS_FILE
        if not permissions_file.exists():
            return False

        with permissions_file.open("r") as f:
            permissions = json.load(f)

        if path.is_dir():
            dir_permissions = permissions.get("dir_permissions", {})
            user_permissions = dir_permissions.get(self.username, []) + dir_permissions.get("*", [])
            return permission in user_permissions
        else:
            file_section = permissions.get("files", {}).get(path.name)
            if file_section is not None:
                file_permissions = file_section.get("permissions", {})
                user_permissions = file_permissions.get(self.username, []) + file_permissions.get("*", [])
                if permission in user_permissions:
                    return True
            dir_permissions = permissions.get("dir_permissions", {})
            user_permissions = dir_permissions.get(self.username, []) + dir_permissions.get("*", [])
            return permission in user_permissions