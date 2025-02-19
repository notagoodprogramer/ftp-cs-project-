import json
from pathlib import Path

PERMISSIONS_FILE = ".permissions.json"

class PermissionManager:
    def __init__(self, username: str):
        self.username = username

    def has_permission(self, path: Path, permission: str) -> bool:
        permissions_file = (path if path.is_dir() else path.parent) / PERMISSIONS_FILE
        if not permissions_file.exists():
            return False
        with permissions_file.open("r") as f:
            permissions = json.load(f)
        if path.is_dir():
            dir_permissions = permissions.get("dir_permissions", {})
            user_permissions = dir_permissions.get(self.username, []) + dir_permissions.get("*", [])
            return permission in user_permissions
        file_permissions = permissions.get("files", {}).get(path.name, {}).get("permissions", {})
        user_permissions = file_permissions.get(self.username, []) + file_permissions.get("*", [])
        return permission in user_permissions
