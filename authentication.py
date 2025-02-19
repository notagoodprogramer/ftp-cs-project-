import json
import time
from pathlib import Path
from Crypto.Hash import SHA256
import jwt

SECRET_KEY = "very_secret"
USERS_FILE = "users.json"
HOME_DIR_ROOT = "file_perm_root"
PERMISSIONS_FILE = ".permissions.json"
SESSION_TIME = 3600

class AuthenticationManager:
    def __init__(self):
        self.users_file = Path(USERS_FILE)

    def load_users(self):
        if self.users_file.exists():
            with self.users_file.open("r") as f:
                return json.load(f)
        return {}

    def create_user(self, username: str, password: str) -> str:
        users = self.load_users()
        if username in users:
            return f"User '{username}' already exists."
        hash_obj = SHA256.new(password.encode())
        password_hash = hash_obj.hexdigest()
        user_home = Path(HOME_DIR_ROOT) / username
        user_home.mkdir(parents=True, exist_ok=True)
        
        permissions = {
            "owner": username,
            "dir_permissions": {
                username: ["read", "write"]
            },
            "files": {}
        }
        permissions_file = user_home / PERMISSIONS_FILE
        with permissions_file.open("w") as pf:
            json.dump(permissions, pf, indent=4)
        
        users[username] = {"password": password_hash, "home": str(user_home)}
        with self.users_file.open("w") as f:
            json.dump(users, f, indent=4)
        return f"User '{username}' created successfully. Home directory: {user_home}"
    def login(self, username: str, password: str):
        users = self.load_users()
        if username not in users:
            return False, "Invalid username."
        hash_obj = SHA256.new(password.encode())
        if hash_obj.hexdigest() != users[username]["password"]:
            return False, "Invalid password."
        payload = {"sub": username, "home": users[username]["home"], "exp": time.time() + SESSION_TIME}
        token = jwt.encode(payload, SECRET_KEY, algorithm="HS256")
        return True, token
