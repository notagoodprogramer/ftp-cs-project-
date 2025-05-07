import json
import time
from pathlib import Path
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
import jwt
import binascii
from Crypto.PublicKey import RSA
from Config import ROOT_DIRECTORY, PERMISSIONS_FILE, SECRET_KEY, SESSION_TIME, USERS_FILE

RSA_KEY_SIZE = 2048

class AuthenticationManager:
    """
    Manages user authentication, registration, and RSA key management.

    Handles user creation, login verification, password hashing, and JWT token generation.
    """

    def __init__(self):
        """Initializes the AuthenticationManager with the path to the user database file."""
        self.users_file = Path(USERS_FILE)

    def load_users(self):
        """
        Loads user data from the USERS_FILE.

        Returns:
            dict: A dictionary of user credentials and metadata.
        """
        if self.users_file.exists():
            with self.users_file.open("r") as f:
                try:
                    return json.load(f)
                except json.JSONDecodeError:
                    return {}
        return {}

    def generate_rsa_keys(self):
        """
        Generates an RSA key pair and writes them to the 'keys' directory.

        Returns:
            str: Success message.
        """
        key = RSA.generate(RSA_KEY_SIZE)
        private_key = key.export_key()
        public_key = key.publickey().export_key()

        keys_dir = Path("keys")
        keys_dir.mkdir(exist_ok=True)

        with (keys_dir / "private.pem").open("wb") as f:
            f.write(private_key)
        with (keys_dir / "public.pem").open("wb") as f:
            f.write(public_key)

        return "RSA keys generated successfully."

    def create_user(self, username: str, password: str) -> str:
        """
        Creates a new user with hashed password and initializes their home directory.

        Args:
            username (str): The desired username.
            password (str): The desired password.

        Returns:
            str: Result message indicating success or failure.
        """
        users = self.load_users()
        if username in users:
            return f"User '{username}' already exists."

        salt = get_random_bytes(16)
        salt_hex = binascii.hexlify(salt).decode()
        hash_obj = SHA256.new(salt + password.encode())
        password_hash = hash_obj.hexdigest()

        user_home = Path(ROOT_DIRECTORY) / username
        user_home.mkdir(parents=True, exist_ok=True)

        shared_folder = user_home / "shared"
        shared_folder.mkdir(exist_ok=True)

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

        shared_perms = {
            "owner": username,
            "dir_permissions": {
                "*": ["read", "write"]
            },
            "files": {}
        }
        shared_perms_file = shared_folder / PERMISSIONS_FILE
        with shared_perms_file.open("w") as spf:
            json.dump(shared_perms, spf, indent=4)

        users[username] = {
            "salt": salt_hex,
            "password": password_hash,
            "home": str(user_home)
        }
        with self.users_file.open("w") as f:
            json.dump(users, f, indent=4)

        return f"User '{username}' created successfully. Home directory: {user_home}"

    def login(self, username: str, password: str):
        """
        Validates user credentials and returns a JWT token if successful.

        Args:
            username (str): The username.
            password (str): The plaintext password.

        Returns:
            tuple: (bool, str) where bool indicates success and str contains the token or error.
        """
        users = self.load_users()
        if username not in users:
            return False, "Invalid username."

        salt_hex = users[username].get("salt")
        if salt_hex is None:
            return False, "Salt missing for user."

        salt = binascii.unhexlify(salt_hex)
        hash_obj = SHA256.new(salt + password.encode())

        if hash_obj.hexdigest() != users[username]["password"]:
            return False, "Invalid password."

        payload = {
            "sub": username,
            "home": users[username]["home"],
            "exp": time.time() + SESSION_TIME
        }
        token = jwt.encode(payload, SECRET_KEY, algorithm="HS256")
        return True, token
