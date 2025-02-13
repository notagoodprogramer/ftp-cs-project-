from pathlib import Path
from shutil import rmtree
from socket import socket, AF_INET, SOCK_STREAM
from threading import Thread
from cmd import Cmd
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Security import SecurityHandler
import json
from Crypto.Hash import SHA256
import time
import jwt
SECRET_KEY = "very_secret"
USERS_FILE = "users.json"
PERMISSIONS_FILE = ".permissions.json"
HOME_DIR_ROOT = "file_perm_root"  

IP = "127.0.0.1"
PORT = 12345

RSA_KEY_SIZE = 2048
AES_KEY_SIZE = 32
IV_SIZE = 16
CHUNK_SIZE = 4096
def get_available_port() -> int:
    """Get an available port for file transfer."""
    with socket(AF_INET, SOCK_STREAM) as temp_socket:
        temp_socket.bind((IP, 0))
        return temp_socket.getsockname()[1]

class FTPHandler(Cmd):
    """FTPHandler implements a command-line based FTP server."""

    prompt = ""

    def __init__(self, root: str) -> None:
        """Initialize the FTPHandler.

        Args:
            root (str): The root directory for the FTP server.
        """
        super().__init__()
        self.root = Path(root).resolve()
        self.current_dir = None
        self.username = None
        self.setup_root_permissions()
        self.security = SecurityHandler()

    def setup_root_permissions(self) -> None:
        """Set up root permissions if the permissions file does not exist."""
        permissions_file = self.root / PERMISSIONS_FILE
        if not permissions_file.exists():
            permissions = {
                "owner": "admin",
                "dir_permissions": {},
                "files": {}
            }
            with permissions_file.open("w") as f:
                json.dump(permissions, f, indent=4)
   
    def perform_handshake(self, client_socket: socket):
        """Perform RSA-AES key exchange with the client."""
        private_key_path = Path("keys/private.pem")
        if not private_key_path.exists():
            raise FileNotFoundError("Missing private.pem! Run the server once to generate keys.")

        with private_key_path.open("rb") as f:
            self.security.rsa_private_key = RSA.import_key(f.read())

        
        encrypted_aes_size = int.from_bytes(client_socket.recv(4), "big")
        encrypted_aes = client_socket.recv(encrypted_aes_size)

        
        self.security.decrypt_aes_key(encrypted_aes)


    def handle_connection(self, client_socket: socket) -> None:
        """Handle a client connection with JWT validation."""
        self.client_socket = client_socket
        self.perform_handshake(client_socket)

        while True:
            header = self.client_socket.recv(4)
            if not header:
                break
            data_size = int.from_bytes(header, byteorder="big")

            encrypted_command = self.receive_data(self.client_socket, data_size)
            decrypted_command = self.security.decrypt_message(encrypted_command)

            print(f"[SERVER DEBUG] Received command: {decrypted_command}")

            if decrypted_command.lower().startswith("createuser"):
                self.onecmd(decrypted_command)
                continue  

            if decrypted_command.lower().startswith("login"):
                self.onecmd(decrypted_command)
                continue  

            if decrypted_command.lower().startswith("logout"):
                self.onecmd(decrypted_command)
                continue  

            if self.username is None:
                self.send_response("Authentication required. Please log in.")
                continue

            if not decrypted_command.startswith("TOKEN"):
                self.send_response("Authentication required. Please log in.")
                continue

            try:
                _, token, command = decrypted_command.split(" ", 2)
                decoded = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
                self.username = decoded["sub"]
                self.current_dir = Path(decoded["home"])
            except jwt.ExpiredSignatureError:
                self.send_response("Session expired. Please log in again.")
                continue
            except jwt.InvalidTokenError:
                self.send_response("Invalid token. Please log in again.")
                continue
            except ValueError:
                self.send_response("Malformed token. Please log in again.")
                continue

            if command.lower() == "quit":
                self.send_response("Goodbye!")
                break

            self.onecmd(command)



    def send_response(self, response: str) -> None:
        """Encrypt and send a response to the client."""
        encrypted_response = self.security.encrypt_message(response)
        self.client_socket.sendall(len(encrypted_response).to_bytes(4, "big"))
        self.client_socket.sendall(encrypted_response)  

    def receive_data(self, conn: socket, size: int) -> bytes:
        """Receive raw data from the specified socket."""
        data = b""
        while len(data) < size:
            packet = conn.recv(size - len(data))  
            if not packet:
                raise ConnectionError("Connection closed by client.")
            data += packet

        if len(data) != size:
            raise ValueError(f"Expected {size} bytes, but only received {len(data)} bytes.")
        
        return data  


     
    def precmd(self, line: str) -> str:
        """Strip the line before executing it."""
        return line.strip()

    def onecmd(self, line: str) -> bool:
        """Execute a single command.

        Args:
            line (str): The command line input.

        Returns:
            bool: Whether to stop the command loop.
        """
        if not line.strip():
            return False

        command, _, arg = line.partition(" ")
        command = command.upper()

        method = getattr(self, f"do_{command}", None)

        if method:
            return method(arg)
        else:
            self.default(line)
            return False

    def default(self, line: str) -> None:
        """Handle unknown commands."""
        self.send_response(f"Unknown command: {line.split()[0] if line else ''}")


    def has_permission(self, path: Path, permission: str) -> bool:
        """Check if the user has a specific permission on a path.

        Args:
            path (Path): The path to check.
            permission (str): The permission to check for.

        Returns:
            bool: True if the user has the permission, False otherwise.
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

        file_permissions = permissions.get("files", {}).get(path.name, {}).get("permissions", {})
        user_permissions = file_permissions.get(self.username, []) + file_permissions.get("*", [])
        return permission in file_permissions

    def do_LOGIN(self, args: str) -> None:
        """Authenticate a user using stored credentials."""
        if self.username is not None and self.username.strip() != "":
            self.send_response("You are already logged in.")
            return

        parts = args.split(" ", 1)  
        if len(parts) != 2:
            self.send_response("Usage: LOGIN <username> <password>")
            return

        username, password = parts
        credentials_file = Path(USERS_FILE)

        if not credentials_file.exists():
            self.send_response("No users found. Please create an account first.")
            return

        with credentials_file.open("r") as f:
            users = json.load(f)

        if username not in users:
            self.send_response("Invalid username.")
            return

        hash_obj = SHA256.new(password.encode())
        entered_hash = hash_obj.hexdigest()

        stored_hash = users[username]["password"]

        if entered_hash != stored_hash:
            self.send_response("Invalid password.")
            return

        self.username = username
        self.current_dir = Path(users[username]["home"])

        payload = {
            "sub": username,  
            "home": users[username]["home"],
            "exp": time.time() + 3600  
        }
        
        token = jwt.encode(payload, SECRET_KEY, algorithm="HS256")  

        self.send_response(f"SUCCESS {token} | Welcome, {username}. Home directory: {self.current_dir}")

    def do_LOGOUT(self, arg: str) -> None:
        """Log out the current user and clear session data."""
        if self.username is None:
            self.send_response("You are not logged in.")
            return

        self.username = None
        self.current_dir = None

        self.send_response("SUCCESS Logged out successfully. Please log in again.")


    def do_CREATEUSER(self, args: str) -> None:
        """Create a new user, hash the password, and set up a home directory with permissions."""
        parts = args.split(" ", 1)  
        if len(parts) != 2:
            self.send_response("Usage: CREATEUSER <username> <password>")
            return

        username, password = parts
        credentials_file = Path(USERS_FILE)

        if credentials_file.exists():
            with credentials_file.open("r") as f:
                users = json.load(f)
        else:
            users = {}

        if username in users:
            self.send_response(f"User '{username}' already exists.")
            return

        hash_obj = SHA256.new(password.encode())
        password_hash = hash_obj.hexdigest()

        user_home = Path(HOME_DIR_ROOT) / username
        user_home.mkdir(parents=True, exist_ok=True)  

        permissions_data = {
            "owner": username,
            "dir_permissions": {
                username: ["read", "write", "mkdir", "delete", "access"]
            },
            "files": {}
        }
        with (user_home / PERMISSIONS_FILE).open("w") as f:
            json.dump(permissions_data, f, indent=4)

        users[username] = {"password": password_hash, "home": str(user_home)}

        with credentials_file.open("w") as f:
            json.dump(users, f, indent=4)

        self.send_response(f"User '{username}' created successfully. Home directory: {user_home}")

    def do_LIST(self, arg: str) -> None:
        """List files in the current directory."""
        if self.current_dir is None:
            self.send_response("You must log in first using the LOGIN command.")
            return

        if not self.has_permission(self.current_dir, "read"):
            self.send_response("Access denied: You do not have permission to list files in this directory.")
            return

        files = "\r\n".join(
            f.name for f in self.current_dir.iterdir() if f.name != PERMISSIONS_FILE
        )
        self.send_response(f"The files in the current directory are:\r\n{files}")

    def do_CWD(self, arg: str) -> None:
        """Change the current working directory."""
        if self.current_dir is None:
            self.send_response("You must log in first using the LOGIN command.")
            return

        if not arg:
            self.send_response("CWD command requires a target directory.")
            return

        target = arg.strip()
        if target == "..":
            target_path = self.current_dir.parent
        else:
            target_path = self.current_dir / target

        if not target_path.is_dir():
            self.send_response(f"Directory '{target}' does not exist.")
            return

        if not self.has_permission(target_path, "access"):
            self.send_response("Access denied: You do not have permission to access this directory.")
            return

        self.current_dir = target_path
        self.send_response(f"Changed working directory to {self.current_dir.relative_to(self.root / self.username)}.")

    def do_MKDIR(self, arg: str) -> None:
        """Create a new directory."""
        if self.current_dir is None:
            self.send_response("You must log in first using the LOGIN command.")
            return

        if not arg:
            self.send_response("MKDIR command requires a directory name.")
            return

        if arg.strip() == PERMISSIONS_FILE:
            self.send_response("Access denied: Cannot create a directory with this name.")
            return

        if not self.has_permission(self.current_dir, "mkdir"):
            self.send_response("Access denied: You do not have permission to create directories here.")
            return

        dir_path = self.current_dir / arg.strip()
        dir_path.mkdir(exist_ok=True)
        parent_permissions_file = self.current_dir / PERMISSIONS_FILE
        new_permissions_file = dir_path / PERMISSIONS_FILE

        if parent_permissions_file.exists():
            with parent_permissions_file.open("r") as f:
                parent_permissions = json.load(f)

            with new_permissions_file.open("w") as f:
                json.dump(parent_permissions, f, indent=4)

        self.send_response(f"Directory '{arg}' created successfully.")

    def do_DELETE(self, arg: str) -> None:
        """Delete a file or directory."""
        if self.current_dir is None:
            self.send_response("You must log in first using the LOGIN command.")
            return

        if not arg:
            self.send_response("DELETE command requires a target file or directory.")
            return

        target = (self.current_dir / arg.strip()).resolve()

        if target.name == PERMISSIONS_FILE:
            self.send_response("Access denied: Cannot delete the permissions file.")
            return

        if not self.has_permission(target.parent, "delete"):
            self.send_response("Access denied: You do not have permission to delete items here.")
            return

        if target.is_file():
            target.unlink()
            self.send_response(f"File '{arg}' deleted successfully.")
        elif target.is_dir():
            rmtree(target)
            self.send_response(f"Directory '{arg}' deleted successfully.")
        else:
            self.send_response(f"Target '{arg}' does not exist.")


    def do_UPLOAD(self, filename: str) -> None:
        """Prepare for an upload request from a client."""
        if self.current_dir is None:
            self.send_response("You must log in first using the LOGIN command.")
            return

        if not filename:
            self.send_response("UPLOAD command requires a filename.")
            return

        port = get_available_port()
        self.send_response(f"READY {port}")
        Thread(target=self.handle_upload, args=(port,)).start()

    def handle_upload(self, port: int) -> None:
        """Handle the upload process for a file."""
        with socket(AF_INET, SOCK_STREAM) as upload_socket:
            upload_socket.bind((IP, port))
            upload_socket.listen(1)
            conn, _ = upload_socket.accept()
            with conn:
                header_size = int.from_bytes(self.receive_data(conn, 4), byteorder="big")
                encrypted_header = self.receive_data(conn, header_size)
                decrypted_header = self.security.decrypt_message(encrypted_header)
                file_name, file_size_str = decrypted_header.split("|")
                file_size = int(file_size_str)

                file_path = self.current_dir / file_name
                with file_path.open("wb") as f:
                    remaining = file_size
                    while remaining > 0:
                        chunk_size = int.from_bytes(self.receive_data(conn, 4), byteorder="big")
                        encrypted_chunk = self.receive_data(conn, chunk_size)
                        decrypted_chunk = self.security.decrypt_file_chunk(encrypted_chunk)
                        f.write(decrypted_chunk)
                        remaining -= len(decrypted_chunk)

                conn.sendall(b"Upload complete.")


    def do_DOWNLOAD(self, filename: str) -> None:
        """Prepare for a download request from a client."""
        if self.current_dir is None:
            self.send_response("You must log in first using the LOGIN command.")
            return

        if not filename:
            self.send_response("DOWNLOAD command requires a filename")
            return

        file_path = self.current_dir / filename.strip()
        if not file_path.is_file():
            self.send_response(f"File '{filename}' does not exist.")
            return

        port = get_available_port()
        self.send_response(f"READY {port}")
        Thread(target=self.handle_download, args=(file_path, port)).start()

    def handle_download(self, file_path: Path, port: int) -> None:
        """Handle the download process for a file."""
        with socket(AF_INET, SOCK_STREAM) as download_socket:
            download_socket.bind((IP, port))
            download_socket.listen(1)
            conn, _ = download_socket.accept()
            with conn:
                file_size = file_path.stat().st_size
                header = f"{file_path.name}|{file_size}"
                encrypted_header = self.security.encrypt_message(header)

                conn.sendall(len(encrypted_header).to_bytes(4, byteorder="big"))
                conn.sendall(encrypted_header)

                with file_path.open("rb") as f:
                    while chunk := f.read(4096):
                        encrypted_chunk = self.security.encrypt_file_chunk(chunk)
                        conn.sendall(len(encrypted_chunk).to_bytes(4, byteorder="big"))
                        conn.sendall(encrypted_chunk)

                ack = self.receive_data(conn, 3) 
                if ack != b"ACK":
                    print("Download: No proper acknowledgment received.")
                else:
                    print("Download: Transfer completed successfully.")

    def do_SHARE(self, args: str) -> None:
        """Share a file or directory with another user.

        Args:
            args (str): Arguments in the format "<name> <user_to_share_with> [permissions]".
        """
        if self.current_dir is None:
            self.send_response("You must log in first using the LOGIN command.")
            return

        parts = args.split()
        if len(parts) < 2:
            self.send_response("SHARE command requires at least a file/directory name and a recipient username.")
            return

        target_name, user_to_share_with = parts[:2]
        permissions = parts[2:] if len(parts) > 2 else None

        target = (self.current_dir / target_name).resolve()

        if not target.exists():
            self.send_response(f"Target '{target_name}' does not exist.")
            return

        if not (self.has_permission(target, "read") or self.has_permission(target.parent, "read")):
            self.send_response("Access denied: You do not have permission to share this item.")
            return

        recipient_root = self.root / user_to_share_with
        if not recipient_root.exists() or not recipient_root.is_dir():
            self.send_response(f"Recipient '{user_to_share_with}' does not exist.")
            return

        recipient_shared_dir = recipient_root / "shared"
        if not recipient_shared_dir.exists():
            recipient_shared_dir.mkdir(exist_ok=True)

        if not self.has_permission(recipient_shared_dir, "write"):
            self.send_response("Access denied: Sender does not have write access to their shared directory.")
            return

        symlink_path = recipient_shared_dir / target.name
        if symlink_path.exists():
            self.send_response(f"The recipient already has a shared item named '{target.name}'.")
            return

        symlink_path.symlink_to(target, target.is_dir())

        def update_permissions_recursively(path: Path, permissions_data: dict, sharer_permissions: list):
            if path.is_dir():
                dir_permissions = permissions_data.setdefault("dir_permissions", {})
                recipient_permissions = dir_permissions.setdefault(user_to_share_with, [])

                for perm in sharer_permissions:
                    if perm not in recipient_permissions:
                        recipient_permissions.append(perm)

                for sub_path in path.iterdir():
                    sub_permissions_file = sub_path / PERMISSIONS_FILE if sub_path.is_dir() else sub_path.parent / PERMISSIONS_FILE
                    if sub_permissions_file.exists():
                        with sub_permissions_file.open("r") as f:
                            sub_permissions_data = json.load(f)

                        update_permissions_recursively(sub_path, sub_permissions_data, sharer_permissions)

                        with sub_permissions_file.open("w") as f:
                            json.dump(sub_permissions_data, f, indent=4)
            else:
                file_permissions = permissions_data.get("files", {}).get(path.name, {}).get("permissions", {})
                if file_permissions:  
                    recipient_permissions = file_permissions.setdefault(user_to_share_with, [])

                    for perm in sharer_permissions:
                        if perm not in recipient_permissions:
                            recipient_permissions.append(perm)

        with (target.parent / PERMISSIONS_FILE).open("r") as f:
            permissions_data = json.load(f)

        sharer_permissions = permissions_data.get("dir_permissions", {}).get(self.username, [])

        if permissions:
            sharer_permissions = [perm for perm in sharer_permissions if perm in permissions]

        update_permissions_recursively(target, permissions_data, sharer_permissions)

        with (target.parent / PERMISSIONS_FILE).open("w") as f:
            json.dump(permissions_data, f, indent=4)

        self.send_response(f"'{target.name}' has been shared with '{user_to_share_with}' successfully.")

