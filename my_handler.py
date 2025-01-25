from pathlib import Path
from shutil import rmtree
from socket import socket, AF_INET, SOCK_STREAM
from threading import Thread
from cmd import Cmd
import json

PERMISSIONS_FILE = ".permissions.json"
IP = "127.0.0.1"
PORT = 12345

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

    def handle_connection(self, client_socket: socket) -> None:
        """Handle a client connection.

        Args:
            client_socket (socket): The client socket.
        """
        self.client_socket = client_socket
        while True:
            header = self.client_socket.recv(4)
            if not header:
                break
            data_size = int.from_bytes(header, byteorder="big")
            command = self.receive_data(data_size).decode()

            if command.lower() == "quit":
                self.send_response("Goodbye!")
                break

            self.onecmd(command)

    def send_response(self, response: str) -> None:
        """Send a response to the client.

        Args:
            response (str): The response message.
        """
        response_bytes = response.encode()
        response_size = len(response_bytes)
        self.client_socket.sendall(response_size.to_bytes(4, byteorder="big"))
        self.client_socket.sendall(response_bytes)

    def receive_data(self, size: int) -> bytes:
        """Receive data from the client.

        Args:
            size (int): Number of bytes to receive.

        Returns:
            bytes: The received data.
        """
        data = b""
        while len(data) < size:
            packet = self.client_socket.recv(size - len(data))
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

    def do_LOGIN(self, username: str) -> None:
        """Log in as a user.

        Args:
            username (str): The username to log in as.
        """
        username = username.strip()
        user_root = self.root / username

        if not user_root.exists() or not user_root.is_dir():
            self.send_response(f"User '{username}' does not exist.")
            return

        self.username = username
        self.current_dir = user_root
        self.send_response(f"Logged in as '{username}'. Home directory is {user_root}.")

    def do_LOGOUT(self, arg: str) -> None:
        """Log out the current user."""
        if self.username is None:
            self.send_response("You are not logged in.")
            return

        self.username = None
        self.current_dir = None
        self.send_response("Logged out successfully.")

    def do_CREATEUSER(self, username: str) -> None:
        """Create a new user.

        Args:
            username (str): The username of the new user.
        """
        username = username.strip()
        user_root = self.root / username
        if user_root.exists():
            self.send_response(f"User '{username}' already exists.")
            return

        user_root.mkdir(parents=True, exist_ok=True)
        permissions_file = user_root / PERMISSIONS_FILE
        permissions = {
            "owner": username,
            "dir_permissions": {
                username: ["read", "write", "mkdir", "delete", "access"]
               
            },
            "files": {}
        }
        with permissions_file.open("w") as f:
            json.dump(permissions, f, indent=4)

        shared_dir = user_root / "shared"
        shared_dir.mkdir(exist_ok=True)

        shared_permissions_file = shared_dir / PERMISSIONS_FILE
        shared_permissions = {
            "owner": username,
            "dir_permissions": {
                username: ["read", "write", "mkdir", "delete", "access"],
                "*": ["write"] 
            },
            "files": {}
        }
        with shared_permissions_file.open("w") as f:
            json.dump(shared_permissions, f, indent=4)

        self.send_response(f"User '{username}' created successfully. Home directory is {user_root}.")

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
        """Upload a file to the server."""
        if self.current_dir is None:
            self.send_response("You must log in first using the LOGIN command.")
            return

        if not filename:
            self.send_response("UPLOAD command requires a filename.")
            return

        if not self.has_permission(self.current_dir, "write"):
            self.send_response("Access denied: You do not have permission to upload items here.")
            return

        if filename == PERMISSIONS_FILE:
            self.send_response(f"Cannot upload file with name {PERMISSIONS_FILE}.")
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
                header_size = int.from_bytes(conn.recv(4), byteorder="big")
                header = conn.recv(header_size).decode()
                file_name, file_size = header.split("|")
                file_size = int(file_size)

                file_path = self.current_dir / file_name
                with file_path.open("wb") as f:
                    remaining = file_size
                    while remaining > 0:
                        chunk = conn.recv(min(4096, remaining))
                        if not chunk:
                            raise ConnectionError("Connection lost during upload.")
                        f.write(chunk)
                        remaining -= len(chunk)

                conn.sendall(b"Upload complete.")

    def do_DOWNLOAD(self, filename: str) -> None:
        """Download a file from the server."""
        if self.current_dir is None:
            self.send_response("You must log in first using the LOGIN command.")
            return

        if not filename:
            self.send_response("DOWNLOAD command requires a filename.")
            return

        if not self.has_permission(self.current_dir, "read"):
            self.send_response("Access denied: You do not have permission to download items here.")
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
                header = f"{file_path.name}|{file_size}".encode()
                conn.sendall(len(header).to_bytes(4, byteorder="big"))
                conn.sendall(header)

                with file_path.open("rb") as f:
                    while chunk := f.read(4096):
                        conn.sendall(chunk)

                ack = conn.recv(1024)
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

