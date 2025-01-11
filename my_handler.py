from pathlib import Path
from shutil import rmtree
from socket import socket, AF_INET, SOCK_STREAM
from threading import Thread
from cmd import Cmd
import json

PERMISSIONS_FILE = ".permissions.json"

class FTPHandler(Cmd):
    prompt = ""

    def __init__(self, root: str) -> None:
        super().__init__()
        self.root = Path(root).resolve()
        self.current_dir = None
        self.username = None
        self.setup_root_permissions()

    def handle_connection(self, client_socket: socket) -> None:
        self.client_socket = client_socket
        while True:
            header = self.client_socket.recv(4)
            if not header:
                print("Client disconnected.")
                break
            data_size = int.from_bytes(header, byteorder="big")
            command = self.receive_command(data_size).decode()

            if command.lower() == "quit":
                self.send_response("Goodbye!")
                break

            self.onecmd(command)

    def precmd(self, line: str) -> str:
        return line.strip()

    def onecmd(self, line: str) -> bool:
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
        self.send_response(f"Unknown command: {line.split()[0] if line else ''}")

    def do_LIST(self, arg: str) -> None:
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

    def do_quit(self, arg: str) -> bool:
        self.send_response("Goodbye!")
        return True

    def has_permission(self, path: Path, permission: str) -> bool:
        permissions_file = path / PERMISSIONS_FILE
        if not permissions_file.exists():
            return False

        with permissions_file.open("r") as f:
            permissions = json.load(f)

        fle = permissions.get("files", {}).get(path.name, {})
        user_permissions = fle.get("permissions", {}).get(self.username, [])
        if permission in user_permissions:
            return True

        dir_permissions = permissions.get("dir_permissions", {}).get(self.username, [])
        return permission in dir_permissions

    def do_CREATEUSER(self, username: str) -> None:
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

        self.send_response(f"User '{username}' created successfully. Home directory is {user_root}.")

    def do_LOGIN(self, username: str) -> None:
        username = username.strip()
        user_root = self.root / username

        if not user_root.exists() or not user_root.is_dir():
            self.send_response(f"User '{username}' does not exist.")
            return

        self.username = username
        self.current_dir = user_root
        self.send_response(f"Logged in as '{username}'. Home directory is {user_root}.")

    def do_LOGOUT(self, arg: str) -> None:
        if self.username is None:
            self.send_response("You are not logged in.")
            return

        self.username = None
        self.current_dir = None
        self.send_response("Logged out successfully.")

    def setup_root_permissions(self) -> None:
        permissions_file = self.root / PERMISSIONS_FILE
        if not permissions_file.exists():
            permissions = {
                "owner": "admin",
                "dir_permissions": {},
                "files": {}
            }
            with permissions_file.open("w") as f:
                json.dump(permissions, f, indent=4)
            print(f"Created root permissions file at {permissions_file}")

    def send_response(self, response: str) -> None:
        response_bytes = response.encode()
        response_size = len(response_bytes)
        self.client_socket.sendall(response_size.to_bytes(4, byteorder="big"))
        self.client_socket.sendall(response_bytes)

    def receive_command(self, size: int) -> bytes:
        data = b""
        while len(data) < size:
            packet = self.client_socket.recv(size - len(data))
            if not packet:
                raise ConnectionError("Connection lost while receiving data.")
            data += packet
        return data


class TCPServer:
    def __init__(self, host: str, port: int, root: str) -> None:
        self.host = host
        self.port = port
        self.root = root

    def start(self) -> None:
        with socket(AF_INET, SOCK_STREAM) as server_socket:
            server_socket.bind((self.host, self.port))
            server_socket.listen(5)
            print(f"Server listening on {self.host}:{self.port}")

            while True:
                client_socket, client_address = server_socket.accept()
                print(f"Connection established with {client_address}")
                Thread(
                    target=self.handle_client, args=(client_socket,)
                ).start()

    def handle_client(self, client_socket: socket) -> None:
        with client_socket:
            handler = FTPHandler(self.root)
            handler.handle_connection(client_socket)


if __name__ == "__main__":
    root_directory = "file_perm_root"
    server = TCPServer("127.0.0.1", 12345, root_directory)
    server.start()
