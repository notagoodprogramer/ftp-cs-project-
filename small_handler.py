# handler.py
import json
import time
import jwt
from pathlib import Path
from cmd import Cmd
from secure_connection import SecureConnection
from authentication import AuthenticationManager
from permission_manager import PermissionManager
from shutil import rmtree
from threading import Thread
from socket import socket, AF_INET, SOCK_STREAM

PERMISSIONS_FILE = ".permissions.json"
SECRET_KEY = "very_secret"
IP = "127.0.0.1"  
HOME_DIR_ROOT = "file_perm_root"

class FTPHandler(Cmd):
    prompt = ""
    
    def __init__(self, root: str):
        super().__init__()
        self.root = Path(root).resolve()
        self.current_dir = None
        self.username = None
        self.auth_manager = AuthenticationManager()
        self.secure_conn = None
        self.perm_manager = None

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
        self.secure_conn.send_message(f"Unknown command: {line.split()[0] if line else ''}")
        
    def handle_connection(self, client_socket):
        self.secure_conn = SecureConnection(client_socket, is_server=True)
        while True:
            try:
                command_line = self.secure_conn.receive_message()
            except ConnectionError:
                break

            if command_line.upper().startswith("LOGIN") or command_line.upper().startswith("CREATEUSER"):
                self.onecmd(command_line)
                continue

            if not command_line.startswith("TOKEN"):
                self.secure_conn.send_message("Authentication required. Please log in.")
                continue

            try:
                _, token, command = command_line.split(" ", 2)
                payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
                self.username = payload["sub"]
                if self.current_dir is None:
                    self.current_dir = Path(payload["home"]).resolve()
                self.perm_manager = PermissionManager(self.username)
            except Exception:
                self.secure_conn.send_message("Invalid or expired token. Please log in again.")
                continue

            self.onecmd(command)

    def do_LOGIN(self, args: str) -> None:
        if self.username is not None:
            self.secure_conn.send_message("Already logged in.")
            return
        parts = args.split(" ", 1)
        if len(parts) != 2:
            self.secure_conn.send_message("Usage: LOGIN <username> <password>")
            return
        username, password = parts
        success, token = self.auth_manager.login(username, password)
        if success:
            self.username = username
            payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
            self.current_dir = Path(payload["home"])
            self.secure_conn.send_message(f"SUCCESS {token} | Welcome, {username}.")
        else:
            self.secure_conn.send_message(token)


    def do_LOGOUT(self, args: str) -> None:
        if self.username is None:
            self.secure_conn.send_message("You are not logged in.")
            return
        self.username = None
        self.current_dir = None
        self.secure_conn.send_message("SUCCESS Logged out successfully. Please log in again.")

    def do_CREATEUSER(self, args: str) -> None:
        parts = args.split(" ", 1)
        if len(parts) != 2:
            self.secure_conn.send_message("Usage: CREATEUSER <username> <password>")
            return
        username, password = parts
        result = self.auth_manager.create_user(username, password)
        self.secure_conn.send_message(result)

    def do_LIST(self, args: str) -> None:
        if self.current_dir is None:
            self.secure_conn.send_message("You must log in first.")
            return
        if not self.perm_manager.has_permission(self.current_dir, "write"):
            self.secure_conn.send_message("Access denied: You do not have permission to list files.")
            return
        files = "\n".join(f.name for f in self.current_dir.iterdir() if f.name != PERMISSIONS_FILE)
        self.secure_conn.send_message(f"Directory listing:\n{files}")
        
    def do_MKDIR(self, arg: str) -> None:
        """Create a new directory."""
        if self.current_dir is None:
            self.secure_conn.send_message("You must log in first using the LOGIN command.")
            return

        if not arg:
            self.secure_conn.send_message("MKDIR command requires a directory name.")
            return
    
        if arg.strip() == PERMISSIONS_FILE:
            self.secure_conn.send_message("Access denied: Cannot create a directory with this name.")
            return

        if not self.perm_manager.has_permission(self.current_dir, "write"):
            self.secure_conn.send_message("Access denied: You do not have permission to create directories here.")
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

        self.secure_conn.send_message(f"Directory '{arg}' created successfully.")

    def do_DELETE(self, arg: str) -> None:
        """Delete a file or directory."""
        if self.current_dir is None:
            self.secure_conn.send_message("You must log in first using the LOGIN command.")
            return

        if not arg:
            self.secure_conn.send_message("DELETE command requires a target file or directory.")
            return

        target = (self.current_dir / arg.strip()).resolve()

        if target.name == PERMISSIONS_FILE:
            self.secure_conn.send_message("Access denied: Cannot delete the permissions file.")
            return

        if not self.perm_manager.has_permission(target.parent, "write"):
            self.secure_conn.send_message("Access denied: You do not have permission to delete items here.")
            return

        if target.is_file():
            target.unlink()
            self.secure_conn.send_message(f"File '{arg}' deleted successfully.")
        elif target.is_dir():
            rmtree(target)
            self.secure_conn.send_message(f"Directory '{arg}' deleted successfully.")
        else:
            self.secure_conn.send_message(f"Target '{arg}' does not exist.")
    
    def do_CWD(self, arg: str) -> None:
        """Change the current working directory."""
        if self.current_dir is None:
            self.secure_conn.send_message("You must log in first using the LOGIN command.")
            return

        if not arg:
            self.secure_conn.send_message("CWD command requires a target directory.")
            return

        target = arg.strip()
        if target == "..":
            target_path = self.current_dir.parent
        else:
            target_path = self.current_dir / target

        if not target_path.is_dir():
            self.secure_conn.send_message(f"Directory '{target}' does not exist.")
            return

        if not self.perm_manager.has_permission(target_path, "read"):
            self.secure_conn.send_message("Access denied: You do not have permission to access this directory.")
            return

        self.current_dir = target_path.resolve()
        print(self.current_dir)
        try:
            relative_path = self.current_dir.relative_to((self.root / self.username).resolve())
        except ValueError:
          
            relative_path = self.current_dir

        self.secure_conn.send_message(f"Changed working directory to {relative_path}.")

  
    def do_UPLOAD(self, args: str) -> None:
        if self.current_dir is None:
            self.secure_conn.send_message("You must log in first.")
            return
        port = SecureConnection.get_available_port()
        def listener():
            with socket(AF_INET, SOCK_STREAM) as s:
                s.bind((IP, port))
                s.listen(1)
                conn, addr = s.accept()
                sc = SecureConnection(conn, is_server=True)
                sc.receive_file(self.current_dir)
        Thread(target=listener).start()
        self.secure_conn.send_message(f"READY {port}")
    
    
    def do_DOWNLOAD(self, args: str) -> None:
        if self.current_dir is None:
            self.secure_conn.send_message("You must log in first.")
            return
        filename = args.strip()
        if not filename:
            self.secure_conn.send_message("Usage: DOWNLOAD <filename>")
            return
        file_path = self.current_dir / filename
        if not file_path.exists():
            self.secure_conn.send_message(f"File '{filename}' does not exist.")
            return
        port = SecureConnection.get_available_port()
        def listener():
            with socket(AF_INET, SOCK_STREAM) as s:
                s.bind((IP, port))
                s.listen(1)
                conn, addr = s.accept()
                sc = SecureConnection(conn, is_server=True)
                sc.send_file(file_path)
        Thread(target=listener).start()
        self.secure_conn.send_message(f"READY {port}")
        
    def do_SHARE(self, args: str) -> None:
        """
        Share a file or directory with another user.
        Command format: SHARE <target> <recipient> [read]
        
        If the optional third argument is provided and is "read", then only "read"
        permission is granted; otherwise, default is ["read", "write"].
        The shared symlink in the recipient's shared folder is named with the 
        sharer's username as a prefix.
        """
        if self.current_dir is None:
            self.secure_conn.send_message("You must log in first.")
            return

        parts = args.split()
        if len(parts) < 2:
            self.secure_conn.send_message("Usage: SHARE <target> <recipient> [read]")
            return

        target_name, recipient = parts[0], parts[1]
        perms = ["read", "write"]
        if len(parts) >= 3 and parts[2].lower() == "read":
            perms = ["read"]

        target = (self.current_dir / target_name).resolve()
        if not target.exists():
            self.secure_conn.send_message(f"Target '{target_name}' does not exist.")
            return

        if not self.perm_manager.has_permission(target, "read"):
            self.secure_conn.send_message("Access denied: You do not have permission to share this item.")
            return

        recipient_home = self.root / recipient
        if not recipient_home.exists():
            self.secure_conn.send_message(f"User '{recipient}' does not exist.")
            return

        recipient_shared = recipient_home / "shared"
        if not recipient_shared.exists():
            try:
                recipient_shared.mkdir(exist_ok=True)
            except Exception as e:
                self.secure_conn.send_message(f"Failed to create shared folder for {recipient}: {e}")
                return

  
        symlink_name = f"{self.username}_{target.name}"
        symlink_path = recipient_shared / symlink_name

        if symlink_path.exists():
            self.secure_conn.send_message(f"A shared item named '{symlink_name}' already exists for '{recipient}'.")
            return

        try:
            symlink_path.symlink_to(target, target.is_dir())
        except Exception as e:
            self.secure_conn.send_message(f"Failed to create symlink: {e}")
            return

        if target.is_dir():
            
            perms_file = target / PERMISSIONS_FILE
            if not perms_file.exists():
                self.secure_conn.send_message("Permissions file not found in target directory.")
                return
            try:
                with perms_file.open("r") as f:
                    data = json.load(f)
            except Exception as e:
                self.secure_conn.send_message(f"Failed to load permissions file: {e}")
                return

            data.setdefault("dir_permissions", {})[recipient] = perms
            try:
                with perms_file.open("w") as f:
                    json.dump(data, f, indent=4)
            except Exception as e:
                self.secure_conn.send_message(f"Failed to update permissions file: {e}")
                return

            def update_subdirs(directory: Path):
                for sub in directory.iterdir():
                    if sub.is_dir():
                        sub_perm = sub / PERMISSIONS_FILE
                        if sub_perm.exists():
                            try:
                                with sub_perm.open("r") as f:
                                    sub_data = json.load(f)
                            except Exception:
                                continue
                            sub_data.setdefault("dir_permissions", {})[recipient] = perms
                            with sub_perm.open("w") as f:
                                json.dump(sub_data, f, indent=4)
                        update_subdirs(sub)
                    else:
                        parent = sub.parent
                        parent_perm = parent / PERMISSIONS_FILE
                        if parent_perm.exists():
                            try:
                                with parent_perm.open("r") as f:
                                    p_data = json.load(f)
                            except Exception:
                                continue
                            if "files" in p_data and sub.name in p_data["files"]:
                                p_data["files"][sub.name].setdefault("permissions", {})[recipient] = perms
                                with parent_perm.open("w") as f:
                                    json.dump(p_data, f, indent=4)
            update_subdirs(target)
        else:
            parent = target.parent
            perms_file = parent / PERMISSIONS_FILE
            if not perms_file.exists():
                self.secure_conn.send_message("Permissions file not found in parent directory.")
                return
            try:
                with perms_file.open("r") as f:
                    data = json.load(f)
            except Exception as e:
                self.secure_conn.send_message(f"Failed to load permissions file: {e}")
                return
            data.setdefault("files", {}).setdefault(target.name, {"permissions": {}})["permissions"][recipient] = perms
            try:
                with perms_file.open("w") as f:
                    json.dump(data, f, indent=4)
            except Exception as e:
                self.secure_conn.send_message(f"Failed to update permissions file: {e}")
                return

        self.secure_conn.send_message(f"'{target.name}' has been shared with '{recipient}' as '{symlink_name}' with permissions {perms}.")

        