import json
import jwt
import time

from pathlib import Path
from shutil import rmtree, copy2, copytree
from socket import socket, AF_INET, SOCK_STREAM
from threading import Thread

from secure_connection import SecureConnection
from authentication import AuthenticationManager
from permission_manager import PermissionManager
from Config import IP, PERMISSIONS_FILE, SECRET_KEY


class FTPHandler:
    """
    Handles a single client FTP session, including authentication, file
    operations, and permission enforcement over a secure connection.
    """

    def __init__(self, root: str):
        """
        Initializes the FTPHandler.

        Args:
            root (str): Root directory path for the server.
        """
        self.root = Path(root).resolve()
        self.current_dir = None
        self.username = None
        self.auth_manager = AuthenticationManager()
        self.secure_conn = None
        self.perm_manager = None

    def handle_connection(self, client_socket):
        """
        Handles an incoming client socket by managing authentication and command dispatch.

        Args:
            client_socket (socket): The client socket object.
        """
        self.secure_conn = SecureConnection(client_socket, is_server=True)
        while True:
            try:
                msg = self.secure_conn.receive_message()
            except ConnectionError:
                break

            cmd = msg.split(' ', 1)[0].upper()
            if cmd in ("LOGIN", "CREATEUSER", "LOGOUT"):
                getattr(self, f"do_{cmd.lower()}")(msg)
                continue

            if not msg.startswith("TOKEN "):
                self.secure_conn.send_message("Authentication required. Please log in.")
                continue

            _, token, payload = msg.split(' ', 2)
            try:
                user = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
                self.username = user["sub"]
                if self.current_dir is None:
                    self.current_dir = Path(user["home"]).resolve()
                self.perm_manager = PermissionManager(self.username)
            except Exception:
                self.secure_conn.send_message("Invalid or expired token. Please log in again.")
                continue

            self.dispatch_command(payload)

    def dispatch_command(self, line: str):
        """
        Routes an incoming command to the appropriate method.

        Args:
            line (str): Command string.
        """
        parts = line.split(' ', 1)
        cmd = parts[0].lower()
        arg = parts[1] if len(parts) > 1 else ""
        method = getattr(self, f"do_{cmd}", None)
        if method:
            method(arg)
        else:
            self.secure_conn.send_message(f"Unknown command: {cmd.upper()}")

    # Authentication commands
    def do_login(self, msg: str):
        """Authenticate a user and return a JWT token."""
        _, rest = msg.split(' ', 1)
        parts = rest.split(' ', 1)
        if len(parts) != 2:
            self.secure_conn.send_message("Usage: LOGIN <username> <password>")
            return
        user, pwd = parts
        success, token = self.auth_manager.login(user, pwd)
        if success:
            self.username = user
            payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
            self.current_dir = Path(payload["home"]).resolve()
            self.secure_conn.send_message(f"SUCCESS {token} | Welcome, {user}.")
        else:
            self.secure_conn.send_message(token)

    def do_createuser(self, msg: str):
        """Create a new user account."""
        _, rest = msg.split(' ', 1)
        parts = rest.split(' ', 1)
        if len(parts) != 2:
            self.secure_conn.send_message("Usage: CREATEUSER <username> <password>")
            return
        user, pwd = parts
        res = self.auth_manager.create_user(user, pwd)
        self.secure_conn.send_message(res)

    def do_logout(self, msg: str):
        """Log out the current user."""
        if not self.username:
            self.secure_conn.send_message("You are not logged in.")
            return
        self.username = None
        self.current_dir = None
        self.secure_conn.send_message("SUCCESS Logged out successfully. Please log in again.")

    # File operations (list, mkdir, delete, etc.)
    def do_list(self, arg: str):
        """List directory contents."""
        if not self.current_dir:
            self.secure_conn.send_message("You must log in first.")
            return
        if not self.perm_manager.has_permission(self.current_dir, "read"):
            self.secure_conn.send_message("Access denied.")
            return
        names = [e.name for e in self.current_dir.iterdir() if e.name != PERMISSIONS_FILE]
        self.secure_conn.send_message("Directory listing:\n" + "\n".join(names))

    def do_mkdir(self, name: str):
        """Create a new directory."""
        if not name or not self.current_dir:
            self.secure_conn.send_message("Usage: MKDIR <dirname>")
            return
        tgt = (self.current_dir / name).resolve()
        if tgt.exists():
            self.secure_conn.send_message("Already exists.")
            return
        if not self.perm_manager.has_permission(self.current_dir, "write"):
            self.secure_conn.send_message("Access denied.")
            return
        tgt.mkdir()
        parent_perm = self.current_dir / PERMISSIONS_FILE
        if parent_perm.exists():
            (tgt / PERMISSIONS_FILE).write_text(parent_perm.read_text())
        self.secure_conn.send_message(f"Directory '{name}' created.")

    def do_delete(self, name: str):
        """Delete a file or directory."""
        if not name or not self.current_dir:
            self.secure_conn.send_message("Usage: DELETE <name>")
            return
        tgt = (self.root / self.username / name).resolve() if '/' in name else (self.current_dir / name).resolve()
        if not tgt.exists():
            self.secure_conn.send_message("Not found.")
            return
        if not self.perm_manager.has_permission(tgt.parent, "write"):
            self.secure_conn.send_message("Access denied.")
            return
        try:
            rmtree(tgt) if tgt.is_dir() else tgt.unlink()
            self.secure_conn.send_message(f"Deleted '{name}'.")
        except Exception as e:
            self.secure_conn.send_message(f"Delete failed: {e}")

    def do_cwd(self, name: str):
        """Change working directory."""
        if not name or not self.current_dir:
            self.secure_conn.send_message("Usage: CWD <path>")
            return
        tgt = self.current_dir.parent if name == '..' else (self.current_dir / name).resolve()
        if not tgt.is_dir():
            self.secure_conn.send_message("Not a directory.")
            return
        if not self.perm_manager.has_permission(tgt, "read"):
            self.secure_conn.send_message("Access denied.")
            return
        self.current_dir = tgt
        rel = tgt.relative_to((self.root / self.username).resolve())
        self.secure_conn.send_message(f"Changed working directory to {rel}")

    def do_download(self, name: str):
        """Prepare a file for download over a separate connection."""
        if not name:
            self.secure_conn.send_message("Usage: DOWNLOAD <name>")
            return
        target = (self.current_dir / name).resolve()
        if not target.exists() or target.is_dir():
            self.secure_conn.send_message("ERROR: DOWNLOAD only supports individual files.")
            return
        port = SecureConnection.get_available_port()
        def lstn():
            with socket(AF_INET, SOCK_STREAM) as s:
                s.bind((IP, port))
                s.listen(1)
                conn, _ = s.accept()
                sc = SecureConnection(conn, is_server=True)
                sc.send_file(target)
        Thread(target=lstn, daemon=True).start()
        self.secure_conn.send_message(f"READY {port}")

    def do_upload(self, arg: str):
        """Receive a file upload over a separate connection."""
        port = SecureConnection.get_available_port()
        def lstn():
            with socket(AF_INET, SOCK_STREAM) as s:
                s.bind((IP, port))
                s.listen(1)
                conn, _ = s.accept()
                sc = SecureConnection(conn, is_server=True)
                file_path = sc.receive_file(self.current_dir)
                if file_path.suffix.lower() == ".zip":
                    file_path.unlink()
                    self.secure_conn.send_message("ERROR: UPLOAD only supports single files.")
                else:
                    self.secure_conn.send_message(f"File '{file_path.name}' uploaded successfully.")
        Thread(target=lstn, daemon=True).start()
        self.secure_conn.send_message(f"READY {port}")

    def do_copy(self, args: str):
        """Copy file or directory from one location to another."""
        parts = args.split(' ', 1)
        if len(parts) != 2:
            self.secure_conn.send_message("Usage: COPY <src> <dest>")
            return
        src, dst = parts
        srcp = (self.root / self.username / src).resolve()
        dstp = (self.current_dir / dst).resolve()
        if not srcp.exists():
            self.secure_conn.send_message("Source not found.")
            return
        if not (self.perm_manager.has_permission(srcp.parent, "read") and self.perm_manager.has_permission(self.current_dir, "write")):
            self.secure_conn.send_message("Access denied.")
            return
        try:
            copytree(srcp, dstp) if srcp.is_dir() else copy2(srcp, dstp)
            self.secure_conn.send_message(f"Copied '{src}' into '{dst}'.")
        except Exception as e:
            self.secure_conn.send_message(f"Copy failed: {e}")

    def do_cut(self, args: str):
        """Move (cut) file or directory from one location to another."""
        parts = args.split(' ', 1)
        if len(parts) != 2:
            self.secure_conn.send_message("Usage: CUT <src> <dest>")
            return
        src, dst = parts
        self.do_copy(args)
        self.do_delete(src)

    def do_rename(self, args: str):
        """Rename a file or directory."""
        parts = args.split(' ', 1)
        if len(parts) != 2:
            self.secure_conn.send_message("Usage: RENAME <old> <new>")
            return
        old, new = parts
        oldp = (self.current_dir / old).resolve()
        newp = (self.current_dir / new).resolve()
        if not oldp.exists():
            self.secure_conn.send_message("Source not found.")
            return
        if not self.perm_manager.has_permission(oldp.parent, "write"):
            self.secure_conn.send_message("Access denied.")
            return
        try:
            oldp.rename(newp)
            self.secure_conn.send_message(f"Renamed '{old}' to '{new}'.")
        except Exception as e:
            self.secure_conn.send_message(f"Rename failed: {e}")

    def do_share(self, args: str):
        """Share a file or directory with another user."""
        parts = args.split()
        if len(parts) != 2:
            self.secure_conn.send_message("Usage: SHARE <username> <name>")
            return
        target_user, name = parts
        src = (self.current_dir / name).resolve()
        if not src.exists():
            self.secure_conn.send_message("Not found.")
            return
        if not self.perm_manager.has_permission(src.parent, "read"):
            self.secure_conn.send_message("Access denied.")
            return
        dest_dir = (self.root / target_user / "shared").resolve()
        try:
            dest_dir.mkdir(parents=True, exist_ok=True)
            dest = dest_dir / name
            if dest.exists():
                rmtree(dest) if dest.is_dir() else dest.unlink()
            copytree(src, dest) if src.is_dir() else copy2(src, dest)
            self.secure_conn.send_message(f"Shared '{name}' with {target_user}.")
        except Exception as e:
            self.secure_conn.send_message(f"Share failed: {e}")
