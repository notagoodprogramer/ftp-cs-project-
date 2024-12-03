from pathlib import Path
from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.servers import FTPServer
from pyftpdlib.filesystems import AbstractedFS

class CustomFS(AbstractedFS):
    def __init__(self, root, cmd_channel):
        super().__init__(root, cmd_channel)
        self.allowed_symlink_targets = set()
        self.scan_symlinks()

    def scan_symlinks(self):
        """Scan the root directory and add symlink targets to the allowed list."""
        base_path = Path(self.root)
        for item in base_path.rglob('*'):
            if item.is_symlink():
                target = item.resolve()
                print(f"Discovered symlink: {item} -> {target}")
                self.allowed_symlink_targets.add(target)
       
    def add_symlink_target(self, symlink_path):
        """Add a symlink target to the allowed list."""
        target = Path(symlink_path).resolve()
        self.allowed_symlink_targets.add(target)
        print(f"Added symlink target: {target}")
    

    def validpath(self, path):
        """Validate the resolved path."""
        real_path = Path(self.realpath(path)).resolve()
        root_path = Path(self.root).resolve()

        # Allow paths within the jail
        if root_path in real_path.parents or real_path == root_path:
            return True

        # Allow paths that are in the allowed symlink targets
        if real_path in self.allowed_symlink_targets:
            return True

        print(f"Access denied: {real_path} is not within allowed paths or symlink targets")
        return False
    

    def realpath(self, path):
        """Resolve the full path, allowing symlinks."""
        resolved_path = super().realpath(path)
        real_path = Path(resolved_path).resolve()
        print(f"Resolved path: {resolved_path} -> {real_path}")
        return str(real_path)


class BetterFTPHandler(FTPHandler):
    abstracted_fs = CustomFS 

    def ftp_CREATESYMLINK(self, cmd):
        try:
            folder_to_share, folder_to_put_symlink, symlink_name = cmd.split(" ", 2)

            shared_folder_path = self.fs.realpath(folder_to_share)
            symlink_folder_path = self.fs.realpath(folder_to_put_symlink)
            symlink_target = Path(symlink_folder_path) / symlink_name

            if not Path(shared_folder_path).is_dir():
                return self.respond("550 The folder to share does not exist.")
            if not Path(symlink_folder_path).is_dir():
                return self.respond("550 The folder to place the symbolic link does not exist.")
            if not Path(shared_folder_path).is_dir():
                return self.respond("550 The folder to share does not exist.")
            if not Path(symlink_folder_path).is_dir():
                return self.respond("550 The folder to place the symbolic link does not exist.")

            symlink_target.symlink_to(shared_folder_path, target_is_directory=True)
            self.fs.add_symlink_target(shared_folder_path)  # Add target to the allowed list
            self.respond(f"250 Symbolic link {symlink_name} created.")
        except Exception as e:
            print(f"Error during CREATESYMLINK: {e}")
            self.respond(f"550 Failed to create symbolic link: {str(e)}")

# Add custom command to proto_cmds
BetterFTPHandler.proto_cmds["CREATESYMLINK"] = {
    "perm": "elradfmw",  # Required permissions
    "auth": True,        # Requires authentication
    "arg": True,         # Requires arguments
    "help": "Syntax: CREATESYMLINK <folder_to_share> <folder_to_put_symlink> <symlink_name>."
}

def main():
    authorizer = DummyAuthorizer()

    for i in range(5):
        user_name = f"user{i}"
        password = "12345"
        home_dir = Path("root") / f"user{i}folder"
        home_dir.mkdir(parents=True, exist_ok=True)
        authorizer.add_user(user_name, password, str(home_dir), perm="elradfmw")

    handler = BetterFTPHandler
    handler.authorizer = authorizer
    handler.banner = "Welcome to the FTP server."

    print("Registered commands:", handler.proto_cmds.keys())

    server = FTPServer(("0.0.0.0", 2121), handler)
    server.serve_forever()

if __name__ == "__main__":
    main()
