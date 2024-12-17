from pathlib import Path
import shutil
import socket
import threading

class FTPHandler:
    def __init__(self, root: str) -> None:
        self.root = Path(root).resolve()
        self.current_dir = self.root

    def handle_connection(self, client_socket: socket.socket) -> None:
        """
        Handles the communication with a connected client.
        """
        try:
            while True:
                header = client_socket.recv(4)
                if not header:
                    print("Client disconnected.")
                    break

                data_size = int.from_bytes(header, byteorder='big')
                command = self.receive_all(client_socket, data_size).decode()
                print(f"Received command: {command}")

                response = self.handle_cmd(command)
                response_bytes = response.encode()
                response_size = len(response_bytes)
                client_socket.sendall(response_size.to_bytes(4, byteorder='big'))
                client_socket.sendall(response_bytes)
        except ConnectionError as e:
            print(f"Connection error: {e}")

    def handle_cmd(self, cmd: str) -> str:
        cmd_split = cmd.strip().split()
        cmd_name = cmd_split[0].upper()
        args = cmd_split[1:]
        if cmd_name == "LIST":
            return self.handle_list()
        elif cmd_name == "CWD":
            return self.handle_cwd(args)
        elif cmd_name == "MKDIR":
            return self.handle_make_dir(args)
        elif cmd_name == "DELETE":
            return self.handle_delete(args)
        else:
            return f"Unknown command: {cmd_name}"

    def handle_list(self) -> str:
        files = "\r\n".join(f.name for f in self.current_dir.iterdir())
        return f"The files in the current directory are:\r\n{files}\r\n"

    

    def handle_cwd(self, args: list) -> str:
        if not args:
            return "CWD command requires a target directory."

        target = args[0]
        if target == "..":
            if self.current_dir == self.root:
                return "Already at the root directory; cannot move up."
            self.current_dir = self.current_dir.parent
            return f"Changed working directory to {self.current_dir.relative_to(self.root)}."

        target_path = self.current_dir / target

        if target_path.is_dir():
            self.current_dir = target_path
            return f"Changed working directory to {self.current_dir.relative_to(self.root)}."
        else:
            return f"Directory '{target}' does not exist."




    def handle_make_dir(self, args: list) -> str:
        if not args:
            return "MKDIR command requires a directory name."
        dir_path = self.current_dir / args[0]
        dir_path.mkdir()
        return f"Directory '{args[0]}' created successfully."

    def handle_delete(self, args: list) -> str:
        if not args:
            return "DELETE command requires a target file or directory."
        target = (self.current_dir / args[0]).resolve()
        if target.is_file():
            target.unlink()
            return f"File '{args[0]}' deleted successfully."
        elif target.is_dir():
            shutil.rmtree(target)
            return f"Directory '{args[0]}' deleted successfully."
        else:
            return f"Target '{args[0]}' does not exist."

    def receive_all(self, client_socket: socket.socket, size: int) -> bytes:
        data = b''
        while len(data) < size:
            packet = client_socket.recv(size - len(data))
            if not packet:
                raise ConnectionError("Connection lost before all data was received.")
            data += packet
        return data


class TCPServer:
    def __init__(self, host: str, port: int, root: str) -> None:
        self.host = host
        self.port = port
        self.root = root

    def start(self) -> None:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
            server_socket.bind((self.host, self.port))
            server_socket.listen(5)
            print(f"Server listening on {self.host}:{self.port}")

            while True:
                client_socket, client_address = server_socket.accept()
                print(f"Connection established with {client_address}")
                threading.Thread(
                    target=self.handle_client, args=(client_socket,)
                ).start()

    def handle_client(self, client_socket: socket.socket) -> None:
        with client_socket:
            handler = FTPHandler(self.root)
            handler.handle_connection(client_socket)


if __name__ == "__main__":
    root_directory = "my_handler_root"
    server = TCPServer("127.0.0.1", 12345, root_directory)
    server.start()
