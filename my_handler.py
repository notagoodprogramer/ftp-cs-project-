from pathlib import Path
import shutil
import socket
import threading
import cmd
class FTPHandler(cmd.Cmd):
    prompt = ""  
    def __init__(self, root: str) -> None:
        super().__init__()
        self.root = Path(root).resolve()
        self.current_dir = self.root

    def handle_connection(self, client_socket: socket.socket) -> None:
        self.client_socket = client_socket  
        while True:  
            header = self.client_socket.recv(4)  
            if not header:
                print("Client disconnected.")
                break 
            data_size = int.from_bytes(header, byteorder='big')
            command = self.receive_command(data_size).decode()
            
            if command.lower() == "quit":
                self.send_response("Goodbye!")
                break  

            self.onecmd(command)  
       
    def precmd(self, line):
       return line.strip()
    def onecmd(self, line):
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

    def default(self, line):
        self.send_response(f"Unknown command: {line.split()[0] if line else ''}")

    def do_LIST(self, arg):
        files = "\r\n".join(f.name for f in self.current_dir.iterdir())
        self.send_response(f"The files in the current directory are:\r\n{files}\r\n")

    def do_CWD(self, arg):
        if not arg:
            self.send_response("CWD command requires a target directory.")
            return

        target = arg.strip()
        if target == "..":
            if self.current_dir == self.root:
                self.send_response("Already at the root directory; cannot move up.")
            else:
                self.current_dir = self.current_dir.parent
                self.send_response(f"Changed working directory to {self.current_dir.relative_to(self.root)}.")
        else:
            target_path = self.current_dir / target
            if target_path.is_dir():
                self.current_dir = target_path
                self.send_response(f"Changed working directory to {self.current_dir.relative_to(self.root)}.")
            else:
                self.send_response(f"Directory '{target}' does not exist.")

    def do_MKDIR(self, arg):
        if not arg:
            self.send_response("MKDIR command requires a directory name.")
            return
        dir_path = self.current_dir / arg.strip()
        dir_path.mkdir(exist_ok=True)
        self.send_response(f"Directory '{arg}' created successfully.")

    def do_DELETE(self, arg):
        if not arg:
            self.send_response("DELETE command requires a target file or directory.")
            return

        target = (self.current_dir / arg.strip()).resolve()
        if target.is_file():
            target.unlink()
            self.send_response(f"File '{arg}' deleted successfully.")
        elif target.is_dir():
            shutil.rmtree(target)
            self.send_response(f"Directory '{arg}' deleted successfully.")
        else:
            self.send_response(f"Target '{arg}' does not exist.")

    def do_quit(self, arg):
        self.send_response("Goodbye!")
        return True  
    
    def send_response(self, response: str):
        response_bytes = response.encode()
        response_size = len(response_bytes)
        self.client_socket.sendall(response_size.to_bytes(4, byteorder='big'))
        self.client_socket.sendall(response_bytes)
        
    def receive_command(self, size):
        data = b''
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
