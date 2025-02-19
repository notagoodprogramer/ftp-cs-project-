from socket import socket, AF_INET, SOCK_STREAM
from threading import Thread
from small_handler import FTPHandler

PERMISSIONS_FILE = ".permissions.json"
IP = "127.0.0.1"
PORT = 12345


class TCPServer:
    def __init__(self, host: str, port: int, root: str) -> None:
        self.host = host
        self.port = port
        self.root = root

    def start(self) -> None:
        with socket(AF_INET, SOCK_STREAM) as server_socket:
            server_socket.bind((self.host, self.port))
            server_socket.listen(5)
            
            while True:
                client_socket, _ = server_socket.accept()
                Thread(
                    target=self.handle_client, args=(client_socket,)
                ).start()

    def handle_client(self, client_socket: socket) -> None:
        with client_socket:
            handler = FTPHandler(self.root)
            handler.handle_connection(client_socket)

if __name__ == "__main__":
    root_directory = "file_perm_root"
    server = TCPServer(IP, PORT, root_directory)
    server.start()
