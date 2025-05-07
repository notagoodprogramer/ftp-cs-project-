from socket import socket, AF_INET, SOCK_STREAM
from threading import Thread
from small_handler import FTPHandler
from Config import IP, ROOT_DIRECTORY, PORT


class TCPServer:
    """
    A simple multi-threaded TCP server that accepts incoming connections
    and handles each client in a separate thread using FTPHandler.
    
    Attributes:
        host (str): The IP address to bind the server to.
        port (int): The port number to listen on.
        root (str): The root directory for the FTP handler.
    """

    def __init__(self, host: str, port: int, root: str) -> None:
        """
        Initializes the TCPServer with the given host, port, and root directory.

        Args:
            host (str): Server IP address.
            port (int): Server port number.
            root (str): Root directory for handling FTP requests.
        """
        self.host = host
        self.port = port
        self.root = root

    def start(self) -> None:
        """
        Starts the TCP server, binds it to the host and port, and listens for connections.
        Each client connection is handled in a separate thread.
        """
        with socket(AF_INET, SOCK_STREAM) as server_socket:
            server_socket.bind((self.host, self.port))
            server_socket.listen(5)
            print(f"Server started on {self.host}:{self.port}")

            while True:
                client_socket, client_address = server_socket.accept()
                print(f"Connection accepted from {client_address}")
                # Spawn a new thread to handle the client connection
                Thread(target=self.handle_client, args=(client_socket,)).start()

    def handle_client(self, client_socket: socket) -> None:
        """
        Handles a client connection by passing the socket to the FTPHandler.

        Args:
            client_socket (socket): The connected client socket.
        """
        with client_socket:
            handler = FTPHandler(self.root)
            handler.handle_connection(client_socket)


if __name__ == "__main__":
    server = TCPServer(IP, PORT, ROOT_DIRECTORY)
    server.start()