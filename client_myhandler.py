from pathlib import Path
from socket import socket, AF_INET, SOCK_STREAM
from Security import SecurityHandler
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes

RSA_KEY_SIZE = 2048
AES_KEY_SIZE = 32
IV_SIZE = 16

class TCPClient:
    """A secure FTP client using JWT authentication and encrypted communication."""

    def __init__(self, host, port):
        """Initialize the client with server details and security handler."""
        self.host = host
        self.port = port
        self.security = SecurityHandler()
        self.token = None

    def start(self):
        """Start the client, connect to the server, and handle user commands."""
        with socket(AF_INET, SOCK_STREAM) as client_socket:
            client_socket.connect((self.host, self.port))
            print(f"Connected to {self.host}:{self.port}")

            self.perform_handshake(client_socket)

            while True:
                command = input("Enter a command (or 'quit' to exit): ").strip()
                if not command:
                    continue

                command_name, _, arg = command.partition(" ")

                if command_name.lower() == "quit":
                    self.send_command(client_socket, "QUIT")
                    break

                if command_name.lower() == "createuser":
                    self.send_command(client_socket, f"CREATEUSER {arg.strip()}")
                    print(f"[Server Response]: {self.receive_response(client_socket)}")
                    continue

                if command_name.lower() == "login":
                    self.send_command(client_socket, f"LOGIN {arg.strip()}")
                    response = self.receive_response(client_socket)
                    if response.startswith("SUCCESS"):
                        parts = response.split(" ", 2)
                        self.token = parts[1]
                        if len(parts) > 2:
                            print(parts[2])
                    else:
                        print(f"[Server Response]: {response}")
                    continue

                if command_name.lower() == "logout":
                    self.send_command(client_socket, "LOGOUT")
                    response = self.receive_response(client_socket)
                    if response.startswith("SUCCESS"):
                        self.token = None
                        print(response.split(" ", 1)[1])
                    else:
                        print(f"[Server Response]: {response}")
                    continue

                if not self.token:
                    print("You must log in first.")
                    continue

                if command_name.lower() == "upload":
                    self.handle_upload(client_socket, arg.strip())
                elif command_name.lower() == "download":
                    file_name, _, save_path = arg.partition(" ")
                    self.handle_download(client_socket, file_name.strip(), save_path.strip())
                else:
                    self.send_command(client_socket, command)
                    print(f"Response: {self.receive_response(client_socket)}")

    def send_command(self, client_socket: socket, command: str):
        """Encrypt and send a command to the server, attaching JWT token if needed."""
        if self.token and not command.startswith("LOGIN"):
            command = f"TOKEN {self.token} {command}"
        encrypted_command = self.security.encrypt_message(command)
        client_socket.sendall(len(encrypted_command).to_bytes(4, "big"))
        client_socket.sendall(encrypted_command)

    def receive_response(self, client_socket: socket) -> str:
        """Receive and decrypt the server's response."""
        size_bytes = client_socket.recv(4)
        if not size_bytes:
            raise ConnectionError("No response received; connection closed by server.")

        size = int.from_bytes(size_bytes, byteorder="big")
        encrypted_response = self.receive_data(client_socket, size)
        response = self.security.decrypt_message(encrypted_response)

        if "Session expired" in response or "Invalid token" in response:
            print("Session expired. Please log in again.")
            self.token = None
        
        return response

    def receive_data(self, conn: socket, size: int) -> bytes:
        """Receive raw data from the connection, ensuring complete transfer."""
        data = b""
        while len(data) < size:
            packet = conn.recv(size - len(data))
            if not packet:
                raise ConnectionError("Connection lost while receiving data.")
            data += packet
        return data

    def perform_handshake(self, client_socket: socket):
        """Perform RSA-AES key exchange to establish secure communication."""
        public_key_path = Path("keys/server_public.pem")
        if not public_key_path.exists():
            raise FileNotFoundError("Missing 'server_public.pem'. Start the server first!")

        with public_key_path.open("rb") as f:
            server_public_key = RSA.import_key(f.read())

        aes_key = get_random_bytes(AES_KEY_SIZE)
        encrypted_aes = self.security.encrypt_aes_key(aes_key, server_public_key)
        client_socket.sendall(len(encrypted_aes).to_bytes(4, "big"))
        client_socket.sendall(encrypted_aes)
        self.security.aes_key = aes_key

    def handle_upload(self, client_socket: socket, file_path: str):
        """Encrypt and securely upload a file to the server."""
        file_path = Path(file_path)
        if not file_path.is_file():
            print(f"Invalid file path: {file_path}. Ensure the file exists.")
            return

        file_size = file_path.stat().st_size
        header = f"{file_path.name}|{file_size}"
        encrypted_header = self.security.encrypt_message(header)

        self.send_command(client_socket, f"UPLOAD {file_path.name}")
        response = self.receive_response(client_socket)

        if response.startswith("READY"):
            port = int(response.split()[1])
            with socket(AF_INET, SOCK_STREAM) as upload_socket:
                upload_socket.connect((self.host, port))
                upload_socket.sendall(len(encrypted_header).to_bytes(4, "big"))
                upload_socket.sendall(encrypted_header)

                with file_path.open("rb") as f:
                    while chunk := f.read(4096):
                        encrypted_chunk = self.security.encrypt_file_chunk(chunk)
                        upload_socket.sendall(len(encrypted_chunk).to_bytes(4, "big"))
                        upload_socket.sendall(encrypted_chunk)

                print("File uploaded successfully.")
        else:
            print(response)

    def handle_download(self, client_socket: socket, file_name: str, save_path: str):
        """Download and decrypt a file securely from the server."""
        if not file_name:
            print("You must specify a file name to download.")
            return

        save_path = Path(save_path)
        self.send_command(client_socket, f"DOWNLOAD {file_name}")
        response = self.receive_response(client_socket)

        if response.startswith("READY"):
            port = int(response.split()[1])
            with socket(AF_INET, SOCK_STREAM) as download_socket:
                download_socket.connect((self.host, port))

                header_size = int.from_bytes(self.receive_data(download_socket, 4), byteorder="big")
                encrypted_header = self.receive_data(download_socket, header_size)
                decrypted_header = self.security.decrypt_message(encrypted_header)

                server_file_name, file_size_str = decrypted_header.split("|")
                file_size = int(file_size_str)

                file_path = save_path / server_file_name if save_path.is_dir() else save_path
                print(f"Saving to: {file_path}")

                with file_path.open("wb") as f:
                    remaining = file_size
                    while remaining > 0:
                        chunk_size = int.from_bytes(self.receive_data(download_socket, 4), byteorder="big")
                        encrypted_chunk = self.receive_data(download_socket, chunk_size)
                        decrypted_chunk = self.security.decrypt_file_chunk(encrypted_chunk)
                        f.write(decrypted_chunk)
                        remaining -= len(decrypted_chunk)

                download_socket.sendall(b"ACK")
                print(f"File '{server_file_name}' downloaded successfully to {file_path}.")
        else:
            print(response)


if __name__ == "__main__":
    client = TCPClient("127.0.0.1", 12345)
    client.start()
