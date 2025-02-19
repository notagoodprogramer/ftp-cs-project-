# secure_connection.py
from socket import socket, AF_INET, SOCK_STREAM
from pathlib import Path
from threading import Thread
from Security import SecurityHandler
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes

AES_KEY_SIZE = 32
IV_SIZE = 16
CHUNK_SIZE = 4096
IP = "127.0.0.1"  

class SecureConnection:
    def __init__(self, sock: socket, is_server: bool = False):
        self.sock = sock
        self.security = SecurityHandler()
        self.is_server = is_server
        if self.is_server:
            self._perform_server_handshake()
        else:
            self._perform_client_handshake()

    def _perform_client_handshake(self):
        public_key_path = Path("keys/server_public.pem")
        if not public_key_path.exists():
            raise FileNotFoundError("Server public key not found!")
        with public_key_path.open("rb") as f:
            server_public_key = RSA.import_key(f.read())
        aes_key = get_random_bytes(AES_KEY_SIZE)
        encrypted_aes = self.security.encrypt_aes_key(aes_key, server_public_key)
        self.sock.sendall(len(encrypted_aes).to_bytes(4, "big"))
        self.sock.sendall(encrypted_aes)
        self.security.aes_key = aes_key

    def _perform_server_handshake(self):
        private_key_path = Path("keys/private.pem")
        if not private_key_path.exists():
            raise FileNotFoundError("Server private key not found!")
        with private_key_path.open("rb") as f:
            self.security.rsa_private_key = RSA.import_key(f.read())
        size_bytes = self.sock.recv(4)
        size = int.from_bytes(size_bytes, "big")
        encrypted_aes = self._receive_data(size)
        self.security.decrypt_aes_key(encrypted_aes)

    def send_message(self, message: str):
        """Encrypts and sends a text message."""
        encrypted_message = self.security.encrypt_message(message)
        self.sock.sendall(len(encrypted_message).to_bytes(4, "big"))
        self.sock.sendall(encrypted_message)

    def receive_message(self) -> str:
        """Receives and decrypts a text message."""
        size_bytes = self.sock.recv(4)
        if not size_bytes:
            raise ConnectionError("No data received!")
        size = int.from_bytes(size_bytes, "big")
        encrypted_message = self._receive_data(size)
        return self.security.decrypt_message(encrypted_message)

    def send_file_chunk(self, chunk: bytes):
        """Encrypts a binary file chunk and sends it."""
        encrypted_chunk = self.security.encrypt_file_chunk(chunk)
        self.sock.sendall(len(encrypted_chunk).to_bytes(4, "big"))
        self.sock.sendall(encrypted_chunk)

    def receive_file_chunk(self) -> bytes:
        """Receives an encrypted file chunk and decrypts it."""
        size_bytes = self.sock.recv(4)
        if not size_bytes:
            raise ConnectionError("No data received for file chunk!")
        size = int.from_bytes(size_bytes, "big")
        encrypted_chunk = self._receive_data(size)
        return self.security.decrypt_file_chunk(encrypted_chunk)

    def send_file(self, file_path, chunk_size=CHUNK_SIZE):
        """
        Sends an entire file using the chunk system.
        It first sends a header with the file name and size,
        then sends the file in chunks.
        After finishing, it waits for an acknowledgment from the receiver.
        """
        file_path = Path(file_path)
        if not file_path.is_file():
            raise FileNotFoundError(f"{file_path} is not a valid file.")
        file_size = file_path.stat().st_size
        header = f"{file_path.name}|{file_size}"
        self.send_message(header)
        with file_path.open("rb") as f:
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                self.send_file_chunk(chunk)
        ack = self.receive_message()
        return ack

    def receive_file(self, destination, chunk_size=CHUNK_SIZE):
        """
        Receives an entire file using the chunk system.
        It first receives a header with the file name and size,
        then receives file chunks until the full file is transferred.
        Once complete, it sends an acknowledgment back.
        """
        header = self.receive_message()
        try:
            file_name, file_size_str = header.split("|")
            file_size = int(file_size_str)
        except Exception:
            raise ValueError("Invalid file header received.")
        destination = Path(destination)
        if destination.is_dir():
            file_path = destination / file_name
        else:
            file_path = destination
        with file_path.open("wb") as f:
            remaining = file_size
            while remaining > 0:
                chunk = self.receive_file_chunk()
                f.write(chunk)
                remaining -= len(chunk)
        self.send_message("ACK")
        return file_path

    def _receive_data(self, size: int) -> bytes:
        """Helper method to receive a specified number of bytes."""
        data = b""
        while len(data) < size:
            packet = self.sock.recv(size - len(data))
            if not packet:
                raise ConnectionError("Connection lost!")
            data += packet
        return data

    @staticmethod
    def get_available_port() -> int:
        """Returns an available port number."""
        with socket(AF_INET, SOCK_STREAM) as s:
            s.bind((IP, 0))
            return s.getsockname()[1]

   
    def transfer_file(self, path, host, port, mode, chunk_size=CHUNK_SIZE):
        """
        A simplified, unified method for file transfer.
        
        Parameters:
        path: if mode=="send", this is the file to send;
                if mode=="receive", this is the destination (directory or full path) to save the file.
        host, port: the remote host/port to connect to.
        mode: either "send" or "receive".
        """
        def worker():
            try:
                with socket(AF_INET, SOCK_STREAM) as s:
                    s.connect((host, port))
                    sc = SecureConnection(s, is_server=False)
                    if mode == "send":
                        ack = sc.send_file(path, chunk_size)
                        print(f"Upload successful. Ack: {ack}")
                    elif mode == "receive":
                        file_path = sc.receive_file(path, chunk_size)
                        print(f"Download successful. File saved to: {file_path}")
                    else:
                        print("Unknown mode.")
            except Exception as e:
                print(f"File transfer failed: {e}")
        Thread(target=worker).start()


        