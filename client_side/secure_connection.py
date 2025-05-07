from socket import socket, AF_INET, SOCK_STREAM
from pathlib import Path
from threading import Thread
from Security import SecurityHandler
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Config import IP

AES_KEY_SIZE = 32
IV_SIZE = 16
CHUNK_SIZE = 4096

class SecureConnection:
    """
    Provides secure communication over a socket using RSA and AES encryption.
    Supports encrypted message exchange and file transfers.
    """

    def __init__(self, sock: socket, is_server: bool = False):
        """
        Initializes the secure connection and performs a handshake.

        Args:
            sock (socket): The socket object for communication.
            is_server (bool): True if acting as server, False if client.
        """
        self.sock = sock
        self.security = SecurityHandler()
        self.is_server = is_server
        if self.is_server:
            self._perform_server_handshake()
        else:
            self._perform_client_handshake()

    def _perform_client_handshake(self):
        """
        Performs client-side handshake by loading server's public key
        and sending an encrypted AES key.
        """
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
        """
        Performs server-side handshake by receiving and decrypting AES key.
        """
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
        """
        Sends an AES-encrypted text message.

        Args:
            message (str): Plaintext message to encrypt and send.
        """
        encrypted_message = self.security.encrypt_message(message)
        self.sock.sendall(len(encrypted_message).to_bytes(4, "big"))
        self.sock.sendall(encrypted_message)

    def receive_message(self) -> str:
        """
        Receives and decrypts an AES-encrypted message.

        Returns:
            str: Decrypted plaintext message.

        Raises:
            ConnectionError: If no data is received.
        """
        size_bytes = self.sock.recv(4)
        if not size_bytes:
            raise ConnectionError("No data received!")
        size = int.from_bytes(size_bytes, "big")
        encrypted_message = self._receive_data(size)
        return self.security.decrypt_message(encrypted_message)

    def send_file_chunk(self, chunk: bytes):
        """
        Encrypts and sends a binary chunk of a file.

        Args:
            chunk (bytes): The file chunk to send.
        """
        encrypted_chunk = self.security.encrypt_file_chunk(chunk)
        self.sock.sendall(len(encrypted_chunk).to_bytes(4, "big"))
        self.sock.sendall(encrypted_chunk)

    def receive_file_chunk(self) -> bytes:
        """
        Receives and decrypts a binary chunk of a file.

        Returns:
            bytes: The decrypted file chunk.

        Raises:
            ConnectionError: If no data is received.
        """
        size_bytes = self.sock.recv(4)
        if not size_bytes:
            raise ConnectionError("No data received for file chunk!")
        size = int.from_bytes(size_bytes, "big")
        encrypted_chunk = self._receive_data(size)
        return self.security.decrypt_file_chunk(encrypted_chunk)

    def send_file(self, file_path, chunk_size=CHUNK_SIZE):
        """
        Sends a complete file securely in encrypted chunks.

        Args:
            file_path (Path or str): Path to the file to send.
            chunk_size (int): Size of each file chunk.

        Returns:
            str: Acknowledgment message from receiver.

        Raises:
            FileNotFoundError: If the file doesn't exist.
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
        Receives a complete file securely in encrypted chunks.

        Args:
            destination (Path or str): Directory or file path to save the received file.
            chunk_size (int): Size of each file chunk.

        Returns:
            Path: Path to the saved file.

        Raises:
            ValueError: If the file header is invalid.
        """
        header = self.receive_message()
        try:
            file_name, file_size_str = header.split("|")
            file_size = int(file_size_str)
        except Exception:
            raise ValueError("Invalid file header received.")
        destination = Path(destination)
        file_path = destination / file_name if destination.is_dir() else destination
        with file_path.open("wb") as f:
            remaining = file_size
            while remaining > 0:
                chunk = self.receive_file_chunk()
                f.write(chunk)
                remaining -= len(chunk)
        self.send_message("ACK")
        return file_path

    def _receive_data(self, size: int) -> bytes:
        """
        Helper method to receive a fixed number of bytes.

        Args:
            size (int): Number of bytes to receive.

        Returns:
            bytes: Received data.

        Raises:
            ConnectionError: If connection is interrupted.
        """
        data = b""
        while len(data) < size:
            packet = self.sock.recv(size - len(data))
            if not packet:
                raise ConnectionError("Connection lost!")
            data += packet
        return data

    @staticmethod
    def get_available_port() -> int:
        """
        Get an available port from the OS.

        Returns:
            int: An unused port number.
        """
        with socket(AF_INET, SOCK_STREAM) as s:
            s.bind((IP, 0))
            return s.getsockname()[1]

    def transfer_file(self, path, host, port, mode, chunk_size=CHUNK_SIZE):
        """
        Performs file upload or download in a separate thread.

        Args:
            path: File path to send or destination to receive into.
            host: Remote host IP.
            port: Remote port.
            mode (str): Either 'send' or 'receive'.
            chunk_size (int): Chunk size in bytes.
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