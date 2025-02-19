# tcp_client.py
from socket import socket, AF_INET, SOCK_STREAM
from pathlib import Path
from secure_connection import SecureConnection
import time
from threading import Thread
from pathlib import Path

class TCPClient:
    """A secure FTP client using JWT authentication and encrypted communication."""
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.secure_conn = None
        self.token = None

    def start(self):
        """Establish connection and start interactive command loop."""
        with socket(AF_INET, SOCK_STREAM) as client_socket:
            client_socket.connect((self.host, self.port))
            print(f"Connected to {self.host}:{self.port}")
            self.secure_conn = SecureConnection(client_socket, is_server=False)
            self.user_session_loop()

    def user_session_loop(self):
        """Accept user commands, handle authentication and file transfers."""
        while True:
            command = input("Enter a command (or 'quit' to exit): ").strip()
            if not command:
                continue

            command_name, _, arg = command.partition(" ")

            if command_name.lower() == "quit":
                self.send_command("QUIT")
                break

            if command_name.lower() in ("createuser", "login"):
                self.send_command(f"{command_name.upper()} {arg.strip()}")
                response = self.receive_response()
                if command_name.lower() == "login" and response.startswith("SUCCESS"):
                    parts = response.split(" ", 2)
                    self.token = parts[1]
                    print("Login successful!")
                    if len(parts) > 2:
                        print(parts[2])
                else:
                    print(f"[Server Response]: {response}")
                continue

            if not self.token:
                print("You must log in first.")
                continue

            if command_name.lower() == "logout":
                self.send_command("LOGOUT")
                response = self.receive_response()
                if response.startswith("SUCCESS"):
                    self.token = None
                    print("Logged out successfully.")
                else:
                    print(f"[Server Response]: {response}")
                continue

            if command_name.lower() == "upload":
                self.handle_upload(arg.strip())
            elif command_name.lower() == "download":
                file_name, _, save_path = arg.partition(" ")
                self.handle_download(file_name.strip(), save_path.strip())
            else:
                self.send_command(command)
                print(f"Response: {self.receive_response()}")

    def send_command(self, command: str):
        """Attach token if needed and send the command via SecureConnection."""
        if self.token and not command.upper().startswith("LOGIN"):
            command = f"TOKEN {self.token} {command}"
        self.secure_conn.send_message(command)

    def receive_response(self) -> str:
        return self.secure_conn.receive_message()

    def handle_upload(self, file_path: str):
        file_path = Path(file_path)
        if not file_path.is_file():
            print(f"Invalid file path: {file_path}.")
            return
        self.send_command(f"UPLOAD {file_path.name}")
        response = self.receive_response()
        if response.startswith("READY"):
            try:
                _, port_str = response.split()
                port = int(port_str)
            except Exception:
                print("Invalid READY response.")
                return
            self.secure_conn.transfer_file(file_path, self.host, port, "send")
        else:
            print(f"[Server Response]: {response}")

                
    def handle_download(self, file_name: str, save_path: str):
        if not file_name:
            print("You must specify a file name to download.")
            return
        save_path = Path(save_path)
        self.send_command(f"DOWNLOAD {file_name}")
        response = self.receive_response()
        if response.startswith("READY"):
            try:
                _, port_str = response.split()
                port = int(port_str)
            except Exception:
                print("Invalid READY response.")
                return
            self.secure_conn.transfer_file(save_path, self.host, port, "receive")
        else:
            print(f"[Server Response]: {response}")






   


if __name__ == "__main__":
    client = TCPClient("127.0.0.1", 12345)
    client.start()
