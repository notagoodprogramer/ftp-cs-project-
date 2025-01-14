from pathlib import Path
from socket import socket, AF_INET, SOCK_STREAM

class TCPClient:
    def __init__(self, host, port):
        self.host = host
        self.port = port

    def start(self):
        with socket(AF_INET, SOCK_STREAM) as client_socket:
            client_socket.connect((self.host, self.port))
            print(f"Connected to {self.host}:{self.port}")

            while True:
                command = input("Enter a command (or 'quit' to exit): ").strip()
                if not command:
                    continue

                command_name, _, arg = command.partition(" ")
                if command_name.lower() == "upload":
                    self.handle_upload(client_socket, arg.strip())
                elif command_name.lower() == "download":
                    file_name, _, save_path = arg.partition(" ")
                    self.handle_download(client_socket, file_name.strip(), save_path.strip())
                else:
                    self.send_command(client_socket, command)
                    if command.lower() == "quit":
                        break

                    response = self.receive_response(client_socket)
                    if response:
                        print(f"Response: {response}")

    def handle_upload(self, client_socket: socket, file_path: str):
        file_path = Path(file_path)
        if not file_path.is_file():
            print(f"Invalid file path: {file_path}. Ensure the file exists.")
            return

        file_size = file_path.stat().st_size
        header = f"{file_path.name}|{file_size}".encode()

        self.send_command(client_socket, f"UPLOAD {file_path.name}")
        response = self.receive_response(client_socket)
        if response.startswith("READY"):
            port = int(response.split()[1])
            with socket(AF_INET, SOCK_STREAM) as upload_socket:
                upload_socket.connect((self.host, port))
                upload_socket.sendall(len(header).to_bytes(4, byteorder="big"))
                upload_socket.sendall(header)

                with file_path.open("rb") as f:
                    while chunk := f.read(4096):
                        upload_socket.sendall(chunk)

                print(upload_socket.recv(1024).decode())
        else:
            print(response)

    def handle_download(self, client_socket: socket, file_name: str, save_path: str):
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
                header = self.receive_data(download_socket, header_size).decode()
                server_file_name, file_size = header.split("|")
                file_size = int(file_size)

                if save_path.is_dir():
                    file_path = save_path / server_file_name
                else:
                    file_path = save_path

                print(f"Saving to: {file_path}")
                with file_path.open("wb") as f:
                    remaining = file_size
                    while remaining > 0:
                        chunk_size = min(4096, remaining)
                        chunk = download_socket.recv(chunk_size)
                        if not chunk:
                            raise ConnectionError("Connection lost during download.")
                        f.write(chunk)
                        remaining -= len(chunk)

                download_socket.sendall(b"ACK")
                print(f"File '{server_file_name}' downloaded successfully to {file_path}.")
            
        else:
            print(response)


    def send_command(self, client_socket: socket, command):
        command_bytes = command.encode()
        client_socket.sendall(len(command_bytes).to_bytes(4, byteorder="big"))
        client_socket.sendall(command_bytes)
    

    def receive_response(self, client_socket):
        size_bytes = client_socket.recv(4)
        if not size_bytes:
            raise ConnectionError("No response received; connection closed by server.")
        size = int.from_bytes(size_bytes, byteorder="big")
        response = self.receive_data(client_socket, size).decode()
        return response
       

    def receive_data(self, conn: socket, size: int) -> bytes:
        data = b""
        while len(data) < size:
            packet = conn.recv(size - len(data))
            if not packet:
                raise ConnectionError("Connection lost while receiving data.")
            data += packet
        return data


if __name__ == "__main__":
    client = TCPClient("127.0.0.1", 12345)
    client.start()
