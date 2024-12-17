import socket

class TCPClient:
    def __init__(self, host, port):
        self.host = host
        self.port = port

    def start(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
            client_socket.connect((self.host, self.port))
            print(f"Connected to {self.host}:{self.port}")

            while True:
                command = input("Enter a command (or 'quit' to exit): ").strip().upper()
                if not command:
                    continue  
                
                self.send_command(client_socket, command)
                if command.lower() == "quit":
                    break  
                
    def send_command(self, client_socket, command):
        """Send a command to the server and receive the response."""
        command_bytes = command.encode()
        client_socket.sendall(len(command_bytes).to_bytes(4, byteorder="big"))
        client_socket.sendall(command_bytes)

        response = self.receive_response(client_socket)
        print(response)
        
    def receive_response(self, client_socket):
        size_bytes = client_socket.recv(4)
        if not size_bytes:
            raise ConnectionError("No response received; connection closed.")
        size = int.from_bytes(size_bytes, byteorder="big")

        data = b""
        while len(data) < size:
            packet = client_socket.recv(size - len(data))
            if not packet:
                raise ConnectionError("Connection closed while receiving response.")
            data += packet

        return data.decode()


if __name__ == "__main__":
    client = TCPClient("127.0.0.1", 12345)
    client.start()
