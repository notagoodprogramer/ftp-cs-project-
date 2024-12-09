import socket

class TCPClient:
    def __init__(self, host, port):
        self.host = host
        self.port = port

    def send_command(self, command):
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
                client_socket.connect((self.host, self.port))
                command_bytes = command.encode()

                command_size = len(command_bytes)
                client_socket.sendall(command_size.to_bytes(4, byteorder='big'))
                client_socket.sendall(command_bytes)

                response_size_bytes = client_socket.recv(4)
                response_size = int.from_bytes(response_size_bytes, byteorder='big')

                response = self.receive_all(client_socket, response_size).decode()
                print(f"Server response: {response}")

       

    def receive_all(self, client_socket, size):
        data = b''
        while len(data) < size:
            packet = client_socket.recv(size - len(data))
            if not packet:
                raise ConnectionError("Connection lost before all data was received.")
            data += packet
        return data


if __name__ == "__main__":
    client = TCPClient("127.0.0.1", 12345)

    while True:
        command = input("Enter a command (or 'quit' to exit): ")
        if command.lower() == "quit":
            break
        client.send_command(command)
