import socket 
from pathlib import Path
class Server:
    
    def __init__(self,port, ip,root):
        self.port = port
        self.ip = ip 
        self.root= Path(root)
        
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((ip, port))  
    server_socket.listen(5)
    
 

   
        while True:
            client_socket, addr = server_socket.accept()
                        
            client_socket.sendall("enter the function you wnat")
            function = client_socket.recv(1).decode()
            
            if function == 1:
                client_socket.sendall("enter the file name to del")
            #fun2, fun3 im lazy later. 

            
            size = client_socket.recv(4).decode()
            file_name = ""
            while len(file_name) < size:
                file_name += client_socket.recv(size).decode()
                
        
        

    
        
    
    # client_socket.close()
    