from pathlib import Path
from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.servers import FTPServer

rootpath = "root" 

def main():
    authorizer = DummyAuthorizer()
    password = "12345"

    #
    for i in range(5):  
        user_name = "user" + str(i)
        user_folder_name = "user" + str(i) + "folder"
        user_folder = Path(rootpath) / user_folder_name  
        
        if user_folder.exists() and user_folder.is_dir():
            authorizer.add_user(user_name, password, str(user_folder), perm="elradfmw")
        else:
            print(f"Directory for {user_name} does not exist: {user_folder}")

    handler = FTPHandler
    handler.authorizer = authorizer

    handler.banner = "Welcome to the FTP server."

    address = ('0.0.0.0', 2121) 
    server = FTPServer(address, handler)
    
    server.serve_forever()

if __name__ == "__main__":
    main()
