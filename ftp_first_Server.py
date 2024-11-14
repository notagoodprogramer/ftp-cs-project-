from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.servers import FTPServer

def main():
    # Instantiate a dummy authorizer to handle user authentication
    authorizer = DummyAuthorizer()

    # Add a user with full r/w permissions
    authorizer.add_user("user", "12345", R"C:\ftp_first_server_filesys", perm="elradfmw")
    # elradfmw stands for: 
    # e = change directories (CWD, CDUP commands)
    # l = list files (LIST, NLST, STAT, MLSD, MLST, SIZE commands)
    # r = retrieve file from the server (RETR command)
    # a = append data to an existing file (APPE command)
    # d = delete file or directory (DELE, RMD commands)
    # f = rename file or directory (RNFR, RNTO commands)
    # m = create directory (MKD command)
    # w = store a file on the server (STOR, STOU commands)

    # Allow anonymous connections
    authorizer.add_anonymous(R"C:\ftp_first_server_filesys")

    # Instantiate an FTP handler
    handler = FTPHandler
    handler.authorizer = authorizer

    # Define a customized banner (string returned when client connects)
    handler.banner = "Welcome to the FTP server."

    # Instantiate the FTP server
    address = ('0.0.0.0', 2121)  # Listen on all network interfaces at port 2121
    server = FTPServer(address, handler)

    # Start the FTP server
    server.serve_forever()

if __name__ == "__main__":
    main()
