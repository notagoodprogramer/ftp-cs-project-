from ftplib import FTP
import os

def connect_to_ftp():
    ftp = FTP()
    ftp.connect('127.0.0.1', 2121)  # Connect to the local FTP server
    ftp.login('user', '12345')  # Log in with the username and password
    print(ftp.getwelcome())
    return ftp

def list_files(ftp):
    ftp.retrlines('LIST')

def upload_file(ftp, file_name):
    if os.path.exists:
        with open(file_name, 'rb') as file:
            ftp.storbinary(f'STOR {file_name}', file)
        print(f"Uploaded: {file_name}")
    else:
        print(f"File: {file_name} does not exist")

def download_file(ftp, file_name):
    if file_name in ftp.nlst():
        with open(file_name, 'wb') as file:
            ftp.retrbinary(f'RETR {file_name}', file.write)
            print(f"Downloaded: {file_name}")
    else:
        print(f"File: {file_name} does not exist")

def delete_file(ftp, file_name):
    if file_name in ftp.nlst():
        ftp.delete(file_name)
        print(f"Deleted: {file_name}")
    else: 
        print(f"File: {file_name} does not exist")

        
def main():
    ftp = connect_to_ftp()
    
    while True:
        action = input("Enter action name (list, upload, download, delete, quit): ").strip().lower()
        
        if action == "list":
            list_files(ftp)
        elif action == "upload":
            file_name = input("Enter the name of the file to upload: ").strip()
            upload_file(ftp,file_name)
        elif action == "download":
            file_name = input("Enter the name of the file to download: ").strip()
            download_file(ftp,file_name)
        elif action == "delete":
            file_name = input("Enter the name of the file to delete: ").strip()
            delete_file(ftp,file_name)
        elif action == "quit":
            print("quiting")
            break
            
            
    ftp.quit()

if __name__ == "__main__":
    main()
