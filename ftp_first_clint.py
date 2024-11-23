from ftplib import FTP
from pathlib import Path

IP = "10.0.0.15"
PORT = 2121

def connect_to_ftp(user_num):
    ftp = FTP()
    ftp.connect(IP, PORT)  
    ftp.login(f'user{user_num}', '12345')  
    print(ftp.getwelcome())
    return ftp

def logout_user(ftp):
        ftp.quit()
        print("Logged out successfully.")

def list_files(ftp):
    print("Files and directories in the current directory:")
    ftp.retrlines('LIST')

def upload_file(ftp, file_name):
    file_path = Path(file_name)
    if file_path.exists() and file_path.is_file():
        with file_path.open('rb') as file:
            ftp.storbinary(f'STOR {file_path.name}', file)
        print(f"Uploaded: {file_path.name}")
    else:
        print(f"File: {file_name} does not exist or is not a file")

def download_file(ftp, file_name):
    if file_name in ftp.nlst():
        file_path = Path(file_name)
        with file_path.open('wb') as file:
            ftp.retrbinary(f'RETR {file_name}', file.write)
            print(f"Downloaded: {file_name}")
    else:
        print(f"File: {file_name} does not exist on the server")

def delete_file(ftp, file_name):
    if file_name in ftp.nlst():
        ftp.delete(file_name)
        print(f"Deleted: {file_name}")
    else:
        print(f"File: {file_name} does not exist on the server")

def create_folder(ftp, folder_name):
        ftp.mkd(folder_name)
        print(f"Folder '{folder_name}' created successfully.")

def move_up(ftp):
    try:
        ftp.cwd("..")
        print(f"Moved up to directory: {ftp.pwd()}")
    except Exception as e:
        print(f"Error moving up: {e}")

def move_down(ftp, folder_name):
    try:
        ftp.cwd(folder_name)
        print(f"Moved down into directory: {ftp.pwd()}")
    except Exception as e:
        print(f"Error moving into folder '{folder_name}': {e}")

def main():
    ftp = None
    while True:
        if not ftp:  
            user_num = input("Enter the number of the user to connect: ").strip()
            ftp = connect_to_ftp(user_num)
 
        action = input("Enter action name (list, upload, download, delete, create_folder, move_up, move_down, switch_user, quit): ").strip().lower()
        
        if action == "list":
            list_files(ftp)
        elif action == "upload":
            file_name = input("Enter the name of the file to upload: ").strip()
            upload_file(ftp, file_name)
        elif action == "download":
            file_name = input("Enter the name of the file to download: ").strip()
            download_file(ftp, file_name)
        elif action == "delete":
            file_name = input("Enter the name of the file to delete: ").strip()
            delete_file(ftp, file_name)
        elif action == "create_folder":
            folder_name = input("Enter the name of the folder to create: ").strip()
            create_folder(ftp, folder_name)
        elif action == "move_up":
            move_up(ftp)
        elif action == "move_down":
            folder_name = input("Enter the name of the folder to move into: ").strip()
            move_down(ftp, folder_name)
        elif action == "switch_user":
            logout_user(ftp)
            user_num = input("Enter the number of the new user to connect: ").strip()
            ftp = connect_to_ftp(user_num)
        elif action == "quit":
            if ftp:
                logout_user(ftp)
            print("Quitting...")
            break

if __name__ == "__main__":
    main()
