from ftplib import FTP

def connect_to_ftp():
    ftp = FTP()
    ftp.connect('127.0.0.1', 2121)  # Connect to the local FTP server
    ftp.login('user', '12345')  # Log in with the username and password
    print(ftp.getwelcome())
    return ftp

def list_files(ftp):
    ftp.retrlines('LIST')

def upload_file(ftp, local_file, remote_file):
    with open(local_file, 'rb') as file:
        ftp.storbinary(f'STOR {remote_file}', file)

def download_file(ftp, remote_file, local_file):
    with open(local_file, 'wb') as file:
        ftp.retrbinary(f'RETR {remote_file}', file.write)

def delete_file(ftp, remote_file):
    ftp.delete(remote_file)

def main():
    ftp = connect_to_ftp()

    print("Listing files:")
    list_files(ftp)

    local_file_to_upload = 'upload_test.txt'
    remote_file_name = 'uploaded_test.txt'
    print(f"\nUploading {local_file_to_upload} as {remote_file_name}")
    upload_file(ftp, local_file_to_upload, remote_file_name)

    print("\nListing files after upload:")
    list_files(ftp)

    local_file_to_download = 'downloaded_test.txt'
    print(f"\nDownloading {remote_file_name} as {local_file_to_download}")
    download_file(ftp, remote_file_name, local_file_to_download)

    print("\nListing files after download:")
    list_files(ftp)

    print(f"\nDeleting {remote_file_name}")
    delete_file(ftp, remote_file_name)

    print("\nListing files after deletion:")
    list_files(ftp)

    ftp.quit()

if __name__ == "__main__":
    main()
