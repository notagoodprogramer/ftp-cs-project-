import base64
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

RSA_KEY_SIZE = 2048
AES_KEY_SIZE = 32
IV_SIZE = 16

class SecurityHandler:
    """Handles encryption and decryption using RSA and AES."""

    def __init__(self, rsa_private_key=None, rsa_public_key=None):
        """
        Initialize the security handler with optional RSA keys.

        Args:
            rsa_private_key (bytes, optional): RSA private key in binary format.
            rsa_public_key (bytes, optional): RSA public key in binary format.
        """
        self.aes_key = None

        if rsa_private_key and rsa_public_key:
            self.rsa_private_key = RSA.import_key(rsa_private_key)
            self.rsa_public_key = RSA.import_key(rsa_public_key)
        else:
            self.generate_rsa_keys()

    def generate_rsa_keys(self):
        """
        Generate an RSA key pair and store them in files.
        """
        key = RSA.generate(RSA_KEY_SIZE)
        self.rsa_private_key = key
        self.rsa_public_key = key.publickey()

        with open("private.pem", "wb") as f:
            f.write(self.rsa_private_key.export_key())
        with open("public.pem", "wb") as f:
            f.write(self.rsa_public_key.export_key())

    def encrypt_aes_key(self, aes_key: bytes, recipient_public_key: RSA.RsaKey) -> bytes:
        """
        Encrypt an AES key using the recipient's RSA public key.

        Args:
            aes_key (bytes): The AES key to encrypt.
            recipient_public_key (RSA.RsaKey): The recipient's public RSA key.

        Returns:
            bytes: The encrypted AES key.
        """
        cipher_rsa = PKCS1_OAEP.new(recipient_public_key)
        return cipher_rsa.encrypt(aes_key)

    def decrypt_aes_key(self, encrypted_aes: bytes):
        """
        Decrypt an AES key using the RSA private key.

        Args:
            encrypted_aes (bytes): The encrypted AES key.
        """
        cipher_rsa = PKCS1_OAEP.new(self.rsa_private_key)
        self.aes_key = cipher_rsa.decrypt(encrypted_aes)

    def encrypt_message(self, message: str) -> bytes:
        """
        Encrypt a plaintext string using AES.

        Args:
            message (str): The plaintext message to encrypt.

        Returns:
            bytes: The encrypted message.
        """
        if not self.aes_key:
            raise ValueError("AES key not set. Set it before encryption.")

        iv = get_random_bytes(IV_SIZE)
        cipher = AES.new(self.aes_key, AES.MODE_CBC, iv)
        encrypted_data = iv + cipher.encrypt(pad(message.encode('utf-8'), AES.block_size))
        return encrypted_data

    def decrypt_message(self, encrypted_message: bytes) -> str:
        """
        Decrypt an AES-encrypted message.

        Args:
            encrypted_message (bytes): The encrypted message.

        Returns:
            str: The decrypted plaintext message.
        """
        if not self.aes_key:
            raise ValueError("AES key not set. Set it before decryption.")

        if len(encrypted_message) < IV_SIZE:
            raise ValueError("The encrypted message is too short to contain an IV.")

        iv, encrypted_text = encrypted_message[:IV_SIZE], encrypted_message[IV_SIZE:]
        cipher = AES.new(self.aes_key, AES.MODE_CBC, iv)
        decrypted_text = unpad(cipher.decrypt(encrypted_text), AES.block_size)
        return decrypted_text.decode("utf-8")

    def encrypt_file_chunk(self, chunk: bytes) -> bytes:
        """
        Encrypt a chunk of a file using AES.

        Args:
            chunk (bytes): The file chunk to encrypt.

        Returns:
            bytes: The encrypted file chunk.
        """
        iv = get_random_bytes(IV_SIZE)
        cipher = AES.new(self.aes_key, AES.MODE_CBC, iv)
        return iv + cipher.encrypt(pad(chunk, AES.block_size))

    def decrypt_file_chunk(self, encrypted_chunk: bytes) -> bytes:
        """
        Decrypt a chunk of an AES-encrypted file.

        Args:
            encrypted_chunk (bytes): The encrypted file chunk.

        Returns:
            bytes: The decrypted file chunk.
        """
        iv, encrypted_data = encrypted_chunk[:IV_SIZE], encrypted_chunk[IV_SIZE:]
        cipher = AES.new(self.aes_key, AES.MODE_CBC, iv)
        return unpad(cipher.decrypt(encrypted_data), AES.block_size)
