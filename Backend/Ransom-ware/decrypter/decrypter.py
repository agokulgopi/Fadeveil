import os
import re
import sys
import subprocess
import multiprocessing
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import padding as rsa_padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from dotenv import load_dotenv
import chardet  # Detects encoding for text files

# Load environment variables
load_dotenv()

CHUNK_SIZE = 4 * 1024 * 1024  # 4MB chunk size

class Decryptor:
    def __init__(self, folder_path):
        self.folder_path = folder_path
        self.key_folder = os.path.join(os.path.dirname(__file__), "..", "key")

        self.rsa_private_key_file = os.path.join(self.key_folder, "private_key.pem")
        self.encrypted_aes_key_file = os.path.join(self.key_folder, "encrypted_aes_key.bin")

        if not os.path.exists(self.rsa_private_key_file) or not os.path.exists(self.encrypted_aes_key_file):
            raise FileNotFoundError("RSA private key or AES key file is missing.")

        print(f"Using target folder: {self.folder_path}")

    def decrypt_aes_key(self):
        """Decrypt the AES key using the RSA private key."""
        try:
            with open(self.rsa_private_key_file, "rb") as priv_file:
                private_key = serialization.load_pem_private_key(
                    priv_file.read(), password=None, backend=default_backend()
                )

            with open(self.encrypted_aes_key_file, "rb") as enc_key_file:
                encrypted_aes_key = enc_key_file.read()

            aes_key = private_key.decrypt(
                encrypted_aes_key,
                rsa_padding.OAEP(
                    mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

            if len(aes_key) not in (16, 24, 32):
                raise ValueError("AES key has an invalid length.")

            return aes_key
        except Exception as e:
            print(f"Error decrypting AES key: {e}")
            raise

    def pkcs7_unpad(self, data):
        """Removes PKCS#7 padding from decrypted data."""
        pad_len = data[-1]
        if pad_len < 1 or pad_len > 16:
            raise ValueError("Invalid padding length.")
        return data[:-pad_len]

    def decrypt_file(self, file_path, aes_key):
        """Decrypts a single encrypted file."""
        if not os.path.exists(file_path):
            print(f"File not found: {file_path}")
            return

        try:
            with open(file_path, "rb") as file:
                iv = file.read(16)  # Read IV first
                
                cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
                decryptor = cipher.decryptor()

                decrypted_data = b""
                while chunk := file.read(CHUNK_SIZE):
                    decrypted_data += decryptor.update(chunk)

                decrypted_data += decryptor.finalize()
                decrypted_data = self.pkcs7_unpad(decrypted_data)

            # Restore original filename
            filename = os.path.basename(file_path).replace(".wcry", "")
            filename = re.sub(r'^\d+-', '', filename)
            original_filepath = os.path.join(self.folder_path, filename)

            # Define text and binary file extensions
            text_extensions = {".txt", ".csv", ".json", ".html", ".xml", ".log"}
            file_extension = os.path.splitext(filename)[1].lower()

            if file_extension in text_extensions:
                # Detect encoding for text files
                encoding_info = chardet.detect(decrypted_data)
                detected_encoding = encoding_info['encoding'] or "utf-8"

                try:
                    with open(original_filepath, "w", encoding=detected_encoding, errors="ignore") as outfile:
                        outfile.write(decrypted_data.decode(detected_encoding, errors="ignore"))
                except Exception as e:
                    print(f"Failed to write text file {original_filepath}: {e}")
            else:
                # Save non-text files (image, video, audio) in binary mode
                try:
                    with open(original_filepath, "wb") as outfile:
                        outfile.write(decrypted_data)
                except Exception as e:
                    print(f"Failed to write binary file {original_filepath}: {e}")

            os.remove(file_path)  # Delete encrypted file after decryption
            print(f"Decrypted and saved: {original_filepath}")

        except Exception as e:
            print(f"Error decrypting {file_path}: {e}")

    def decrypt_all_files(self):
        """Scans the folder and decrypts all .wcry files using multiprocessing."""
        try:
            aes_key = self.decrypt_aes_key()
            wcry_files = [os.path.join(root, file) for root, _, files in os.walk(self.folder_path) for file in files if file.endswith(".wcry")]

            if not wcry_files:
                print("No encrypted (.wcry) files found for decryption.")
                return

            print(f"Found {len(wcry_files)} encrypted files. Starting decryption...")

            # Use multiprocessing to decrypt multiple files in parallel
            with multiprocessing.Pool(processes=min(4, len(wcry_files))) as pool:
                pool.starmap(self.decrypt_file, [(file, aes_key) for file in wcry_files])

            print("\nDecryption process completed successfully.")

            # Automatically launch AlertViewer.py after decryption
            # alert_viewer_path = os.path.join(os.path.dirname(__file__), "..", "AlertViewer.py")

            # if os.path.exists(alert_viewer_path):
            #     subprocess.run(["python", alert_viewer_path], check=True)
            # else:
            #     print(f"AlertViewer script not found at {alert_viewer_path}")

        except Exception as e:
            print(f"Decryption failed: {e}")

if __name__ == "__main__":
    target_folder = os.getenv("TARGET_FOLDER")
    
    if not target_folder or not os.path.exists(target_folder):
        print("Error: TARGET_FOLDER is not set or does not exist.")
        sys.exit(1)

    decryptor = Decryptor(target_folder)
    decryptor.decrypt_all_files()
