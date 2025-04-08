import os
import secrets
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

def encrypt_file(file_path, password):
    salt = secrets.token_bytes(16)
    iv = secrets.token_bytes(12)  # 12 bytes for AES-GCM
    key = PBKDF2HMAC(algorithm=hashes.SHA256(), iterations=600000, salt=salt, length=32).derive(password.encode())

    with open(file_path, "rb") as f:
        plaintext = f.read()

    cipher = Cipher(algorithms.AES(key), modes.GCM(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    encrypted_path = file_path + ".crabcrypt"
    with open(encrypted_path, "wb") as f:
        f.write(salt + iv + encryptor.tag + ciphertext)

    print(f"File encrypted successfully! Saved at: {encrypted_path}")

def decrypt_file(file_path, password):
    with open(file_path, "rb") as f:
        data = f.read()

    salt, iv, tag, ciphertext = data[:16], data[16:28], data[28:44], data[44:]
    key = PBKDF2HMAC(algorithm=hashes.SHA256(), iterations=600000, salt=salt, length=32).derive(password.encode())

    cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag))
    decryptor = cipher.decryptor()
    decrypted = decryptor.update(ciphertext) + decryptor.finalize()

    new_file_path = input("Enter the path to save the decrypted file: ")
    with open(new_file_path, "wb") as f:
        f.write(decrypted)

    print(f"File decrypted successfully! Saved at: {new_file_path}")

def main():
    while True:
        action = input("Do you want to (e)ncrypt or (d)ecrypt a file? (e/d): ").strip().lower()
        if action not in ['e', 'd']:
            print("Invalid option. Please enter 'e' to encrypt or 'd' to decrypt.")
            continue

        file_path = input("Enter the path to the file: ")
        if not os.path.isfile(file_path):
            print("File does not exist. Please enter a valid file path.")
            continue

        password = input("Enter password: ")
        if not password:
            print("Password cannot be empty.")
            continue

        if action == 'e':
            encrypt_file(file_path, password)
        elif action == 'd':
            decrypt_file(file_path, password)

        another = input("Do you want to perform another operation? (y/n): ").strip().lower()
        if another != 'y':
            break

if __name__ == "__main__":
    main()