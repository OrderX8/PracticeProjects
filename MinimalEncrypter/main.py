from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os
import base64

def generate_key(password):

    password = password.encode()

    salt = os.urandom(16)

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # Fernet needs a 32-byte key
        salt=salt,
        iterations=100000,  # Number of iterations for security
    )

    key = base64.urlsafe_b64encode(kdf.derive(password))

    return key, salt

def encrypt_file(file_path, key):

    fernet = Fernet(key)

    with open(file_path, 'rb') as file:
        file_data = file.read()

    encrypt_data = fernet.encrypt(file_data)

    # Encrypting file section
    encrypted_file_path = file_path + '.encrypted'
    with open(encrypted_file_path, 'wb') as file:
        file.write(encrypt_data)
    return encrypted_file_path

def decrypt_file(encrypted_file_path, key):
    
    fernet = Fernet(key)
    
    with open(encrypted_file_path, 'rb') as file:
        encrypted_data = file.read()
    
    decrypted_data = fernet.decrypt(encrypted_data)
    
    decrypted_file_path = encrypted_file_path.replace('.encrypted', '.decrypted')
    with open(decrypted_file_path, 'wb') as file:
        file.write(decrypted_data)
    return decrypted_file_path

def remove_outer_quotes(line):
    if len(line) >= 2 and line[0] == line[-1] and line[0] in ('"', "'"):
        return line[1:-1]
    return line

def main():

    action = input("Do you want to (e)ncrypt or (d)ecrypt a file? ").lower()
    file_path = input("Enter your file path: ")
    password = input("Enter your password: ")

    file_path = remove_outer_quotes(file_path)

    if action == 'e':
        key, salt = generate_key(password)
        encrypted_file = encrypt_file(file_path, key)

        with open(encrypted_file + '.salt', 'wb') as salt_file:
            salt_file.write(salt)
        print(f"File encrypted successfully: {encrypted_file}")
    elif action == 'd':
        salt_file = file_path + '.salt'
        if not os.path.exists(salt_file):
            print("Error: Salt file not found. Cannot decrypt.")
            return
        with open(salt_file, 'rb') as salt_file_obj:
            salt = salt_file_obj.read()
        # Derive the key using the original salt
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        decrypted_file = decrypt_file(file_path, key)
        print(f"File decrypted successfully: {decrypted_file}")
    else:
        print("Invalid choice. Please choose 'e' or 'd'.")

    return

if __name__ == "__main__":
    main()