import os
import json
import hmac
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes

# Generate a random salt
def generate_salt():
    return os.urandom(16)  # 16 bytes = 128-bit

# Key derivation function
def derive_keys(master_password, salt):
    # Derive two keys: one for AES encryption and one for HMAC
    master_key = hashlib.pbkdf2_hmac('sha256', master_password.encode(), salt, 100000)
    aes_key = master_key[:16]  # First 16 bytes for AES (128-bit)
    hmac_key = master_key[16:]  # Remaining bytes for HMAC
    return aes_key, hmac_key

# Encrypt service name using AES-ECB
def encrypt_service_name(service_name, aes_key):
    cipher = AES.new(aes_key, AES.MODE_ECB)
    encrypted_service_name = cipher.encrypt(pad(service_name.encode(), AES.block_size))
    return encrypted_service_name

# Encrypt password using AES-CTR
def encrypt_password(password, aes_key):
    nonce = get_random_bytes(16)  # 128-bit nonce
    cipher = AES.new(aes_key, AES.MODE_CTR, nonce=nonce)
    encrypted_password = cipher.encrypt(password.encode())
    return encrypted_password, nonce

# Generate HMAC
def generate_hmac(data, hmac_key):
    return hmac.new(hmac_key, data, hashlib.sha256).digest()

# Store data in master.txt
def store_data(filename, data):
    with open(filename, 'a') as file:
        file.write(json.dumps(data) + '\n')

# Check if a service name already exists
def service_exists(filename, encrypted_service_name):
    if not os.path.exists(filename):
        return False
    with open(filename, 'r') as file:
        for line in file:
            record = json.loads(line.strip())
            if record['encrypted_service_name'] == encrypted_service_name.hex():
                return True
    return False

# Main function to add a new service
def add_service(master_password, service_name, password):
    # Generate a random salt
    salt = generate_salt()

    # Derive keys using the salt
    aes_key, hmac_key = derive_keys(master_password, salt)

    # Encrypt the service name
    encrypted_service_name = encrypt_service_name(service_name, aes_key)
    if service_exists('master.txt', encrypted_service_name):
        print("Service name already exists!")
        return

    # Encrypt the password
    encrypted_password, nonce = encrypt_password(password, aes_key)

    # Generate HMACs
    hmac_service_name = generate_hmac(encrypted_service_name, hmac_key)
    hmac_password = generate_hmac(encrypted_password, hmac_key)

    # Store data
    data = {
        'salt': salt.hex(),  # Store salt as hex
        'encrypted_service_name': encrypted_service_name.hex(),
        'encrypted_password': encrypted_password.hex(),
        'nonce': nonce.hex(),
        'hmac_service_name': hmac_service_name.hex(),
        'hmac_password': hmac_password.hex()
    }
    store_data('master.txt', data)
    print("Service and password added successfully!")

# Example usage
if __name__ == "__main__":
    master_password = input("Enter your master password: ")
    service_name = input("Enter the service name: ")
    password = input("Enter the password: ")
    add_service(master_password, service_name, password)
