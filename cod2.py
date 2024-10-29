import os
import time
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

def generate_aes_key(key_size):
    return get_random_bytes(key_size // 8)

def encrypt_file(input_file, key):
    cipher = AES.new(key, AES.MODE_CBC)
    iv = cipher.iv  # We need to save the IV for decryption
    encrypted_data = b""
    
    with open(input_file, 'rb') as f:
        file_data = f.read()
    
    # Pad data to be multiple of block size
    padded_data = pad(file_data, AES.block_size)
    
    # Encrypt the data
    encrypted_data += iv  # Prepend the IV for later use
    encrypted_data += cipher.encrypt(padded_data)
    
    return encrypted_data

def decrypt_file(encrypted_data, key):
    iv = encrypted_data[:AES.block_size]  # Extract the IV
    cipher = AES.new(key, AES.MODE_CBC, iv)
    
    # Decrypt the data
    decrypted_data = unpad(cipher.decrypt(encrypted_data[AES.block_size:]), AES.block_size)
    
    return decrypted_data

def measure_aes_performance(file_sizes, key_sizes):
    for key_size in key_sizes:
        key = generate_aes_key(key_size)
        
        for file_size in file_sizes:
            input_file = f'test_{file_size}MB.bin'
            
            # Create a file of the specified size
            with open(input_file, 'wb') as f:
                f.write(b'a' * file_size * 1024 * 1024)
            
            # Measure encryption time
            start_time = time.time()
            encrypted_data = encrypt_file(input_file, key)
            encryption_time = time.time() - start_time
            
            # Measure decryption time
            start_time = time.time()
            decrypted_data = decrypt_file(encrypted_data, key)
            decryption_time = time.time() - start_time
            
            print(f'Key size: {key_size} bits, File size: {file_size} MB')
            print(f'Encryption time: {encryption_time:.2f} seconds')
            print(f'Decryption time: {decryption_time:.2f} seconds')
            print('---')

# Define file sizes in MB and key sizes in bits
file_sizes = [1, 2, 5]
key_sizes = [128, 192, 256]  # AES supports key sizes of 128, 192, or 256 bits

# Measure performance
measure_aes_performance(file_sizes, key_sizes)



