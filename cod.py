import time
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Util.Padding import pad, unpad

def generate_rsa_keypair(bits):
    key = RSA.generate(bits)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

def encrypt_file(input_file, public_key):
    rsa_key = RSA.import_key(public_key)
    cipher = PKCS1_OAEP.new(rsa_key)
    
    with open(input_file, 'rb') as f:
        file_data = f.read()
    
    encrypted_data = b""
    chunk_size = rsa_key.size_in_bytes() - 42  # PKCS1_OAEP padding overhead
    for i in range(0, len(file_data), chunk_size):
        chunk = file_data[i:i + chunk_size]
        encrypted_data += cipher.encrypt(chunk)
    
    return encrypted_data

def decrypt_file(encrypted_data, private_key):
    rsa_key = RSA.import_key(private_key)
    cipher = PKCS1_OAEP.new(rsa_key)
    
    decrypted_data = b""
    chunk_size = rsa_key.size_in_bytes()
    for i in range(0, len(encrypted_data), chunk_size):
        chunk = encrypted_data[i:i + chunk_size]
        decrypted_data += cipher.decrypt(chunk)
    
    return decrypted_data

def measure_rsa_performance(file_sizes, key_sizes):
    for key_size in key_sizes:
        private_key, public_key = generate_rsa_keypair(key_size)
        
        for file_size in file_sizes:
            input_file = f'test_{file_size}MB.bin'
            
            # Create a file of the specified size
            with open(input_file, 'wb') as f:
                f.write(b'a' * file_size * 1024 * 1024)
            
            # Measure encryption time
            start_time = time.time()
            encrypted_data = encrypt_file(input_file, public_key)
            encryption_time = time.time() - start_time
            
            # Measure decryption time
            start_time = time.time()
            decrypted_data = decrypt_file(encrypted_data, private_key)
            decryption_time = time.time() - start_time
            
            print(f'Key size: {key_size} bits, File size: {file_size} MB')
            print(f'Encryption time: {encryption_time:.2f} seconds')
            print(f'Decryption time: {decryption_time:.2f} seconds')
            print('---')

# Define file sizes in MB and key sizes in bits
file_sizes = [1, 2, 5]
key_sizes = [1024, 2048, 4096]

# Measure performance
measure_rsa_performance(file_sizes, key_sizes)


