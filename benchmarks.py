import time
import random
from frsa_rrsa_redacted import fRSA_keygen, fRSA_encrypt, fRSA_decrypt

def benchmark_frsa():
    print("=== fRSA Performance Benchmarks ===")
    
    # Key generation benchmark
    start = time.time()
    pub_key, priv_key = fRSA_keygen(security_level=128)
    keygen_time = time.time() - start
    
    # Encryption benchmark
    message = random.randint(1, 1000000)
    start = time.time()
    ciphertext = fRSA_encrypt(message, pub_key)
    encrypt_time = time.time() - start
    
    # Decryption benchmark
    start = time.time()
    decrypted = fRSA_decrypt(ciphertext, priv_key)
    decrypt_time = time.time() - start
    
    print(f"Key Generation Time: {keygen_time:.4f} seconds")
    print(f"Encryption Time: {encrypt_time:.4f} seconds") 
    print(f"Decryption Time: {decrypt_time:.4f} seconds")
    print(f"Correctness Check: {message == decrypted}")
    print(f"Security Level: 128-bit post-quantum")

def benchmark_multiple_runs():
    print("\n=== Multiple Run Analysis ===")
    keygen_times = []
    encrypt_times = []
    decrypt_times = []
    
    for i in range(10):
        # Key generation
        start = time.time()
        pub_key, priv_key = fRSA_keygen(security_level=128)
        keygen_times.append(time.time() - start)
        
        # Encryption
        message = random.randint(1, 1000000)
        start = time.time()
        ciphertext = fRSA_encrypt(message, pub_key)
        encrypt_times.append(time.time() - start)
        
        # Decryption  
        start = time.time()
        decrypted = fRSA_decrypt(ciphertext, priv_key)
        decrypt_times.append(time.time() - start)
    
    print(f"Average Key Generation: {sum(keygen_times)/len(keygen_times):.4f}s")
    print(f"Average Encryption: {sum(encrypt_times)/len(encrypt_times):.4f}s")
    print(f"Average Decryption: {sum(decrypt_times)/len(decrypt_times):.4f}s")

if __name__ == "__main__":
    benchmark_frsa()
    benchmark_multiple_runs()
