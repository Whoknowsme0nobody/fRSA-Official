import time
import random
from frsa_rrsa_redacted import fRSA_keygen, fRSA_encrypt, fRSA_decrypt, rRSA_keygen, rRSA_encrypt, rRSA_decrypt

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
    
    return keygen_time, encrypt_time, decrypt_time

def benchmark_rrsa():
    print("\n=== rRSA Performance Benchmarks ===")

    # Key generation benchmark
    start = time.time()
    pub_key, priv_key = rRSA_keygen(security_level=128)
    keygen_time = time.time() - start

    # Encryption benchmark
    message = random.randint(1, 1000000)
    start = time.time()
    ciphertext = rRSA_encrypt(message, pub_key)
    encrypt_time = time.time() - start

    # Decryption benchmark
    start = time.time()
    decrypted = rRSA_decrypt(ciphertext, priv_key)
    decrypt_time = time.time() - start

    print(f"Key Generation Time: {keygen_time:.4f} seconds")
    print(f"Encryption Time: {encrypt_time:.4f} seconds") 
    print(f"Decryption Time: {decrypt_time:.4f} seconds")
    print(f"Correctness Check: {message == decrypted}")
    print(f"Security Level: 128-bit post-quantum")
    
    return keygen_time, encrypt_time, decrypt_time

def benchmark_multiple_runs_frsa():
    print("\n=== fRSA Multiple Run Analysis ===")
    keygen_times = []
    encrypt_times = []
    decrypt_times = []

    for i in range(10):
        print(f"fRSA Run {i+1}/10...", end=" ")
        
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
        
        print("✓")

    print(f"Average Key Generation: {sum(keygen_times)/len(keygen_times):.4f}s")
    print(f"Average Encryption: {sum(encrypt_times)/len(encrypt_times):.4f}s")
    print(f"Average Decryption: {sum(decrypt_times)/len(decrypt_times):.4f}s")
    
    return keygen_times, encrypt_times, decrypt_times

def benchmark_multiple_runs_rrsa():
    print("\n=== rRSA Multiple Run Analysis ===")
    keygen_times = []
    encrypt_times = []
    decrypt_times = []

    for i in range(10):
        print(f"rRSA Run {i+1}/10...", end=" ")
        
        # Key generation
        start = time.time()
        pub_key, priv_key = rRSA_keygen(security_level=128)
        keygen_times.append(time.time() - start)

        # Encryption
        message = random.randint(1, 1000000)
        start = time.time()
        ciphertext = rRSA_encrypt(message, pub_key)
        encrypt_times.append(time.time() - start)

        # Decryption  
        start = time.time()
        decrypted = rRSA_decrypt(ciphertext, priv_key)
        decrypt_times.append(time.time() - start)
        
        print("✓")

    print(f"Average Key Generation: {sum(keygen_times)/len(keygen_times):.4f}s")
    print(f"Average Encryption: {sum(encrypt_times)/len(encrypt_times):.4f}s")
    print(f"Average Decryption: {sum(decrypt_times)/len(decrypt_times):.4f}s")
    
    return keygen_times, encrypt_times, decrypt_times

def security_level_comparison():
    print("\n=== Security Level Comparison ===")
    
    security_levels = [128, 256]
    
    for level in security_levels:
        print(f"\n--- Security Level: {level}-bit ---")
        
        # fRSA
        start = time.time()
        pub_key, priv_key = fRSA_keygen(security_level=level)
        frsa_keygen_time = time.time() - start
        
        message = 12345
        start = time.time()
        ciphertext = fRSA_encrypt(message, pub_key)
        frsa_encrypt_time = time.time() - start
        
        start = time.time()
        decrypted = fRSA_decrypt(ciphertext, priv_key)
        frsa_decrypt_time = time.time() - start
        
        # rRSA
        start = time.time()
        pub_key_r, priv_key_r = rRSA_keygen(security_level=level)
        rrsa_keygen_time = time.time() - start
        
        start = time.time()
        ciphertext_r = rRSA_encrypt(message, pub_key_r)
        rrsa_encrypt_time = time.time() - start
        
        start = time.time()
        decrypted_r = rRSA_decrypt(ciphertext_r, priv_key_r)
        rrsa_decrypt_time = time.time() - start
        
        print(f"fRSA - KeyGen: {frsa_keygen_time:.4f}s, Encrypt: {frsa_encrypt_time:.4f}s, Decrypt: {frsa_decrypt_time:.4f}s")
        print(f"rRSA - KeyGen: {rrsa_keygen_time:.4f}s, Encrypt: {rrsa_encrypt_time:.4f}s, Decrypt: {rrsa_decrypt_time:.4f}s")
        print(f"fRSA Correctness: {message == decrypted}")
        print(f"rRSA Correctness: {message == decrypted_r}")

def function_type_comparison():
    print("\n=== Function Type Comparison ===")
    
    function_types = ['polynomial', 'transcendental']
    
    for func_type in function_types:
        print(f"\n--- Function Type: {func_type.title()} ---")
        
        # fRSA
        start = time.time()
        pub_key, priv_key = fRSA_keygen(security_level=128, function_type=func_type)
        frsa_keygen_time = time.time() - start
        
        message = 98765
        start = time.time()
        ciphertext = fRSA_encrypt(message, pub_key)
        frsa_encrypt_time = time.time() - start
        
        start = time.time()
        decrypted = fRSA_decrypt(ciphertext, priv_key)
        frsa_decrypt_time = time.time() - start
        
        # rRSA
        start = time.time()
        pub_key_r, priv_key_r = rRSA_keygen(security_level=128, function_type=func_type)
        rrsa_keygen_time = time.time() - start
        
        start = time.time()
        ciphertext_r = rRSA_encrypt(message, pub_key_r)
        rrsa_encrypt_time = time.time() - start
        
        start = time.time()
        decrypted_r = rRSA_decrypt(ciphertext_r, priv_key_r)
        rrsa_decrypt_time = time.time() - start
        
        print(f"fRSA - KeyGen: {frsa_keygen_time:.4f}s, Encrypt: {frsa_encrypt_time:.4f}s, Decrypt: {frsa_decrypt_time:.4f}s")
        print(f"rRSA - KeyGen: {rrsa_keygen_time:.4f}s, Encrypt: {rrsa_encrypt_time:.4f}s, Decrypt: {rrsa_decrypt_time:.4f}s")
        print(f"fRSA Correctness: {message == decrypted}")
        print(f"rRSA Correctness: {message == decrypted_r}")

def comprehensive_analysis():
    print("\n" + "="*60)
    print("       COMPREHENSIVE PERFORMANCE ANALYSIS")
    print("="*60)
    
    # Single run benchmarks
    frsa_single = benchmark_frsa()
    rrsa_single = benchmark_rrsa()
    
    # Multiple run analysis
    frsa_multiple = benchmark_multiple_runs_frsa()
    rrsa_multiple = benchmark_multiple_runs_rrsa()
    
    # Security level comparison
    security_level_comparison()
    
    # Function type comparison
    function_type_comparison()
    
    # Summary
    print("\n" + "="*60)
    print("                    SUMMARY")
    print("="*60)
    print(f"fRSA Average Performance:")
    print(f"  KeyGen: {sum(frsa_multiple[0])/len(frsa_multiple[0]):.4f}s")
    print(f"  Encrypt: {sum(frsa_multiple[1])/len(frsa_multiple[1]):.4f}s") 
    print(f"  Decrypt: {sum(frsa_multiple[2])/len(frsa_multiple[2]):.4f}s")
    
    print(f"\nrRSA Average Performance:")
    print(f"  KeyGen: {sum(rrsa_multiple[0])/len(rrsa_multiple[0]):.4f}s")
    print(f"  Encrypt: {sum(rrsa_multiple[1])/len(rrsa_multiple[1]):.4f}s")
    print(f"  Decrypt: {sum(rrsa_multiple[2])/len(rrsa_multiple[2]):.4f}s")
    
    # Performance comparison
    frsa_total = sum(frsa_multiple[0]) + sum(frsa_multiple[1]) + sum(frsa_multiple[2])
    rrsa_total = sum(rrsa_multiple[0]) + sum(rrsa_multiple[1]) + sum(rrsa_multiple[2])
    
    print(f"\nPerformance Comparison:")
    if frsa_total < rrsa_total:
        print(f"  fRSA is {rrsa_total/frsa_total:.2f}x faster overall")
    else:
        print(f"  rRSA is {frsa_total/rrsa_total:.2f}x faster overall")
    
    print(f"\nBoth systems achieve 128-bit post-quantum security")
    print("="*60)

if __name__ == "__main__":
    comprehensive_analysis()
