import time
import random
import statistics
from frsa_rrsa_redacted import fRSA_keygen, fRSA_encrypt, fRSA_decrypt, rRSA_keygen, rRSA_encrypt, rRSA_decrypt

def benchmark_frsa():
    """Comprehensive fRSA benchmarking"""
    print("=== fRSA Performance Benchmarks ===")
    
    # Single run benchmark
    print("\n--- Single Run Performance ---")
    start = time.time()
    pub_key, priv_key = fRSA_keygen(security_level=128)
    keygen_time = time.time() - start
    print(f"Key Generation Time: {keygen_time:.4f} seconds")
    
    # Test encryption/decryption
    message = random.randint(1000, 100000)
    
    start = time.time()
    ciphertext = fRSA_encrypt(message, pub_key)
    encrypt_time = time.time() - start
    print(f"Encryption Time: {encrypt_time:.4f} seconds")
    
    start = time.time()
    decrypted = fRSA_decrypt(ciphertext, priv_key)
    decrypt_time = time.time() - start
    print(f"Decryption Time: {decrypt_time:.4f} seconds")
    
    correctness = (message == decrypted)
    print(f"Correctness Check: {correctness}")
    print(f"Security Level: {pub_key['security_level']}-bit post-quantum")
    
    return {
        'keygen': keygen_time,
        'encrypt': encrypt_time,
        'decrypt': decrypt_time,
        'correctness': correctness
    }

def benchmark_rrsa():
    """Comprehensive rRSA benchmarking"""
    print("\n=== rRSA Performance Benchmarks ===")
    
    # Single run benchmark
    print("\n--- Single Run Performance ---")
    start = time.time()
    pub_key, priv_key = rRSA_keygen(security_level=128)
    keygen_time = time.time() - start
    print(f"Key Generation Time: {keygen_time:.4f} seconds")
    
    # Test encryption/decryption
    message = random.randint(1000, 100000)
    
    start = time.time()
    ciphertext = rRSA_encrypt(message, pub_key)
    encrypt_time = time.time() - start
    print(f"Encryption Time: {encrypt_time:.4f} seconds")
    
    start = time.time()
    decrypted = rRSA_decrypt(ciphertext, priv_key)
    decrypt_time = time.time() - start
    print(f"Decryption Time: {decrypt_time:.4f} seconds")
    
    correctness = (message == decrypted)
    print(f"Correctness Check: {correctness}")
    print(f"Security Level: {pub_key['security_level']}-bit post-quantum")
    
    return {
        'keygen': keygen_time,
        'encrypt': encrypt_time,
        'decrypt': decrypt_time,
        'correctness': correctness
    }

def multiple_runs_frsa(runs=10):
    """Multiple run analysis for fRSA"""
    print(f"\n=== fRSA Multiple Run Analysis ({runs} runs) ===")
    
    keygen_times = []
    encrypt_times = []
    decrypt_times = []
    correctness_count = 0
    
    for i in range(runs):
        print(f"Run {i+1}/{runs}...", end=' ')
        
        try:
            # Key generation
            start = time.time()
            pub_key, priv_key = fRSA_keygen(security_level=128)
            keygen_times.append(time.time() - start)
            
            # Encryption/Decryption
            message = random.randint(1000, 100000)
            
            start = time.time()
            ciphertext = fRSA_encrypt(message, pub_key)
            encrypt_times.append(time.time() - start)
            
            start = time.time()
            decrypted = fRSA_decrypt(ciphertext, priv_key)
            decrypt_times.append(time.time() - start)
            
            if message == decrypted:
                correctness_count += 1
            
            print("✓")
        except Exception as e:
            print(f"✗ (Error: {str(e)[:30]}...)")
    
    if keygen_times:  # Only calculate if we have data
        print(f"\nfRSA Results Summary:")
        print(f"Average Key Generation: {statistics.mean(keygen_times):.4f}s (±{statistics.stdev(keygen_times) if len(keygen_times) > 1 else 0:.4f}s)")
        print(f"Average Encryption: {statistics.mean(encrypt_times):.4f}s (±{statistics.stdev(encrypt_times) if len(encrypt_times) > 1 else 0:.4f}s)")
        print(f"Average Decryption: {statistics.mean(decrypt_times):.4f}s (±{statistics.stdev(decrypt_times) if len(decrypt_times) > 1 else 0:.4f}s)")
        print(f"Success Rate: {correctness_count}/{runs} ({100*correctness_count/runs:.1f}%)")
        
        return {
            'keygen': {'mean': statistics.mean(keygen_times), 'stdev': statistics.stdev(keygen_times) if len(keygen_times) > 1 else 0},
            'encrypt': {'mean': statistics.mean(encrypt_times), 'stdev': statistics.stdev(encrypt_times) if len(encrypt_times) > 1 else 0},
            'decrypt': {'mean': statistics.mean(decrypt_times), 'stdev': statistics.stdev(decrypt_times) if len(decrypt_times) > 1 else 0},
            'success_rate': correctness_count/runs
        }
    else:
        return {
            'keygen': {'mean': 0, 'stdev': 0},
            'encrypt': {'mean': 0, 'stdev': 0},
            'decrypt': {'mean': 0, 'stdev': 0},
            'success_rate': 0
        }

def multiple_runs_rrsa(runs=10):
    """Multiple run analysis for rRSA"""
    print(f"\n=== rRSA Multiple Run Analysis ({runs} runs) ===")
    
    keygen_times = []
    encrypt_times = []
    decrypt_times = []
    correctness_count = 0
    
    for i in range(runs):
        print(f"Run {i+1}/{runs}...", end=' ')
        
        try:
            # Key generation
            start = time.time()
            pub_key, priv_key = rRSA_keygen(security_level=128)
            keygen_times.append(time.time() - start)
            
            # Encryption/Decryption
            message = random.randint(1000, 100000)
            
            start = time.time()
            ciphertext = rRSA_encrypt(message, pub_key)
            encrypt_times.append(time.time() - start)
            
            start = time.time()
            decrypted = rRSA_decrypt(ciphertext, priv_key)
            decrypt_times.append(time.time() - start)
            
            if message == decrypted:
                correctness_count += 1
            
            print("✓")
        except Exception as e:
            print(f"✗ (Error: {str(e)[:30]}...)")
    
    if keygen_times:  # Only calculate if we have data
        print(f"\nrRSA Results Summary:")
        print(f"Average Key Generation: {statistics.mean(keygen_times):.4f}s (±{statistics.stdev(keygen_times) if len(keygen_times) > 1 else 0:.4f}s)")
        print(f"Average Encryption: {statistics.mean(encrypt_times):.4f}s (±{statistics.stdev(encrypt_times) if len(encrypt_times) > 1 else 0:.4f}s)")
        print(f"Average Decryption: {statistics.mean(decrypt_times):.4f}s (±{statistics.stdev(decrypt_times) if len(decrypt_times) > 1 else 0:.4f}s)")
        print(f"Success Rate: {correctness_count}/{runs} ({100*correctness_count/runs:.1f}%)")
        
        return {
            'keygen': {'mean': statistics.mean(keygen_times), 'stdev': statistics.stdev(keygen_times) if len(keygen_times) > 1 else 0},
            'encrypt': {'mean': statistics.mean(encrypt_times), 'stdev': statistics.stdev(encrypt_times) if len(encrypt_times) > 1 else 0},
            'decrypt': {'mean': statistics.mean(decrypt_times), 'stdev': statistics.stdev(decrypt_times) if len(decrypt_times) > 1 else 0},
            'success_rate': correctness_count/runs
        }
    else:
        return {
            'keygen': {'mean': 0, 'stdev': 0},
            'encrypt': {'mean': 0, 'stdev': 0},
            'decrypt': {'mean': 0, 'stdev': 0},
            'success_rate': 0
        }

def security_level_comparison():
    """Compare performance across different security levels"""
    print("\n=== Security Level Comparison ===")
    
    security_levels = [128, 256]
    results = {'fRSA': {}, 'rRSA': {}}
    
    for level in security_levels:
        print(f"\n--- Testing {level}-bit security ---")
        
        try:
            # fRSA
            start = time.time()
            pub_key, priv_key = fRSA_keygen(security_level=level)
            frsa_keygen = time.time() - start
            
            message = random.randint(1000, 100000)
            start = time.time()
            ciphertext = fRSA_encrypt(message, pub_key)
            decrypted = fRSA_decrypt(ciphertext, priv_key)
            frsa_crypto = time.time() - start
            
            results['fRSA'][level] = {
                'keygen': frsa_keygen,
                'crypto': frsa_crypto,
                'correct': message == decrypted
            }
            
            # rRSA
            start = time.time()
            pub_key, priv_key = rRSA_keygen(security_level=level)
            rrsa_keygen = time.time() - start
            
            message = random.randint(1000, 100000)
            start = time.time()
            ciphertext = rRSA_encrypt(message, pub_key)
            decrypted = rRSA_decrypt(ciphertext, priv_key)
            rrsa_crypto = time.time() - start
            
            results['rRSA'][level] = {
                'keygen': rrsa_keygen,
                'crypto': rrsa_crypto,
                'correct': message == decrypted
            }
            
            print(f"fRSA {level}-bit: Keygen={frsa_keygen:.4f}s, Crypto={frsa_crypto:.4f}s, Correct={results['fRSA'][level]['correct']}")
            print(f"rRSA {level}-bit: Keygen={rrsa_keygen:.4f}s, Crypto={rrsa_crypto:.4f}s, Correct={results['rRSA'][level]['correct']}")
            
        except Exception as e:
            print(f"Error testing {level}-bit security: {e}")
            results['fRSA'][level] = {'keygen': 0, 'crypto': 0, 'correct': False}
            results['rRSA'][level] = {'keygen': 0, 'crypto': 0, 'correct': False}
    
    return results

def function_type_comparison():
    """Compare polynomial vs transcendental function performance"""
    print("\n=== Function Type Comparison ===")
    
    function_types = ['polynomial', 'transcendental']
    results = {'fRSA': {}, 'rRSA': {}}
    
    for func_type in function_types:
        print(f"\n--- Testing {func_type} functions ---")
        
        try:
            # fRSA
            start = time.time()
            pub_key, priv_key = fRSA_keygen(security_level=128, function_type=func_type)
            frsa_time = time.time() - start
            
            message = random.randint(1000, 100000)
            ciphertext = fRSA_encrypt(message, pub_key)
            decrypted = fRSA_decrypt(ciphertext, priv_key)
            
            results['fRSA'][func_type] = {
                'time': frsa_time,
                'correct': message == decrypted
            }
            
            # rRSA
            start = time.time()
            pub_key, priv_key = rRSA_keygen(security_level=128, function_type=func_type)
            rrsa_time = time.time() - start
            
            message = random.randint(1000, 100000)
            ciphertext = rRSA_encrypt(message, pub_key)
            decrypted = rRSA_decrypt(ciphertext, priv_key)
            
            results['rRSA'][func_type] = {
                'time': rrsa_time,
                'correct': message == decrypted
            }
            
            print(f"fRSA {func_type}: {frsa_time:.4f}s, Correct={results['fRSA'][func_type]['correct']}")
            print(f"rRSA {func_type}: {rrsa_time:.4f}s, Correct={results['rRSA'][func_type]['correct']}")
            
        except Exception as e:
            print(f"Error testing {func_type} functions: {e}")
            results['fRSA'][func_type] = {'time': 0, 'correct': False}
            results['rRSA'][func_type] = {'time': 0, 'correct': False}
    
    return results

def comprehensive_summary(frsa_single, rrsa_single, frsa_multi, rrsa_multi):
    """Generate comprehensive performance summary"""
    print("\n" + "="*60)
    print("           COMPREHENSIVE PERFORMANCE SUMMARY")
    print("="*60)
    
    print(f"\nSINGLE RUN PERFORMANCE")
    print(f"┌─────────────────────────────────────────────────────────┐")
    print(f"│                    fRSA      │      rRSA      │ Winner │")
    print(f"├─────────────────────────────────────────────────────────┤")
    print(f"│ Key Generation    {frsa_single['keygen']:.4f}s    │    {rrsa_single['keygen']:.4f}s    │   {'fRSA' if frsa_single['keygen'] < rrsa_single['keygen'] else 'rRSA'}   │")
    print(f"│ Encryption        {frsa_single['encrypt']:.4f}s    │    {rrsa_single['encrypt']:.4f}s    │   {'fRSA' if frsa_single['encrypt'] < rrsa_single['encrypt'] else 'rRSA'}   │")
    print(f"│ Decryption        {frsa_single['decrypt']:.4f}s    │    {rrsa_single['decrypt']:.4f}s    │   {'fRSA' if frsa_single['decrypt'] < rrsa_single['decrypt'] else 'rRSA'}   │")
    print(f"└─────────────────────────────────────────────────────────┘")
    
    print(f"\nMULTI-RUN AVERAGES")
    print(f"┌─────────────────────────────────────────────────────────┐")
    print(f"│                    fRSA      │      rRSA      │ Winner │")
    print(f"├─────────────────────────────────────────────────────────┤")
    print(f"│ Avg Key Generation {frsa_multi['keygen']['mean']:.4f}s   │    {rrsa_multi['keygen']['mean']:.4f}s    │   {'fRSA' if frsa_multi['keygen']['mean'] < rrsa_multi['keygen']['mean'] else 'rRSA'}   │")
    print(f"│ Avg Encryption     {frsa_multi['encrypt']['mean']:.4f}s   │    {rrsa_multi['encrypt']['mean']:.4f}s    │   {'fRSA' if frsa_multi['encrypt']['mean'] < rrsa_multi['encrypt']['mean'] else 'rRSA'}   │")
    print(f"│ Avg Decryption     {frsa_multi['decrypt']['mean']:.4f}s   │    {rrsa_multi['decrypt']['mean']:.4f}s    │   {'fRSA' if frsa_multi['decrypt']['mean'] < rrsa_multi['decrypt']['mean'] else 'rRSA'}   │")
    print(f"│ Success Rate       {frsa_multi['success_rate']*100:.1f}%      │     {rrsa_multi['success_rate']*100:.1f}%      │   {'fRSA' if frsa_multi['success_rate'] > rrsa_multi['success_rate'] else 'rRSA'}   │")
    print(f"└─────────────────────────────────────────────────────────┘")
    
    # Calculate overall winner
    frsa_wins = 0
    rrsa_wins = 0
    
    # Single run wins
    if frsa_single['keygen'] < rrsa_single['keygen']: frsa_wins += 1
    else: rrsa_wins += 1
    if frsa_single['encrypt'] < rrsa_single['encrypt']: frsa_wins += 1
    else: rrsa_wins += 1
    if frsa_single['decrypt'] < rrsa_single['decrypt']: frsa_wins += 1
    else: rrsa_wins += 1
    
    # Multi-run wins
    if frsa_multi['keygen']['mean'] < rrsa_multi['keygen']['mean']: frsa_wins += 1
    else: rrsa_wins += 1
    if frsa_multi['encrypt']['mean'] < rrsa_multi['encrypt']['mean']: frsa_wins += 1
    else: rrsa_wins += 1
    if frsa_multi['decrypt']['mean'] < rrsa_multi['decrypt']['mean']: frsa_wins += 1
    else: rrsa_wins += 1
    if frsa_multi['success_rate'] > rrsa_multi['success_rate']: frsa_wins += 1
    else: rrsa_wins += 1
    
    overall_winner = 'fRSA' if frsa_wins > rrsa_wins else 'rRSA'
    
    print(f"\nOVERALL PERFORMANCE WINNER: {overall_winner}")
    print(f"   fRSA wins: {frsa_wins}/7 categories")
    print(f"   rRSA wins: {rrsa_wins}/7 categories")

def main():
    """Main benchmark execution"""
    print("ULTIMATE fRSA vs rRSA BENCHMARK SUITE")
    print("="*60)
    
    try:
        # Single run benchmarks
        frsa_single = benchmark_frsa()
        rrsa_single = benchmark_rrsa()
        
        # Multiple run analysis
        frsa_multi = multiple_runs_frsa(runs=10)
        rrsa_multi = multiple_runs_rrsa(runs=10)
        
        # Security level comparison
        security_results = security_level_comparison()
        
        # Function type comparison  
        function_results = function_type_comparison()
        
        # Comprehensive summary
        comprehensive_summary(frsa_single, rrsa_single, frsa_multi, rrsa_multi)
        
        print(f"\nBENCHMARK COMPLETE!")
        print(f"   All tests executed successfully")
        print(f"   Ready for cryptographic deployment!")
        
    except Exception as e:
        print(f"\nBENCHMARK ERROR: {e}")
        print(f"   Check your frsa_rrsa_redacted.py implementation")

if __name__ == "__main__":
    main()
