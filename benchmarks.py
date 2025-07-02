import time
import random
import statistics
from frsa_rrsa_redacted import fRSA_keygen, fRSA_encrypt, fRSA_decrypt, rRSA_keygen, rRSA_encrypt, rRSA_decrypt

def benchmark_frsa():
    print("=== fRSA Performance Benchmarks ===")
    
    # Key generation benchmark
    start = time.time()
    pub_key, priv_key = fRSA_keygen(security_level=128)
    keygen_time = time.time() - start
    print(f"Key Generation Time: {keygen_time:.4f} seconds")
    
    # Encryption benchmark
    message = random.randint(1000, 9999)
    start = time.time()
    ciphertext = fRSA_encrypt(message, pub_key)
    encrypt_time = time.time() - start
    print(f"Encryption Time: {encrypt_time:.6f} seconds")
    
    # Decryption benchmark
    start = time.time()
    decrypted = fRSA_decrypt(ciphertext, priv_key)
    decrypt_time = time.time() - start
    print(f"Decryption Time: {decrypt_time:.6f} seconds")
    
    # Correctness check
    correctness = (message == decrypted)
    print(f"Correctness Check: {correctness}")
    print(f"Original: {message}, Decrypted: {decrypted}")
    
    return {
        'keygen_time': keygen_time,
        'encrypt_time': encrypt_time,
        'decrypt_time': decrypt_time,
        'correctness': correctness,
        'total_time': keygen_time + encrypt_time + decrypt_time
    }

def benchmark_rrsa():
    print("\n=== rRSA Performance Benchmarks ===")
    
    # Key generation benchmark
    start = time.time()
    pub_key, priv_key = rRSA_keygen(security_level=128)
    keygen_time = time.time() - start
    print(f"Key Generation Time: {keygen_time:.4f} seconds")
    
    # Encryption benchmark
    message = random.randint(1000, 9999)
    start = time.time()
    ciphertext = rRSA_encrypt(message, pub_key)
    encrypt_time = time.time() - start
    print(f"Encryption Time: {encrypt_time:.6f} seconds")
    
    # Decryption benchmark
    start = time.time()
    decrypted = rRSA_decrypt(ciphertext, priv_key)
    decrypt_time = time.time() - start
    print(f"Decryption Time: {decrypt_time:.6f} seconds")
    
    # Correctness check
    correctness = (message == decrypted)
    print(f"Correctness Check: {correctness}")
    print(f"Original: {message}, Decrypted: {decrypted}")
    
    return {
        'keygen_time': keygen_time,
        'encrypt_time': encrypt_time,
        'decrypt_time': decrypt_time,
        'correctness': correctness,
        'total_time': keygen_time + encrypt_time + decrypt_time
    }

def run_multiple_benchmarks(runs=10):
    print(f"\n=== Running {runs} Benchmark Iterations ===")
    
    frsa_results = []
    rrsa_results = []
    
    for i in range(runs):
        print(f"\n--- Run {i+1}/{runs} ---")
        
        # fRSA benchmark
        frsa_result = benchmark_frsa()
        frsa_results.append(frsa_result)
        
        # rRSA benchmark  
        rrsa_result = benchmark_rrsa()
        rrsa_results.append(rrsa_result)
    
    return frsa_results, rrsa_results

def analyze_results(frsa_results, rrsa_results):
    print("\n" + "="*60)
    print("COMPREHENSIVE PERFORMANCE ANALYSIS")
    print("="*60)
    
    # Calculate statistics
    frsa_keygen_times = [r['keygen_time'] for r in frsa_results]
    frsa_encrypt_times = [r['encrypt_time'] for r in frsa_results] 
    frsa_decrypt_times = [r['decrypt_time'] for r in frsa_results]
    frsa_total_times = [r['total_time'] for r in frsa_results]
    
    rrsa_keygen_times = [r['keygen_time'] for r in rrsa_results]
    rrsa_encrypt_times = [r['encrypt_time'] for r in rrsa_results]
    rrsa_decrypt_times = [r['decrypt_time'] for r in rrsa_results]
    rrsa_total_times = [r['total_time'] for r in rrsa_results]
    
    # Print detailed comparison
    print("\nKEY GENERATION PERFORMANCE:")
    print("-" * 40)
    print(f"fRSA Average: {statistics.mean(frsa_keygen_times):.4f}s")
    print(f"fRSA Std Dev: {statistics.stdev(frsa_keygen_times):.4f}s")
    print(f"rRSA Average: {statistics.mean(rrsa_keygen_times):.4f}s") 
    print(f"rRSA Std Dev: {statistics.stdev(rrsa_keygen_times):.4f}s")
    
    keygen_winner = "fRSA" if statistics.mean(frsa_keygen_times) < statistics.mean(rrsa_keygen_times) else "rRSA"
    keygen_improvement = abs(statistics.mean(frsa_keygen_times) - statistics.mean(rrsa_keygen_times)) / max(statistics.mean(frsa_keygen_times), statistics.mean(rrsa_keygen_times)) * 100
    print(f"Winner: {keygen_winner} ({keygen_improvement:.1f}% faster)")
    
    print("\nENCRYPTION PERFORMANCE:")
    print("-" * 40)
    print(f"fRSA Average: {statistics.mean(frsa_encrypt_times):.6f}s")
    print(f"fRSA Std Dev: {statistics.stdev(frsa_encrypt_times):.6f}s")
    print(f"rRSA Average: {statistics.mean(rrsa_encrypt_times):.6f}s")
    print(f"rRSA Std Dev: {statistics.stdev(rrsa_encrypt_times):.6f}s")
    
    encrypt_winner = "fRSA" if statistics.mean(frsa_encrypt_times) < statistics.mean(rrsa_encrypt_times) else "rRSA"
    encrypt_improvement = abs(statistics.mean(frsa_encrypt_times) - statistics.mean(rrsa_encrypt_times)) / max(statistics.mean(frsa_encrypt_times), statistics.mean(rrsa_encrypt_times)) * 100
    print(f"Winner: {encrypt_winner} ({encrypt_improvement:.1f}% faster)")
    
    print("\nDECRYPTION PERFORMANCE:")
    print("-" * 40)
    print(f"fRSA Average: {statistics.mean(frsa_decrypt_times):.6f}s")
    print(f"fRSA Std Dev: {statistics.stdev(frsa_decrypt_times):.6f}s")
    print(f"rRSA Average: {statistics.mean(rrsa_decrypt_times):.6f}s")
    print(f"rRSA Std Dev: {statistics.stdev(rrsa_decrypt_times):.6f}s")
    
    decrypt_winner = "fRSA" if statistics.mean(frsa_decrypt_times) < statistics.mean(rrsa_decrypt_times) else "rRSA"
    decrypt_improvement = abs(statistics.mean(frsa_decrypt_times) - statistics.mean(rrsa_decrypt_times)) / max(statistics.mean(frsa_decrypt_times), statistics.mean(rrsa_decrypt_times)) * 100
    print(f"Winner: {decrypt_winner} ({decrypt_improvement:.1f}% faster)")
    
    print("\nOVERALL PERFORMANCE:")
    print("-" * 40)
    print(f"fRSA Total Average: {statistics.mean(frsa_total_times):.4f}s")
    print(f"rRSA Total Average: {statistics.mean(rrsa_total_times):.4f}s")
    
    overall_winner = "fRSA" if statistics.mean(frsa_total_times) < statistics.mean(rrsa_total_times) else "rRSA"
    overall_improvement = abs(statistics.mean(frsa_total_times) - statistics.mean(rrsa_total_times)) / max(statistics.mean(frsa_total_times), statistics.mean(rrsa_total_times)) * 100
    
    print(f"\nOVERALL WINNER: {overall_winner}")
    print(f"Performance Advantage: {overall_improvement:.1f}% faster")
    
    # Correctness summary
    frsa_correctness = all(r['correctness'] for r in frsa_results)
    rrsa_correctness = all(r['correctness'] for r in rrsa_results)
    
    print(f"\nCORRECTNESS:")
    print(f"fRSA: {'PASS' if frsa_correctness else 'FAIL'}")
    print(f"rRSA: {'PASS' if rrsa_correctness else 'FAIL'}")
    
    return {
        'keygen_winner': keygen_winner,
        'encrypt_winner': encrypt_winner, 
        'decrypt_winner': decrypt_winner,
        'overall_winner': overall_winner,
        'overall_improvement': overall_improvement
    }

def security_level_comparison():
    print("\n" + "="*60)
    print("SECURITY LEVEL COMPARISON")
    print("="*60)
    
    security_levels = [128, 256]
    
    for level in security_levels:
        print(f"\n--- Security Level: {level} bits ---")
        
        # fRSA
        start = time.time()
        pub_key, priv_key = fRSA_keygen(security_level=level)
        frsa_time = time.time() - start
        
        # rRSA
        start = time.time()
        pub_key, priv_key = rRSA_keygen(security_level=level)
        rrsa_time = time.time() - start
        
        print(f"fRSA Key Generation: {frsa_time:.4f}s")
        print(f"rRSA Key Generation: {rrsa_time:.4f}s")
        
        winner = "fRSA" if frsa_time < rrsa_time else "rRSA"
        improvement = abs(frsa_time - rrsa_time) / max(frsa_time, rrsa_time) * 100
        print(f"Winner: {winner} ({improvement:.1f}% faster)")

def main():
    print("CRYPTOGRAPHIC PERFORMANCE BENCHMARK SUITE")
    print("="*60)
    
    # Single run benchmarks
    print("\nSINGLE RUN BENCHMARKS:")
    frsa_single = benchmark_frsa()
    rrsa_single = benchmark_rrsa()
    
    # Multiple run analysis
    frsa_results, rrsa_results = run_multiple_benchmarks(runs=5)
    
    # Comprehensive analysis
    analysis = analyze_results(frsa_results, rrsa_results)
    
    # Security level comparison
    security_level_comparison()
    
    # Final summary
    print("\n" + "="*60)
    print("FINAL SUMMARY")
    print("="*60)
    print(f"Overall Performance Winner: {analysis['overall_winner']}")
    print(f"Performance Advantage: {analysis['overall_improvement']:.1f}%")
    print("="*60)

if __name__ == "__main__":
    main()
