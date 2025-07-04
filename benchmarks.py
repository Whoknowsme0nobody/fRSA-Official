import time
import statistics
import matplotlib.pyplot as plt
import numpy as np
from typing import Dict, List, Tuple
import sys
import os

# Add the current directory to path to import our modules
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    from frsa_rrsa_redacted import fRSA_keygen, fRSA_encrypt, fRSA_decrypt
    from Crypto.PublicKey import RSA
    from Crypto.Cipher import PKCS1_OAEP
    from Crypto.Random import get_random_bytes
    print("✓ All imports successful")
except ImportError as e:
    print(f"Import error: {e}")
    print("Please ensure all required modules are installed")
    sys.exit(1)

def benchmark_frsa(key_size: int = 1024, num_iterations: int = 10) -> Dict[str, float]:
    """Benchmark fRSA operations with error handling"""
    
    print(f"\n=== fRSA Benchmarks (Key Size: {key_size} bits) ===")
    
    # Key Generation Benchmark
    keygen_times = []
    for i in range(num_iterations):
        try:
            start_time = time.time()
            pub_key, priv_key = fRSA_keygen(key_size)
            end_time = time.time()
            keygen_times.append(end_time - start_time)
            print(f"Key generation {i+1}/{num_iterations}: {end_time - start_time:.4f}s")
        except Exception as e:
            print(f"Key generation failed on iteration {i+1}: {e}")
            continue
    
    if not keygen_times:
        raise RuntimeError("All key generation attempts failed")
    
    # Use the last successfully generated key pair
    print(f"Using key pair from iteration {len(keygen_times)}")
    
    # Encryption Benchmark
    test_messages = [42, 123, 1000, 9999]  # Small test messages
    encryption_times = []
    decryption_times = []
    
    for msg in test_messages:
        # Ensure message is smaller than modulus
        n = pub_key[0]
        if msg >= n:
            msg = msg % (n - 1)
        
        for i in range(num_iterations // len(test_messages)):
            try:
                # Encryption
                start_time = time.time()
                ciphertext = fRSA_encrypt(msg, pub_key)
                end_time = time.time()
                encryption_times.append(end_time - start_time)
                
                # Decryption
                start_time = time.time()
                decrypted = fRSA_decrypt(ciphertext, priv_key)
                end_time = time.time()
                decryption_times.append(end_time - start_time)
                
                # Verify correctness
                if decrypted != msg:
                    print(f"⚠️  Verification failed: {msg} -> {decrypted}")
                else:
                    print(f"✓ Message {msg} encrypted/decrypted successfully")
                
            except Exception as e:
                print(f"Encryption/Decryption failed for message {msg}: {e}")
                continue
    
    if not encryption_times or not decryption_times:
        raise RuntimeError("All encryption/decryption attempts failed")
    
    # Calculate statistics
    results = {
        'key_generation': {
            'mean': statistics.mean(keygen_times),
            'median': statistics.median(keygen_times),
            'std': statistics.stdev(keygen_times) if len(keygen_times) > 1 else 0,
            'min': min(keygen_times),
            'max': max(keygen_times)
        },
        'encryption': {
            'mean': statistics.mean(encryption_times),
            'median': statistics.median(encryption_times),
            'std': statistics.stdev(encryption_times) if len(encryption_times) > 1 else 0,
            'min': min(encryption_times),
            'max': max(encryption_times)
        },
        'decryption': {
            'mean': statistics.mean(decryption_times),
            'median': statistics.median(decryption_times),
            'std': statistics.stdev(decryption_times) if len(decryption_times) > 1 else 0,
            'min': min(decryption_times),
            'max': max(decryption_times)
        }
    }
    
    return results

def benchmark_standard_rsa(key_size: int = 1024, num_iterations: int = 10) -> Dict[str, float]:
    """Benchmark standard RSA for comparison"""
    
    print(f"\n=== Standard RSA Benchmarks (Key Size: {key_size} bits) ===")
    
    # Key Generation Benchmark
    keygen_times = []
    for i in range(num_iterations):
        try:
            start_time = time.time()
            key = RSA.generate(key_size)
            end_time = time.time()
            keygen_times.append(end_time - start_time)
            print(f"Key generation {i+1}/{num_iterations}: {end_time - start_time:.4f}s")
        except Exception as e:
            print(f"RSA key generation failed on iteration {i+1}: {e}")
            continue
    
    if not keygen_times:
        raise RuntimeError("All RSA key generation attempts failed")
    
    # Encryption/Decryption Benchmark
    test_data = get_random_bytes(64)  # 64 bytes of random data
    encryption_times = []
    decryption_times = []
    
    for i in range(num_iterations):
        try:
            key = RSA.generate(key_size)
            cipher = PKCS1_OAEP.new(key)
            
            # Encryption
            start_time = time.time()
            ciphertext = cipher.encrypt(test_data)
            end_time = time.time()
            encryption_times.append(end_time - start_time)
            
            # Decryption
            start_time = time.time()
            decrypted = cipher.decrypt(ciphertext)
            end_time = time.time()
            decryption_times.append(end_time - start_time)
            
            # Verify
            if decrypted != test_data:
                print(f"⚠️  RSA verification failed")
            else:
                print(f"✓ RSA encryption/decryption successful")
                
        except Exception as e:
            print(f"RSA encryption/decryption failed: {e}")
            continue
    
    if not encryption_times or not decryption_times:
        raise RuntimeError("All RSA encryption/decryption attempts failed")
    
    # Calculate statistics
    results = {
        'key_generation': {
            'mean': statistics.mean(keygen_times),
            'median': statistics.median(keygen_times),
            'std': statistics.stdev(keygen_times) if len(keygen_times) > 1 else 0,
            'min': min(keygen_times),
            'max': max(keygen_times)
        },
        'encryption': {
            'mean': statistics.mean(encryption_times),
            'median': statistics.median(encryption_times),
            'std': statistics.stdev(encryption_times) if len(encryption_times) > 1 else 0,
            'min': min(encryption_times),
            'max': max(encryption_times)
        },
        'decryption': {
            'mean': statistics.mean(decryption_times),
            'median': statistics.median(decryption_times),
            'std': statistics.stdev(decryption_times) if len(decryption_times) > 1 else 0,
            'min': min(decryption_times),
            'max': max(decryption_times)
        }
    }
    
    return results

def create_comparison_charts(frsa_results: Dict, rsa_results: Dict, key_size: int):
    """Create comparison charts"""
    
    operations = ['key_generation', 'encryption', 'decryption']
    operation_labels = ['Key Generation', 'Encryption', 'Decryption']
    
    frsa_means = [frsa_results[op]['mean'] for op in operations]
    rsa_means = [rsa_results[op]['mean'] for op in operations]
    
    x = np.arange(len(operation_labels))
    width = 0.35
    
    fig, ax = plt.subplots(figsize=(12, 8))
    bars1 = ax.bar(x - width/2, frsa_means, width, label='fRSA', alpha=0.8, color='blue')
    bars2 = ax.bar(x + width/2, rsa_means, width, label='Standard RSA', alpha=0.8, color='red')
    
    ax.set_xlabel('Operations')
    ax.set_ylabel('Time (seconds)')
    ax.set_title(f'fRSA vs Standard RSA Performance Comparison ({key_size}-bit keys)')
    ax.set_xticks(x)
    ax.set_xticklabels(operation_labels)
    ax.legend()
    ax.grid(True, alpha=0.3)
    
    # Add value labels on bars
    def add_value_labels(bars):
        for bar in bars:
            height = bar.get_height()
            ax.annotate(f'{height:.4f}s',
                       xy=(bar.get_x() + bar.get_width() / 2, height),
                       xytext=(0, 3),  # 3 points vertical offset
                       textcoords="offset points",
                       ha='center', va='bottom',
                       fontsize=9)
    
    add_value_labels(bars1)
    add_value_labels(bars2)
    
    plt.tight_layout()
    plt.savefig(f'frsa_vs_rsa_comparison_{key_size}bit.png', dpi=300, bbox_inches='tight')
    plt.show()

def print_detailed_results(results: Dict, algorithm: str):
    """Print detailed benchmark results"""
    print(f"\n=== {algorithm} Detailed Results ===")
    
    for operation, stats in results.items():
        print(f"\n{operation.replace('_', ' ').title()}:")
        print(f"  Mean: {stats['mean']:.6f} seconds")
        print(f"  Median: {stats['median']:.6f} seconds")
        print(f"  Std Dev: {stats['std']:.6f} seconds")
        print(f"  Min: {stats['min']:.6f} seconds")
        print(f"  Max: {stats['max']:.6f} seconds")

def main():
    """Main benchmarking function"""
    
    key_sizes = [1024, 2048]
    num_iterations = 5  # Reduced for faster testing
    
    print("🚀 Starting fRSA vs Standard RSA Benchmarking")
    print("=" * 50)
    
    for key_size in key_sizes:
        try:
            print(f"\n🔑 Testing with {key_size}-bit keys")
            
            # Benchmark fRSA
            print("\n🧮 Benchmarking fRSA...")
            frsa_results = benchmark_frsa(key_size, num_iterations)
            print_detailed_results(frsa_results, "fRSA")
            
            # Benchmark standard RSA
            print("\n🔐 Benchmarking Standard RSA...")
            rsa_results = benchmark_standard_rsa(key_size, num_iterations)
            print_detailed_results(rsa_results, "Standard RSA")
            
            # Create comparison charts
            print("\n📊 Creating comparison charts...")
            create_comparison_charts(frsa_results, rsa_results, key_size)
            
            # Performance comparison summary
            print(f"\n📈 Performance Summary for {key_size}-bit keys:")
            print("-" * 50)
            
            for operation in ['key_generation', 'encryption', 'decryption']:
                frsa_time = frsa_results[operation]['mean']
                rsa_time = rsa_results[operation]['mean']
                
                if rsa_time > 0:
                    ratio = frsa_time / rsa_time
                    if ratio > 1:
                        print(f"{operation.replace('_', ' ').title()}: fRSA is {ratio:.2f}x SLOWER than RSA")
                    else:
                        print(f"{operation.replace('_', ' ').title()}: fRSA is {1/ratio:.2f}x FASTER than RSA")
                else:
                    print(f"{operation.replace('_', ' ').title()}: Cannot compare (RSA time = 0)")
                    
        except Exception as e:
            print(f"❌ Benchmarking failed for {key_size}-bit keys: {e}")
            import traceback
            traceback.print_exc()
            continue
    
    print("\n✅ Benchmarking completed!")

if __name__ == "__main__":
    main()
