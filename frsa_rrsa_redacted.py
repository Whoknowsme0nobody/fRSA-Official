"""
Transcendental Function-Based Encryption (TFBE) Implementation
Enhanced Multi-Layer Cryptographic System

Version 2.0 - July 2025
Author: Amine Belachhab
"""

import math
import random
import time
from decimal import Decimal, getcontext
from typing import Tuple, Dict, Any

class TFBEKeyPair:
    """TFBE Key Pair Container"""
    def __init__(self, public_key: Dict[str, Any], private_key: Dict[str, Any]):
        self.public_key = public_key
        self.private_key = private_key

class TFBECryptosystem:
    """
    Transcendental Function-Based Encryption System
    
    Implements the multi-layer security architecture with:
    - Exponential component (m^k)
    - Transcendental component (e^cos(km))
    - Auxiliary transcendental function
    - Modular arithmetic
    - Precision control
    """
    
    def __init__(self, security_level: int = 128):
        self.security_level = security_level
        self.precision_digits = max(security_level, 128)
        self.max_iterations = 50
        self.tolerance = Decimal(10) ** (-self.precision_digits + 10)
        
        # Set high precision arithmetic context
        getcontext().prec = self.precision_digits + 64
        
    def _generate_large_prime(self, bits: int) -> int:
        """Generate a large prime number for the given bit length"""
        # Simplified prime generation - in production use proper primality testing
        while True:
            candidate = random.getrandbits(bits)
            candidate |= (1 << bits - 1) | 1  # Set MSB and LSB
            
            # Simple primality test (Miller-Rabin would be better)
            if self._is_prime(candidate):
                return candidate
                
    def _is_prime(self, n: int, k: int = 5) -> bool:
        """Simple primality test"""
        if n < 2:
            return False
        if n == 2 or n == 3:
            return True
        if n % 2 == 0:
            return False
            
        # Miller-Rabin primality test (simplified)
        for _ in range(k):
            a = random.randrange(2, n - 1)
            if pow(a, n - 1, n) != 1:
                return False
        return True
        
    def _generate_secret_key(self) -> Decimal:
        """Generate a secret real-valued key"""
        # Generate random real number with specified precision
        integer_part = random.randint(2, 1000)
        fractional_part = random.getrandbits(self.precision_digits * 3)
        
        # Combine to form high-precision real number
        k = Decimal(integer_part) + Decimal(fractional_part) / (Decimal(10) ** self.precision_digits)
        return k
        
    def _compute_transcendental(self, k: Decimal, m: Decimal) -> Decimal:
        """Compute transcendental component: e^cos(km)"""
        # Use Taylor series for high precision
        km = k * m
        cos_km = self._cosine_taylor(km)
        exp_cos = self._exponential_taylor(cos_km)
        return exp_cos
        
    def _compute_auxiliary(self, k: Decimal, m: Decimal) -> Decimal:
        """Compute auxiliary function: sin(k²m) + cos(km²) + tan(km·π/4)"""
        k2 = k * k
        m2 = m * m
        
        # Component calculations
        sin_k2m = self._sine_taylor(k2 * m)
        cos_km2 = self._cosine_taylor(k * m2)
        tan_term = self._tangent_taylor(k * m * Decimal('0.78539816339'))  # π/4
        
        return sin_k2m + cos_km2 + tan_term
        
    def _cosine_taylor(self, x: Decimal, terms: int = 50) -> Decimal:
        """High-precision cosine using Taylor series"""
        result = Decimal(1)
        x_squared = x * x
        term = Decimal(1)
        
        for n in range(1, terms):
            term *= -x_squared / (Decimal(2*n-1) * Decimal(2*n))
            result += term
            
            if abs(term) < self.tolerance:
                break
                
        return result
        
    def _sine_taylor(self, x: Decimal, terms: int = 50) -> Decimal:
        """High-precision sine using Taylor series"""
        result = x
        x_squared = x * x
        term = x
        
        for n in range(1, terms):
            term *= -x_squared / (Decimal(2*n) * Decimal(2*n+1))
            result += term
            
            if abs(term) < self.tolerance:
                break
                
        return result
        
    def _exponential_taylor(self, x: Decimal, terms: int = 100) -> Decimal:
        """High-precision exponential using Taylor series"""
        result = Decimal(1)
        term = Decimal(1)
        
        for n in range(1, terms):
            term *= x / Decimal(n)
            result += term
            
            if abs(term) < self.tolerance:
                break
                
        return result
        
    def _tangent_taylor(self, x: Decimal) -> Decimal:
        """High-precision tangent using Taylor series"""
        # tan(x) = sin(x) / cos(x)
        sin_x = self._sine_taylor(x)
        cos_x = self._cosine_taylor(x)
        
        if abs(cos_x) < self.tolerance:
            return Decimal('inf')  # tan is undefined
            
        return sin_x / cos_x
        
    def _encryption_function(self, m: Decimal, k: Decimal, N: int) -> int:
        """Core encryption function f(m,k)"""
        # Layer 1: Exponential component
        exponential = m ** k
        
        # Layer 2: Transcendental component
        transcendental = self._compute_transcendental(k, m)
        
        # Layer 3: Auxiliary function
        auxiliary = self._compute_auxiliary(k, m)
        
        # Combine all layers
        result = exponential * transcendental * auxiliary
        
        # Layer 4: Precision control and modular reduction
        scaled = result * (Decimal(10) ** self.precision_digits)
        final_result = int(scaled) % N
        
        return final_result
        
    def _compute_derivative(self, m: Decimal, k: Decimal) -> Decimal:
        """Compute derivative df/dm for Newton-Raphson"""
        # Simplified derivative computation
        # In practice, this would be the full analytical derivative
        delta = Decimal(1) / (Decimal(10) ** (self.precision_digits // 2))
        
        f_m = self._encryption_function(m, k, 2**64)  # Large modulus for derivative
        f_m_delta = self._encryption_function(m + delta, k, 2**64)
        
        return (f_m_delta - f_m) / delta
        
    def generate_keypair(self) -> TFBEKeyPair:
        """Generate TFBE key pair"""
        # Generate prime factors
        prime_bits = self.security_level // 2
        p = self._generate_large_prime(prime_bits)
        q = self._generate_large_prime(prime_bits)
        N = p * q
        
        # Generate secret key
        k = self._generate_secret_key()
        
        # Generate test vector for key validation
        test_vector = Decimal(42)  # Fixed test value
        validation_value = self._encryption_function(test_vector, k, N)
        
        # Construct key pair
        public_key = {
            'N': N,
            'precision': self.precision_digits,
            'validation': validation_value,
            'test_vector': test_vector
        }
        
        private_key = {
            'k': k,
            'p': p,
            'q': q,
            'N': N,
            'precision': self.precision_digits
        }
        
        return TFBEKeyPair(public_key, private_key)
        
    def encrypt(self, message: int, public_key: Dict[str, Any]) -> int:
        """Encrypt message using TFBE"""
        N = public_key['N']
        precision = public_key['precision']
        
        # Input validation
        if not (0 < message < N):
            raise ValueError(f"Message must be in range (0, {N})")
            
        # For encryption, we need to derive a public key parameter
        # This is a simplified version - in practice, use key derivation
        k_pub = Decimal(str(message)).ln() + Decimal(precision)
        
        m = Decimal(message)
        ciphertext = self._encryption_function(m, k_pub, N)
        
        return ciphertext
        
    def decrypt(self, ciphertext: int, private_key: Dict[str, Any]) -> int:
        """Decrypt ciphertext using TFBE"""
        k = private_key['k']
        N = private_key['N']
        
        # Newton-Raphson method for function inversion
        # Initial guess based on ciphertext
        x = Decimal(ciphertext) / Decimal(N)
        
        for iteration in range(self.max_iterations):
            # Compute function value and derivative
            f_x = self._encryption_function(x, k, N) - ciphertext
            f_prime_x = self._compute_derivative(x, k)
            
            if abs(f_prime_x) < self.tolerance:
                break
                
            # Newton-Raphson update
            x_new = x - f_x / f_prime_x
            
            # Check convergence
            if abs(x_new - x) < self.tolerance:
                break
                
            x = x_new
            
        # Validate result
        result = int(x + Decimal('0.5'))  # Round to nearest integer
        
        # Verify decryption
        if self._encryption_function(Decimal(result), k, N) == ciphertext:
            return result
        else:
            raise ValueError("Decryption failed - invalid result")

# Legacy compatibility functions for benchmarking
def fRSA_keygen(security_level: int = 128) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """Generate TFBE key pair (legacy function name)"""
    tfbe = TFBECryptosystem(security_level)
    keypair = tfbe.generate_keypair()
    return keypair.public_key, keypair.private_key

def fRSA_encrypt(message: int, public_key: Dict[str, Any]) -> int:
    """Encrypt using TFBE (legacy function name)"""
    tfbe = TFBECryptosystem()
    return tfbe.encrypt(message, public_key)

def fRSA_decrypt(ciphertext: int, private_key: Dict[str, Any]) -> int:
    """Decrypt using TFBE (legacy function name)"""
    tfbe = TFBECryptosystem()
    return tfbe.decrypt(ciphertext, private_key)

# Alternative variant (rRSA) - simplified version
def rRSA_keygen(security_level: int = 128) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """Generate simplified TFBE key pair"""
    return fRSA_keygen(security_level)

def rRSA_encrypt(message: int, public_key: Dict[str, Any]) -> int:
    """Encrypt using simplified TFBE"""
    return fRSA_encrypt(message, public_key)

def rRSA_decrypt(ciphertext: int, private_key: Dict[str, Any]) -> int:
    """Decrypt using simplified TFBE"""
    return fRSA_decrypt(ciphertext, private_key)

# Example usage and testing
if __name__ == "__main__":
    print("TFBE Cryptosystem Test")
    print("=" * 50)
    
    # Initialize system
    tfbe = TFBECryptosystem(security_level=128)
    
    # Generate keypair
    print("Generating keypair...")
    start_time = time.time()
    keypair = tfbe.generate_keypair()
    keygen_time = time.time() - start_time
    print(f"Keypair generated in {keygen_time:.4f} seconds")
    
    # Test encryption/decryption
    test_message = 12345
    print(f"\nOriginal message: {test_message}")
    
    # Encrypt
    print("Encrypting...")
    start_time = time.time()
    ciphertext = tfbe.encrypt(test_message, keypair.public_key)
    encrypt_time = time.time() - start_time
    print(f"Ciphertext: {ciphertext}")
    print(f"Encryption time: {encrypt_time:.6f} seconds")
    
    # Decrypt
    print("Decrypting...")
    start_time = time.time()
    decrypted = tfbe.decrypt(ciphertext, keypair.private_key)
    decrypt_time = time.time() - start_time
    print(f"Decrypted message: {decrypted}")
    print(f"Decryption time: {decrypt_time:.6f} seconds")
    
    # Verify correctness
    success = (test_message == decrypted)
    print(f"\nTest result: {'PASS' if success else 'FAIL'}")
    
    if success:
        print("TFBE implementation working correctly!")
    else:
        print("Error in TFBE implementation!")
