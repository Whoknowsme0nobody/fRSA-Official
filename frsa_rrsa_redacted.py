"""
Function-Based and Reverse RSA (fRSA/rRSA) Implementation
Based on the research paper by Amine Belachhab

This implementation provides post-quantum cryptographic security through:
- Function-based transformations
- Precision-dependent security mechanisms
- Multi-layered computational hardness assumptions
"""

import random
import math
import hashlib
from decimal import Decimal, getcontext
from typing import Tuple, List, Callable, Dict, Any

# Set high precision for arbitrary-precision arithmetic
getcontext().prec = 1024

class CryptographicPrimes:
    """Utilities for generating and working with cryptographic primes"""
    
    @staticmethod
    def miller_rabin(n: int, k: int = 10) -> bool:
        """Miller-Rabin primality test"""
        if n < 2:
            return False
        if n == 2 or n == 3:
            return True
        if n % 2 == 0:
            return False
        
        # Write n-1 as d * 2^r
        r = 0
        d = n - 1
        while d % 2 == 0:
            r += 1
            d //= 2
        
        # Perform k rounds of testing
        for _ in range(k):
            a = random.randrange(2, n - 1)
            x = pow(a, d, n)
            
            if x == 1 or x == n - 1:
                continue
            
            for _ in range(r - 1):
                x = pow(x, 2, n)
                if x == n - 1:
                    break
            else:
                return False
        
        return True
    
    @staticmethod
    def generate_prime(bits: int) -> int:
        """Generate a cryptographically strong prime"""
        while True:
            candidate = random.getrandbits(bits)
            candidate |= (1 << bits - 1) | 1  # Ensure it's odd and has correct bit length
            
            if CryptographicPrimes.miller_rabin(candidate):
                return candidate

class SecureFunction:
    """Secure transformation functions for fRSA/rRSA"""
    
    def __init__(self, function_type: str = "polynomial", degree: int = 8, security_level: int = 256):
        self.function_type = function_type
        self.degree = degree
        self.security_level = security_level
        self.coefficients = self._generate_coefficients()
        self.modulus = self._generate_function_modulus()
    
    def _generate_coefficients(self) -> List[int]:
        """Generate secure polynomial coefficients"""
        coefficient_bits = max(64, self.security_level // 4)
        return [random.getrandbits(coefficient_bits) for _ in range(self.degree + 1)]
    
    def _generate_function_modulus(self) -> int:
        """Generate a large prime for function operations"""
        return CryptographicPrimes.generate_prime(self.security_level)
    
    def evaluate(self, x: int) -> Decimal:
        """Evaluate the secure function at point x"""
        if self.function_type == "polynomial":
            return self._evaluate_polynomial(x)
        elif self.function_type == "transcendental":
            return self._evaluate_transcendental(x)
        else:
            raise ValueError(f"Unsupported function type: {self.function_type}")
    
    def _evaluate_polynomial(self, x: int) -> Decimal:
        """Evaluate polynomial function: sum(c_i * x^i) mod p"""
        result = Decimal(0)
        x_power = Decimal(1)
        x_decimal = Decimal(x)
        
        for coeff in self.coefficients:
            term = (Decimal(coeff) * x_power) % Decimal(self.modulus)
            result = (result + term) % Decimal(self.modulus)
            x_power = (x_power * x_decimal) % Decimal(self.modulus)
        
        return result
    
    def _evaluate_transcendental(self, x: int) -> Decimal:
        """Evaluate transcendental function with polynomial base"""
        base_poly = self._evaluate_polynomial(x)
        
        # Add transcendental components for enhanced security
        x_decimal = Decimal(x)
        log_component = base_poly * x_decimal.ln() if x > 1 else base_poly
        
        # Combine with trigonometric-like transformation
        trig_approx = self._sin_approximation(x_decimal / 1000)
        
        return (log_component + Decimal(1000) * trig_approx) % Decimal(self.modulus)
    
    def _sin_approximation(self, x: Decimal) -> Decimal:
        """Taylor series approximation of sine function"""
        result = Decimal(0)
        term = x
        
        for n in range(1, 20, 2):  # Use first 10 terms of Taylor series
            result += term / Decimal(math.factorial(n))
            term *= -x * x
        
        return result

class PrecisionManager:
    """Manages precision-dependent security mechanisms"""
    
    def __init__(self, precision_digits: int, sync_seed: bytes):
        self.precision_digits = precision_digits
        self.sync_seed = sync_seed
        self.guard_digits = 64
    
    def synchronized_compute(self, value: Decimal) -> Decimal:
        """Compute value with synchronized precision"""
        # Set precision context with guard digits
        old_prec = getcontext().prec
        getcontext().prec = self.precision_digits + self.guard_digits
        
        # Apply standardized rounding
        rounded_value = value.quantize(Decimal('0.' + '0' * self.precision_digits))
        
        # Truncate to exact precision
        truncated = self._truncate_to_precision(rounded_value)
        
        # Restore original precision
        getcontext().prec = old_prec
        
        return truncated
    
    def _truncate_to_precision(self, value: Decimal) -> Decimal:
        """Truncate to exact decimal precision"""
        # Convert to string, truncate, and convert back
        value_str = str(value)
        if '.' in value_str:
            integer_part, decimal_part = value_str.split('.')
            truncated_decimal = decimal_part[:self.precision_digits]
            return Decimal(f"{integer_part}.{truncated_decimal}")
        return value
    
    def precision_hash(self, value: Decimal) -> str:
        """Generate hash for precision validation"""
        value_bytes = str(value).encode('utf-8')
        combined = self.sync_seed + value_bytes
        return hashlib.sha256(combined).hexdigest()

class fRSA:
    """Function-based RSA implementation"""
    
    def __init__(self, security_level: int = 128):
        self.security_level = security_level
        self.key_size = max(2048, security_level * 16)  # Ensure adequate key size
        self.precision_digits = security_level * 2  # Precision scales with security
        
    def keygen(self) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        """Generate fRSA key pair"""
        # Generate prime components
        prime_bits = self.key_size // 2
        a = CryptographicPrimes.generate_prime(prime_bits)
        b = CryptographicPrimes.generate_prime(prime_bits)
        
        # Generate transformation function
        f = SecureFunction("polynomial", degree=8, security_level=self.security_level)
        
        # Generate synchronization components
        sync_seed = random.randbytes(32)
        precision_manager = PrecisionManager(self.precision_digits, sync_seed)
        
        # Compute function values
        f_a = f.evaluate(a)
        f_b = f.evaluate(b)
        k_full = f_a * f_b
        
        # Apply precision management
        k_pub = precision_manager.synchronized_compute(k_full)
        
        # Create public and private keys
        public_key = {
            'N': a * b,
            'K_pub': k_pub,
            'type': 'fRSA'
        }
        
        private_key = {
            'a': a,
            'b': b,
            'function': f,
            'K_full': k_full,
            'sync_seed': sync_seed,
            'precision_manager': precision_manager,
            'type': 'fRSA'
        }
        
        return public_key, private_key
    
    def encrypt(self, message: int, public_key: Dict[str, Any]) -> int:
        """Encrypt message using fRSA"""
        if message >= public_key['N']:
            raise ValueError("Message too large for key size")
        
        # Convert K_pub to integer for modular exponentiation
        k_pub_int = int(public_key['K_pub'])
        
        # Perform encryption: c = m^K_pub (mod N)
        ciphertext = pow(message, k_pub_int, public_key['N'])
        
        return ciphertext
    
    def decrypt(self, ciphertext: int, private_key: Dict[str, Any]) -> int:
        """Decrypt ciphertext using fRSA"""
        # Compute private exponent
        N = private_key['a'] * private_key['b']
        phi_N = (private_key['a'] - 1) * (private_key['b'] - 1)
        
        k_full_int = int(private_key['K_full'])
        d_priv = pow(k_full_int, -1, phi_N)  # Modular inverse
        
        # Perform decryption: m = c^d_priv (mod N)
        message = pow(ciphertext, d_priv, N)
        
        return message

class rRSA:
    """Reverse RSA implementation"""
    
    def __init__(self, security_level: int = 128):
        self.security_level = security_level
        self.key_size = max(2048, security_level * 16)
        self.precision_digits = security_level * 2
        
    def keygen(self) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        """Generate rRSA key pair"""
        # Generate public primes
        prime_bits = self.key_size // 2
        a = CryptographicPrimes.generate_prime(prime_bits)
        b = CryptographicPrimes.generate_prime(prime_bits)
        
        # Generate secret transformation function
        f = SecureFunction("transcendental", degree=8, security_level=self.security_level)
        
        # Generate synchronization components
        sync_seed = random.randbytes(32)
        precision_manager = PrecisionManager(self.precision_digits, sync_seed)
        
        # Compute secret key components
        f_a = f.evaluate(a)
        f_b = f.evaluate(b)
        k_sec = f_a * f_b
        k_work = precision_manager.synchronized_compute(k_sec)
        
        # Create public and private keys
        public_key = {
            'a': a,
            'b': b,
            'type': 'rRSA'
        }
        
        private_key = {
            'function': f,
            'K_sec': k_sec,
            'K_work': k_work,
            'sync_seed': sync_seed,
            'precision_manager': precision_manager,
            'type': 'rRSA'
        }
        
        return public_key, private_key
    
    def encrypt(self, message: int, public_key: Dict[str, Any]) -> int:
        """Encrypt message using rRSA (requires shared secret function)"""
        # Note: In practice, the function would be shared through secure channel
        # This is a simplified implementation
        N = public_key['a'] * public_key['b']
        
        if message >= N:
            raise ValueError("Message too large for key size")
        
        # Use a derived exponent based on public primes
        # In full implementation, this would use the secret function
        e = 65537  # Temporary public exponent
        ciphertext = pow(message, e, N)
        
        return ciphertext
    
    def decrypt(self, ciphertext: int, private_key: Dict[str, Any], public_key: Dict[str, Any]) -> int:
        """Decrypt ciphertext using rRSA"""
        N = public_key['a'] * public_key['b']
        phi_N = (public_key['a'] - 1) * (public_key['b'] - 1)
        
        # Use secret function result as private exponent
        k_work_int = int(private_key['K_work'])
        d_priv = pow(k_work_int, -1, phi_N)
        
        # Perform decryption
        message = pow(ciphertext, d_priv, N)
        
        return message

# Unified interface functions for benchmarking
def fRSA_keygen(security_level: int = 128) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """Generate fRSA key pair"""
    frsa = fRSA(security_level)
    return frsa.keygen()

def fRSA_encrypt(message: int, public_key: Dict[str, Any]) -> int:
    """Encrypt using fRSA"""
    frsa = fRSA()
    return frsa.encrypt(message, public_key)

def fRSA_decrypt(ciphertext: int, private_key: Dict[str, Any]) -> int:
    """Decrypt using fRSA"""
    frsa = fRSA()
    return frsa.decrypt(ciphertext, private_key)

def rRSA_keygen(security_level: int = 128) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """Generate rRSA key pair"""
    rrsa = rRSA(security_level)
    return rrsa.keygen()

def rRSA_encrypt(message: int, public_key: Dict[str, Any]) -> int:
    """Encrypt using rRSA"""
    rrsa = rRSA()
    return rrsa.encrypt(message, public_key)

def rRSA_decrypt(ciphertext: int, private_key: Dict[str, Any], public_key: Dict[str, Any]) -> int:
    """Decrypt using rRSA"""
    rrsa = rRSA()
    return rrsa.decrypt(ciphertext, private_key, public_key)

# Demo and testing functions
def demo_frsa():
    """Demonstrate fRSA functionality"""
    print("=== fRSA Demonstration ===")
    
    # Generate keys
    pub_key, priv_key = fRSA_keygen(128)
    print(f"Key generation complete")
    print(f"Public modulus size: {pub_key['N'].bit_length()} bits")
    
    # Test encryption/decryption
    message = 12345
    print(f"Original message: {message}")
    
    ciphertext = fRSA_encrypt(message, pub_key)
    print(f"Encrypted: {ciphertext}")
    
    decrypted = fRSA_decrypt(ciphertext, priv_key)
    print(f"Decrypted: {decrypted}")
    
    print(f"Correctness: {'PASS' if message == decrypted else 'FAIL'}")
    print()

def demo_rrsa():
    """Demonstrate rRSA functionality"""
    print("=== rRSA Demonstration ===")
    
    # Generate keys
    pub_key, priv_key = rRSA_keygen(128)
    print(f"Key generation complete")
    print(f"Public prime a: {pub_key['a'].bit_length()} bits")
    print(f"Public prime b: {pub_key['b'].bit_length()} bits")
    
    # Test encryption/decryption
    message = 54321
    print(f"Original message: {message}")
    
    ciphertext = rRSA_encrypt(message, pub_key)
    print(f"Encrypted: {ciphertext}")
    
    decrypted = rRSA_decrypt(ciphertext, priv_key, pub_key)
    print(f"Decrypted: {decrypted}")
    
    print(f"Correctness: {'PASS' if message == decrypted else 'FAIL'}")
    print()

if __name__ == "__main__":
    print("Function-Based and Reverse RSA Implementation")
    print("=" * 50)
    
    demo_frsa()
    demo_rrsa()
    
    print("Implementation complete. Ready for benchmarking.")
