import secrets
import hashlib
import math
from decimal import Decimal, getcontext
from typing import Tuple, Optional
import gmpy2
from gmpy2 import mpz, mpq, mpfr
import mpmath

# Set high precision for calculations
getcontext().prec = 100
mpmath.mp.dps = 50

class TranscendentalFunctionBasedEncryption:
    """
    Enhanced TFBE implementation with proper error handling and validation
    """
    
    def __init__(self, precision: int = 50):
        self.precision = precision
        mpmath.mp.dps = precision
        self.base_functions = {
            'exp': mpmath.exp,
            'log': mpmath.log,
            'sin': mpmath.sin,
            'cos': mpmath.cos,
            'tan': mpmath.tan,
            'sinh': mpmath.sinh,
            'cosh': mpmath.cosh,
            'tanh': mpmath.tanh,
            'gamma': mpmath.gamma,
            'zeta': mpmath.zeta,
            'pi': lambda: mpmath.pi,
            'e': lambda: mpmath.e
        }
    
    def generate_transcendental_base(self, seed: int) -> mpmath.mpf:
        """Generate a transcendental base using multiple functions"""
        try:
            # Use seed to generate deterministic transcendental number
            mpmath.mp.dps = self.precision
            
            # Create a complex transcendental expression
            x = mpmath.mpf(seed) / mpmath.mpf(1000000)  # Normalize seed
            
            # Combine multiple transcendental functions
            base = (mpmath.exp(x) * mpmath.sin(x + mpmath.pi/4) + 
                   mpmath.log(abs(x) + 1) * mpmath.cos(x) + 
                   mpmath.sqrt(2) * mpmath.gamma(abs(x) + 1))
            
            # Ensure positive real number
            base = abs(base)
            
            # Normalize to reasonable range [2, 100]
            while base < 2:
                base *= 10
            while base > 100:
                base /= 10
                
            return base
        except Exception as e:
            print(f"Error generating transcendental base: {e}")
            return mpmath.mpf(2.718281828)  # Fallback to e
    
    def compute_transcendental_power(self, base: mpmath.mpf, exponent: int) -> mpmath.mpf:
        """Compute base^exponent with high precision"""
        try:
            mpmath.mp.dps = self.precision
            
            # Handle special cases
            if exponent == 0:
                return mpmath.mpf(1)
            if exponent == 1:
                return base
            if base == 0:
                return mpmath.mpf(0)
            
            # Use mpmath's power function for high precision
            result = mpmath.power(base, exponent)
            
            # Ensure result is finite and positive
            if not mpmath.isfinite(result) or result <= 0:
                raise ValueError(f"Invalid power result: {result}")
                
            return result
        except Exception as e:
            print(f"Error computing transcendental power: {e}")
            # Fallback computation
            return mpmath.exp(mpmath.log(base) * exponent)
    
    def modular_transcendental_exp(self, base: mpmath.mpf, exponent: int, modulus: int) -> int:
        """Compute (base^exponent) mod modulus efficiently"""
        try:
            # First compute the transcendental power
            power_result = self.compute_transcendental_power(base, exponent)
            
            # Convert to integer for modular arithmetic
            # Use floor to get integer part
            power_int = int(mpmath.floor(power_result))
            
            # Ensure positive result
            if power_int <= 0:
                power_int = abs(power_int) + 1
            
            # Apply modular reduction
            result = power_int % modulus
            
            # Ensure non-zero result
            if result == 0:
                result = 1
                
            return result
        except Exception as e:
            print(f"Error in modular transcendental exp: {e}")
            # Fallback to regular modular exponentiation
            return pow(int(base), exponent, modulus)
    
    def encrypt(self, plaintext: int, public_key: Tuple[int, int, int]) -> int:
        """Encrypt plaintext using TFBE"""
        try:
            n, e, seed = public_key
            
            # Validate inputs
            if not (0 <= plaintext < n):
                raise ValueError(f"Plaintext must be in range [0, {n-1}]")
            
            # Generate transcendental base
            base = self.generate_transcendental_base(seed)
            
            # Compute transcendental component
            trans_component = self.modular_transcendental_exp(base, e, n)
            
            # Combine with traditional RSA-like encryption
            # C = (m^e * T^e) mod n, where T is transcendental component
            traditional_part = pow(plaintext, e, n)
            ciphertext = (traditional_part * trans_component) % n
            
            return ciphertext
        except Exception as e:
            print(f"Encryption error: {e}")
            raise
    
    def decrypt(self, ciphertext: int, private_key: Tuple[int, int, int, int]) -> int:
        """Decrypt ciphertext using TFBE"""
        try:
            n, d, seed, p_q_info = private_key
            
            # Validate inputs
            if not (0 <= ciphertext < n):
                raise ValueError(f"Ciphertext must be in range [0, {n-1}]")
            
            # Generate same transcendental base as encryption
            base = self.generate_transcendental_base(seed)
            
            # Compute transcendental component for decryption
            # We need T^d mod n where T was used in encryption
            e = 65537  # Standard RSA public exponent
            trans_component_enc = self.modular_transcendental_exp(base, e, n)
            
            # Find modular inverse of transcendental component
            try:
                trans_inv = pow(trans_component_enc, -1, n)
            except ValueError:
                # If no inverse exists, use extended GCD
                def extended_gcd(a, b):
                    if a == 0:
                        return b, 0, 1
                    gcd, x1, y1 = extended_gcd(b % a, a)
                    x = y1 - (b // a) * x1
                    y = x1
                    return gcd, x, y
                
                gcd, x, y = extended_gcd(trans_component_enc, n)
                if gcd != 1:
                    raise ValueError("Transcendental component not invertible")
                trans_inv = x % n
            
            # Remove transcendental component
            traditional_cipher = (ciphertext * trans_inv) % n
            
            # Decrypt using traditional RSA
            plaintext = pow(traditional_cipher, d, n)
            
            # Validate result
            if plaintext >= n:
                raise ValueError("Decryption failed - result too large")
            
            return plaintext
        except Exception as e:
            print(f"Decryption error: {e}")
            raise ValueError("Decryption failed - invalid result")

def generate_prime(bits: int) -> int:
    """Generate a prime number with specified bit length"""
    while True:
        candidate = secrets.randbits(bits)
        candidate |= (1 << bits - 1) | 1  # Ensure odd and right bit length
        if gmpy2.is_prime(candidate):
            return candidate

def fRSA_keygen(bits: int = 1024) -> Tuple[Tuple[int, int, int], Tuple[int, int, int, int]]:
    """Generate fRSA key pair"""
    try:
        # Generate two distinct primes
        p = generate_prime(bits // 2)
        q = generate_prime(bits // 2)
        while p == q:
            q = generate_prime(bits // 2)
        
        n = p * q
        phi_n = (p - 1) * (q - 1)
        
        # Use standard RSA public exponent
        e = 65537
        
        # Compute private exponent
        d = pow(e, -1, phi_n)
        
        # Generate transcendental seed
        seed = secrets.randbelow(1000000) + 1
        
        # Public key: (n, e, seed)
        public_key = (n, e, seed)
        
        # Private key: (n, d, seed, p_q_info)
        private_key = (n, d, seed, (p, q))
        
        return public_key, private_key
    except Exception as e:
        print(f"Key generation error: {e}")
        raise

def fRSA_encrypt(plaintext: int, public_key: Tuple[int, int, int]) -> int:
    """Encrypt using fRSA"""
    tfbe = TranscendentalFunctionBasedEncryption()
    return tfbe.encrypt(plaintext, public_key)

def fRSA_decrypt(ciphertext: int, private_key: Tuple[int, int, int, int]) -> int:
    """Decrypt using fRSA"""
    tfbe = TranscendentalFunctionBasedEncryption()
    return tfbe.decrypt(ciphertext, private_key)

# Test the implementation
if __name__ == "__main__":
    try:
        print("Testing fRSA implementation...")
        
        # Generate keys
        pub_key, priv_key = fRSA_keygen(1024)
        print(f"Keys generated successfully")
        
        # Test encryption/decryption
        test_message = 42
        print(f"Original message: {test_message}")
        
        # Encrypt
        ciphertext = fRSA_encrypt(test_message, pub_key)
        print(f"Encrypted: {ciphertext}")
        
        # Decrypt
        decrypted = fRSA_decrypt(ciphertext, priv_key)
        print(f"Decrypted: {decrypted}")
        
        # Verify
        if decrypted == test_message:
            print("✓ Test passed!")
        else:
            print("✗ Test failed!")
            
    except Exception as e:
        print(f"Test error: {e}")
        import traceback
        traceback.print_exc()
