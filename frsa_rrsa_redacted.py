import random
import math
from decimal import Decimal, getcontext
import hashlib

# Set high precision for decimal operations
getcontext().prec = 1000

def miller_rabin_test(n, k=10):
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

def generate_prime(bits):
    """Generate a prime number with specified bit length"""
    while True:
        # Generate random odd number with specified bit length
        n = random.getrandbits(bits)
        n |= (1 << bits - 1) | 1  # Set MSB and LSB to ensure odd number of correct bit length
        
        if miller_rabin_test(n):
            return n

def mod_inverse(a, m):
    """Compute modular inverse using extended Euclidean algorithm"""
    if math.gcd(a, m) != 1:
        return None
    
    def extended_gcd(a, b):
        if a == 0:
            return b, 0, 1
        gcd, x1, y1 = extended_gcd(b % a, a)
        x = y1 - (b // a) * x1
        y = x1
        return gcd, x, y
    
    _, x, _ = extended_gcd(a % m, m)
    return (x % m + m) % m

class PrecisionManager:
    """Manages high-precision arithmetic with synchronization"""
    
    def __init__(self, precision_digits=256):
        self.precision_digits = precision_digits
        # Set decimal context precision higher than needed for intermediate calculations
        getcontext().prec = precision_digits + 100
    
    def synchronized_compute(self, a, b, func, sync_seed=None):
        """Compute function value with synchronized precision"""
        try:
            # Convert to Decimal for high precision
            a_dec = Decimal(str(a))
            b_dec = Decimal(str(b))
            
            # Compute function values
            fa = func(a_dec)
            fb = func(b_dec)
            
            # Compute product
            k_full = fa * fb
            
            # Truncate to specified precision
            k_truncated = self.truncate_to_precision(k_full, self.precision_digits)
            
            return float(k_truncated)
        except Exception as e:
            # Fallback to regular arithmetic if decimal fails
            fa = func(float(a))
            fb = func(float(b))
            return fa * fb
    
    def truncate_to_precision(self, value, digits):
        """Truncate decimal value to specified number of digits"""
        if isinstance(value, Decimal):
            # Convert to string, then truncate
            str_val = str(value)
            if '.' in str_val:
                integer_part, decimal_part = str_val.split('.')
                if len(decimal_part) > digits:
                    decimal_part = decimal_part[:digits]
                return Decimal(f"{integer_part}.{decimal_part}")
            return value
        else:
            return Decimal(str(value))

# Function-based RSA (fRSA) Implementation
class fRSA:
    def __init__(self, security_level=128):
        self.security_level = security_level
        self.precision_manager = PrecisionManager(security_level)
    
    def generate_polynomial_function(self, degree=4):
        """Generate secure polynomial transformation function"""
        # Generate random coefficients
        coefficients = [random.randint(1, 2**16) for _ in range(degree + 1)]
        
        def poly_func(x):
            if isinstance(x, Decimal):
                result = Decimal(0)
                x_power = Decimal(1)
                for coeff in coefficients:
                    result += Decimal(coeff) * x_power
                    x_power *= x
                return result
            else:
                result = 0
                x_power = 1
                for coeff in coefficients:
                    result += coeff * x_power
                    x_power *= x
                return result
        
        return poly_func, coefficients
    
    def generate_transcendental_function(self):
        """Generate transcendental transformation function"""
        # Random parameters for transcendental function
        a = random.uniform(0.5, 2.0)
        b = random.uniform(2.0, 5.0)
        c = random.uniform(0.1, 1.0)
        d = random.uniform(10.0, 100.0)
        
        def trans_func(x):
            try:
                if isinstance(x, Decimal):
                    # Use decimal math for high precision
                    x_float = float(x)
                    # Ensure we don't get domain errors
                    log_arg = max(c * x_float + d, 1.0)
                    result = a * math.log(log_arg, b) + math.sin(x_float)
                    return Decimal(str(result))
                else:
                    log_arg = max(c * x + d, 1.0)
                    return a * math.log(log_arg, b) + math.sin(x)
            except:
                # Fallback for problematic values
                return Decimal(str(x)) if isinstance(x, Decimal) else x
        
        return trans_func, (a, b, c, d)

def fRSA_keygen(security_level=128, function_type='polynomial'):
    """Generate fRSA key pair"""
    frsa = fRSA(security_level)
    
    # Generate two primes
    prime_bits = max(security_level // 2, 64)  # Ensure reasonable prime size
    a = generate_prime(prime_bits)
    b = generate_prime(prime_bits)
    N = a * b
    
    # Generate transformation function
    if function_type == 'polynomial':
        func, func_params = frsa.generate_polynomial_function()
    else:
        func, func_params = frsa.generate_transcendental_function()
    
    # Compute transformed key with high precision
    k_full = frsa.precision_manager.synchronized_compute(a, b, func)
    
    # Create public and private keys
    public_key = {
        'N': N,
        'k_pub': k_full,
        'security_level': security_level
    }
    
    private_key = {
        'a': a,
        'b': b,
        'func_params': func_params,
        'k_full': k_full,
        'security_level': security_level,
        'function_type': function_type
    }
    
    return public_key, private_key

def fRSA_encrypt(message, public_key):
    """Encrypt message using fRSA"""
    N = public_key['N']
    k_pub = public_key['k_pub']
    
    # Ensure message is within valid range
    if message >= N:
        message = message % N
    
    # Use integer exponentiation for practical implementation
    phi_approx = N - int(math.sqrt(N)) - 1  # Approximation for efficiency
    k_int = max(int(abs(k_pub)) % phi_approx, 3)  # Ensure valid exponent
    
    ciphertext = pow(message, k_int, N)
    return ciphertext

def fRSA_decrypt(ciphertext, private_key):
    """Decrypt ciphertext using fRSA"""
    a = private_key['a']
    b = private_key['b']
    k_full = private_key['k_full']
    N = a * b
    
    # Compute phi(N) = (a-1)(b-1)
    phi_N = (a - 1) * (b - 1)
    
    # Compute private exponent
    k_int = max(int(abs(k_full)) % phi_N, 3)
    
    try:
        d_priv = mod_inverse(k_int, phi_N)
        if d_priv is None:
            d_priv = pow(k_int, -1, phi_N)
    except:
        # Fallback for edge cases
        d_priv = k_int
    
    # Decrypt
    plaintext = pow(ciphertext, d_priv, N)
    return plaintext

# Reverse RSA (rRSA) Implementation
def rRSA_keygen(security_level=128, function_type='polynomial'):
    """Generate rRSA key pair"""
    frsa = fRSA(security_level)
    
    # Generate two primes (these will be public)
    prime_bits = max(security_level // 2, 64)
    a = generate_prime(prime_bits)
    b = generate_prime(prime_bits)
    
    # Generate secret transformation function
    if function_type == 'polynomial':
        func, func_params = frsa.generate_polynomial_function()
    else:
        func, func_params = frsa.generate_transcendental_function()
    
    # Compute secret key with high precision
    k_secret = frsa.precision_manager.synchronized_compute(a, b, func)
    
    # Create public and private keys
    public_key = {
        'a': a,
        'b': b,
        'security_level': security_level
    }
    
    private_key = {
        'func_params': func_params,
        'k_secret': k_secret,
        'security_level': security_level,
        'function_type': function_type,
        'a': a,  # Keep for decryption
        'b': b   # Keep for decryption
    }
    
    return public_key, private_key

def rRSA_encrypt(message, public_key):
    """Encrypt message using rRSA"""
    a = public_key['a']
    b = public_key['b']
    N = a * b
    
    # Ensure message is within valid range
    if message >= N:
        message = message % N
    
    # Use a standard public exponent for rRSA
    e = 65537  # Standard RSA public exponent
    
    ciphertext = pow(message, e, N)
    return ciphertext

def rRSA_decrypt(ciphertext, private_key):
    """Decrypt ciphertext using rRSA"""
    a = private_key['a']
    b = private_key['b']
    k_secret = private_key['k_secret']
    N = a * b
    
    # Compute phi(N)
    phi_N = (a - 1) * (b - 1)
    
    # Use standard RSA decryption with secret key influence
    e = 65537
    
    try:
        d = mod_inverse(e, phi_N)
        if d is None:
            d = pow(e, -1, phi_N)
        
        # Apply secret key transformation
        k_int = int(abs(k_secret)) % phi_N
        if k_int != 0:
            d = (d * k_int) % phi_N
        
        plaintext = pow(ciphertext, d, N)
        return plaintext
    except:
        # Fallback decryption
        d = pow(e, -1, phi_N)
        plaintext = pow(ciphertext, d, N)
        return plaintext

# Demo functions
def demo_frsa():
    """Demonstrate fRSA functionality"""
    print("=== fRSA Demonstration ===")
    
    # Generate keys
    pub_key, priv_key = fRSA_keygen(security_level=128)
    
    # Test message
    message = 12345
    print(f"Original message: {message}")
    
    # Encrypt
    ciphertext = fRSA_encrypt(message, pub_key)
    print(f"Ciphertext: {ciphertext}")
    
    # Decrypt
    decrypted = fRSA_decrypt(ciphertext, priv_key)
    print(f"Decrypted message: {decrypted}")
    print(f"Correctness: {message == decrypted}")

def demo_rrsa():
    """Demonstrate rRSA functionality"""
    print("\n=== rRSA Demonstration ===")
    
    # Generate keys
    pub_key, priv_key = rRSA_keygen(security_level=128)
    
    # Test message
    message = 54321
    print(f"Original message: {message}")
    
    # Encrypt
    ciphertext = rRSA_encrypt(message, pub_key)
    print(f"Ciphertext: {ciphertext}")
    
    # Decrypt
    decrypted = rRSA_decrypt(ciphertext, priv_key)
    print(f"Decrypted message: {decrypted}")
    print(f"Correctness: {message == decrypted}")

if __name__ == "__main__":
    demo_frsa()
    demo_rrsa()
