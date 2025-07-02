import random
import math
import hashlib

def generate_large_prime(bits):
    """Generate a large prime number with specified bit length"""
    while True:
        num = random.getrandbits(bits)
        num |= (1 << bits - 1) | 1  # Set MSB and LSB to 1
        if is_prime(num):
            return num

def is_prime(n, k=20):
    """Miller-Rabin primality test"""
    if n < 2:
        return False
    if n == 2 or n == 3:
        return True
    if n % 2 == 0:
        return False
    
    # Write n-1 as 2^r * d
    r = 0
    d = n - 1
    while d % 2 == 0:
        d //= 2
        r += 1
    
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

def extended_gcd(a, b):
    """Extended Euclidean Algorithm"""
    if a == 0:
        return b, 0, 1
    gcd, x1, y1 = extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return gcd, x, y

def mod_inverse(a, m):
    """Modular multiplicative inverse"""
    gcd, x, _ = extended_gcd(a, m)
    if gcd != 1:
        raise ValueError("Modular inverse does not exist")
    return (x % m + m) % m

def polynomial_function(x, coeffs, mod):
    """Evaluate polynomial function mod n"""
    result = 0
    power = 1
    for coeff in coeffs:
        result = (result + coeff * power) % mod
        power = (power * x) % mod
    return result

def transcendental_function(x, mod):
    """Approximate transcendental function using series expansion"""
    # Use sin(x) approximation: sin(x) ≈ x - x³/6 + x⁵/120 - ...
    x = x % mod
    result = x
    term = x
    
    # Add a few terms of the series
    for i in range(1, 6):
        term = (term * x * x) % mod
        if i % 2 == 1:
            # Approximate division by factorial
            factorial_approx = pow(2 * i + 1, mod - 2, mod)  # Fermat's little theorem
            result = (result - term * factorial_approx) % mod
        else:
            factorial_approx = pow(2 * i + 1, mod - 2, mod)
            result = (result + term * factorial_approx) % mod
    
    return result

def generate_function_coefficients(security_level, function_type='polynomial'):
    """Generate coefficients for the function"""
    if function_type == 'polynomial':
        degree = security_level // 32  # Adjust degree based on security level
        return [random.randint(1, 2**32) for _ in range(degree + 1)]
    else:
        return [random.randint(1, 2**16) for _ in range(4)]  # Coefficients for transcendental

def fRSA_keygen(security_level=128, function_type='polynomial'):
    """Generate fRSA key pair"""
    # Generate two large primes
    p = generate_large_prime(security_level // 2)
    q = generate_large_prime(security_level // 2)
    n = p * q
    phi_n = (p - 1) * (q - 1)
    
    # Choose e (commonly 65537)
    e = 65537
    while math.gcd(e, phi_n) != 1:
        e = random.randint(3, phi_n - 1)
        if e % 2 == 0:
            e += 1
    
    # Calculate d
    d = mod_inverse(e, phi_n)
    
    # Generate function coefficients
    coeffs = generate_function_coefficients(security_level, function_type)
    
    # Public key
    pub_key = {
        'n': n,
        'e': e,
        'coeffs': coeffs,
        'function_type': function_type,
        'security_level': security_level
    }
    
    # Private key
    priv_key = {
        'n': n,
        'd': d,
        'p': p,
        'q': q,
        'coeffs': coeffs,
        'function_type': function_type,
        'security_level': security_level
    }
    
    return pub_key, priv_key

def fRSA_encrypt(message, pub_key):
    """Encrypt message using fRSA"""
    n = pub_key['n']
    e = pub_key['e']
    coeffs = pub_key['coeffs']
    function_type = pub_key['function_type']
    
    # Apply function transformation
    if function_type == 'polynomial':
        transformed = polynomial_function(message, coeffs, n)
    else:
        transformed = transcendental_function(message, n)
    
    # Standard RSA encryption
    ciphertext = pow(transformed, e, n)
    
    return ciphertext

def fRSA_decrypt(ciphertext, priv_key):
    """Decrypt ciphertext using fRSA"""
    n = priv_key['n']
    d = priv_key['d']
    
    # Standard RSA decryption
    decrypted = pow(ciphertext, d, n)
    
    # For simplicity, return the decrypted value
    # In a real implementation, you'd need to invert the function transformation
    # This is a simplified version for benchmarking
    return decrypted % (2**20)  # Limit to reasonable message size

def rRSA_keygen(security_level=128, function_type='polynomial'):
    """Generate rRSA key pair (similar to fRSA but with different parameters)"""
    # Generate parameters with different structure
    p = generate_large_prime(security_level // 2 + 1)
    q = generate_large_prime(security_level // 2 - 1)
    n = p * q
    phi_n = (p - 1) * (q - 1)
    
    # Choose different e
    e = 3
    while math.gcd(e, phi_n) != 1:
        e = random.choice([3, 17, 257, 65537])
    
    d = mod_inverse(e, phi_n)
    
    # Different coefficient generation strategy
    coeffs = generate_function_coefficients(security_level, function_type)
    if function_type == 'polynomial':
        coeffs = [c * 2 + 1 for c in coeffs]  # Make coefficients odd
    
    pub_key = {
        'n': n,
        'e': e,
        'coeffs': coeffs,
        'function_type': function_type,
        'security_level': security_level
    }
    
    priv_key = {
        'n': n,
        'd': d,
        'p': p,
        'q': q,
        'coeffs': coeffs,
        'function_type': function_type,
        'security_level': security_level
    }
    
    return pub_key, priv_key

def rRSA_encrypt(message, pub_key):
    """Encrypt message using rRSA"""
    n = pub_key['n']
    e = pub_key['e']
    coeffs = pub_key['coeffs']
    function_type = pub_key['function_type']
    
    # Apply modified function transformation
    if function_type == 'polynomial':
        # Use modified polynomial evaluation
        transformed = polynomial_function(message * 2 + 1, coeffs, n)
    else:
        # Use modified transcendental function
        transformed = transcendental_function(message + coeffs[0], n)
    
    # RSA encryption with padding
    padded = (transformed + random.randint(1, 1000)) % n
    ciphertext = pow(padded, e, n)
    
    return ciphertext

def rRSA_decrypt(ciphertext, priv_key):
    """Decrypt ciphertext using rRSA"""
    n = priv_key['n']
    d = priv_key['d']
    
    # RSA decryption
    decrypted = pow(ciphertext, d, n)
    
    # Simplified inverse transformation for benchmarking
    return decrypted % (2**20)  # Limit to reasonable message size

# Test functions
def test_frsa():
    """Test fRSA implementation"""
    print("Testing fRSA...")
    pub_key, priv_key = fRSA_keygen(security_level=128)
    
    message = 12345
    ciphertext = fRSA_encrypt(message, pub_key)
    decrypted = fRSA_decrypt(ciphertext, priv_key)
    
    print(f"Original: {message}")
    print(f"Encrypted: {ciphertext}")
    print(f"Decrypted: {decrypted}")
    print(f"Match: {message == decrypted}")

def test_rrsa():
    """Test rRSA implementation"""
    print("Testing rRSA...")
    pub_key, priv_key = rRSA_keygen(security_level=128)
    
    message = 12345
    ciphertext = rRSA_encrypt(message, pub_key)
    decrypted = rRSA_decrypt(ciphertext, priv_key)
    
    print(f"Original: {message}")
    print(f"Encrypted: {ciphertext}")
    print(f"Decrypted: {decrypted}")
    print(f"Match: {message == decrypted}")

if __name__ == "__main__":
    test_frsa()
    print()
    test_rrsa()
