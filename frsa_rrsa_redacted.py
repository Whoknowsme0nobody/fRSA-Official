import random
import math
import hashlib

def extended_gcd(a, b):
    """Extended Euclidean Algorithm"""
    if a == 0:
        return b, 0, 1
    gcd, x1, y1 = extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return gcd, x, y

def mod_inverse(a, m):
    """Compute modular inverse of a modulo m"""
    gcd, x, _ = extended_gcd(a, m)
    if gcd != 1:
        raise ValueError("Modular inverse does not exist")
    return (x % m + m) % m

def is_prime(n, k=10):
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
    """Generate a random prime of specified bit length"""
    while True:
        n = random.getrandbits(bits)
        n |= (1 << bits - 1) | 1  # Set MSB and LSB
        if is_prime(n):
            return n

def polynomial_function(x, coeffs, mod):
    """Evaluate polynomial function modulo mod"""
    result = 0
    power = 1
    for coeff in coeffs:
        result = (result + coeff * power) % mod
        power = (power * x) % mod
    return result

def transcendental_function(x, mod):
    """Approximate transcendental function using Taylor series"""
    # Using sin(x) approximation: x - x^3/6 + x^5/120 - ...
    x = x % mod
    result = x
    term = x
    for i in range(1, 10):  # First 10 terms
        term = (term * x * x) % mod
        if i % 2 == 1:
            # Approximate factorial division
            divisor = pow(2 * i + 1, mod - 2, mod)  # Fermat's little theorem
            term = (term * divisor) % mod
            if i % 4 == 1:
                result = (result - term) % mod
            else:
                result = (result + term) % mod
    return result % mod

def hash_to_number(data):
    """Hash data to a number"""
    return int.from_bytes(hashlib.sha256(str(data).encode()).digest(), 'big')

# fRSA Implementation
def fRSA_keygen(security_level=128, function_type='polynomial'):
    """Generate fRSA key pair"""
    # Generate two large primes
    p = generate_prime(security_level // 2)
    q = generate_prime(security_level // 2)
    n = p * q
    phi = (p - 1) * (q - 1)
    
    # Choose public exponent
    e = 65537
    while math.gcd(e, phi) != 1:
        e += 2
    
    # Compute private exponent
    d = mod_inverse(e, phi)
    
    # Generate function parameters
    if function_type == 'polynomial':
        coeffs = [random.randint(1, n-1) for _ in range(5)]
        func_params = {'type': 'polynomial', 'coeffs': coeffs}
    else:
        func_params = {'type': 'transcendental'}
    
    # Public key
    pub_key = {
        'n': n,
        'e': e,
        'func_params': func_params,
        'security_level': security_level
    }
    
    # Private key  
    priv_key = {
        'n': n,
        'd': d,
        'p': p,
        'q': q,
        'func_params': func_params
    }
    
    return pub_key, priv_key

def fRSA_encrypt(message, pub_key):
    """Encrypt message using fRSA"""
    n = pub_key['n']
    e = pub_key['e']
    func_params = pub_key['func_params']
    
    # Apply functional transformation
    if func_params['type'] == 'polynomial':
        transformed = polynomial_function(message, func_params['coeffs'], n)
    else:
        transformed = transcendental_function(message, n)
    
    # RSA encryption
    ciphertext = pow(transformed, e, n)
    
    return {
        'ciphertext': ciphertext,
        'func_params': func_params
    }

def fRSA_decrypt(encrypted_data, priv_key):
    """Decrypt message using fRSA"""
    n = priv_key['n']
    d = priv_key['d']
    ciphertext = encrypted_data['ciphertext']
    
    # RSA decryption
    transformed = pow(ciphertext, d, n)
    
    # Reverse functional transformation (simplified)
    # In practice, this would require solving the inverse function
    # For demonstration, we'll use a simplified approach
    if priv_key['func_params']['type'] == 'polynomial':
        # Simplified inverse - just return the transformed value
        # In real implementation, you'd solve the polynomial equation
        message = transformed % 1000000  # Simplified recovery
    else:
        # Simplified inverse for transcendental
        message = transformed % 1000000  # Simplified recovery
    
    return message

# rRSA Implementation  
def rRSA_keygen(security_level=128, function_type='polynomial'):
    """Generate rRSA key pair"""
    # Generate large prime
    p = generate_prime(security_level)
    
    # Generate ring parameters
    ring_size = random.randint(100, 1000)
    
    # Choose public exponent
    e = 65537
    while math.gcd(e, p-1) != 1:
        e += 2
    
    # Compute private exponent
    d = mod_inverse(e, p-1)
    
    # Generate function parameters
    if function_type == 'polynomial':
        coeffs = [random.randint(1, p-1) for _ in range(3)]
        func_params = {'type': 'polynomial', 'coeffs': coeffs}
    else:
        func_params = {'type': 'transcendental'}
    
    # Public key
    pub_key = {
        'p': p,
        'e': e,
        'ring_size': ring_size,
        'func_params': func_params,
        'security_level': security_level
    }
    
    # Private key
    priv_key = {
        'p': p,
        'd': d,
        'ring_size': ring_size,
        'func_params': func_params
    }
    
    return pub_key, priv_key

def rRSA_encrypt(message, pub_key):
    """Encrypt message using rRSA"""
    p = pub_key['p']
    e = pub_key['e']
    ring_size = pub_key['ring_size']
    func_params = pub_key['func_params']
    
    # Ring-based transformation
    ring_element = message % ring_size
    
    # Apply functional transformation
    if func_params['type'] == 'polynomial':
        transformed = polynomial_function(ring_element, func_params['coeffs'], p)
    else:
        transformed = transcendental_function(ring_element, p)
    
    # Ring RSA encryption
    ciphertext = pow(transformed, e, p)
    
    return {
        'ciphertext': ciphertext,
        'ring_size': ring_size,
        'func_params': func_params
    }

def rRSA_decrypt(encrypted_data, priv_key):
    """Decrypt message using rRSA"""
    p = priv_key['p']
    d = priv_key['d']
    ciphertext = encrypted_data['ciphertext']
    ring_size = priv_key['ring_size']
    
    # Ring RSA decryption
    transformed = pow(ciphertext, d, p)
    
    # Reverse functional transformation (simplified)
    if priv_key['func_params']['type'] == 'polynomial':
        # Simplified inverse
        ring_element = transformed % ring_size
    else:
        # Simplified inverse
        ring_element = transformed % ring_size
    
    # Recover original message (simplified)
    message = ring_element % 1000000  # Simplified recovery
    
    return message

# Test functions
def test_frsa():
    """Test fRSA implementation"""
    print("Testing fRSA...")
    pub_key, priv_key = fRSA_keygen(security_level=128)
    
    message = 12345
    encrypted = fRSA_encrypt(message, pub_key)
    decrypted = fRSA_decrypt(encrypted, priv_key)
    
    print(f"Original: {message}")
    print(f"Decrypted: {decrypted}")
    print(f"Correct: {message == decrypted}")
    
    return message == decrypted

def test_rrsa():
    """Test rRSA implementation"""
    print("Testing rRSA...")
    pub_key, priv_key = rRSA_keygen(security_level=128)
    
    message = 12345
    encrypted = rRSA_encrypt(message, pub_key)
    decrypted = rRSA_decrypt(encrypted, priv_key)
    
    print(f"Original: {message}")
    print(f"Decrypted: {decrypted}")
    print(f"Correct: {message == decrypted}")
    
    return message == decrypted

if __name__ == "__main__":
    print("Testing cryptographic implementations...")
    frsa_works = test_frsa()
    rrsa_works = test_rrsa()
    
    if frsa_works and rrsa_works:
        print("All tests passed!")
    else:
        print("Some tests failed!")
