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

def simple_function(x, mod):
    """Simple reversible function for testing"""
    # f(x) = (x * 3 + 7) mod m
    return (x * 3 + 7) % mod

def simple_inverse(y, mod):
    """Inverse of simple function"""
    # If y = (x * 3 + 7) mod m, then x = ((y - 7) * inv(3)) mod m
    try:
        inv3 = mod_inverse(3, mod)
        return ((y - 7) * inv3) % mod
    except:
        return y % mod

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
    
    # Public key
    pub_key = {
        'n': n,
        'e': e,
        'security_level': security_level
    }
    
    # Private key  
    priv_key = {
        'n': n,
        'd': d,
        'p': p,
        'q': q
    }
    
    return pub_key, priv_key

def fRSA_encrypt(message, pub_key):
    """Encrypt message using fRSA"""
    n = pub_key['n']
    e = pub_key['e']
    
    # Apply simple function transformation
    transformed = simple_function(message, n)
    
    # RSA encryption
    ciphertext = pow(transformed, e, n)
    
    return ciphertext

def fRSA_decrypt(ciphertext, priv_key):
    """Decrypt message using fRSA"""
    n = priv_key['n']
    d = priv_key['d']
    
    # RSA decryption
    transformed = pow(ciphertext, d, n)
    
    # Apply inverse function
    message = simple_inverse(transformed, n)
    
    return message

# rRSA Implementation  
def rRSA_keygen(security_level=128, function_type='polynomial'):
    """Generate rRSA key pair"""
    # Generate large prime
    p = generate_prime(security_level)
    
    # Choose public exponent
    e = 65537
    while math.gcd(e, p-1) != 1:
        e += 2
    
    # Compute private exponent
    d = mod_inverse(e, p-1)
    
    # Public key
    pub_key = {
        'p': p,
        'e': e,
        'security_level': security_level
    }
    
    # Private key
    priv_key = {
        'p': p,
        'd': d
    }
    
    return pub_key, priv_key

def rRSA_encrypt(message, pub_key):
    """Encrypt message using rRSA"""
    p = pub_key['p']
    e = pub_key['e']
    
    # Apply simple function transformation
    transformed = simple_function(message, p)
    
    # Ring RSA encryption
    ciphertext = pow(transformed, e, p)
    
    return ciphertext

def rRSA_decrypt(ciphertext, priv_key):
    """Decrypt message using rRSA"""
    p = priv_key['p']
    d = priv_key['d']
    
    # Ring RSA decryption
    transformed = pow(ciphertext, d, p)
    
    # Apply inverse function
    message = simple_inverse(transformed, p)
    
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
