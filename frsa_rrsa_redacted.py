"""
Transcendental Function-Based Encryption (TFBE) Implementation
Based on "Enhanced Multi-Layer Cryptographic System: A Novel Approach to Post-Quantum Security"
by Amine Belachhab (Version 2.0, July 2025)

This implementation provides the core TFBE algorithms with multi-layer security architecture.
"""

import math
import decimal
import hashlib
import random
from typing import Tuple, Dict, Any, Optional
import time

# Set default high precision for decimal arithmetic
decimal.getcontext().prec = 512

class TFBEError(Exception):
    """Base exception for TFBE operations"""
    pass

class TFBEKeyError(TFBEError):
    """Key-related errors"""
    pass

class TFBEEncryptionError(TFBEError):
    """Encryption-related errors"""
    pass

class TFBEDecryptionError(TFBEError):
    """Decryption-related errors"""
    pass

def set_precision(bits: int) -> int:
    """Set decimal precision based on security bits"""
    # Convert security bits to decimal digits with safety margin
    digits = int(bits * 0.30103) + 50  # log10(2) ≈ 0.30103
    decimal.getcontext().prec = digits
    return digits

def cosine_taylor(x: decimal.Decimal, precision: int) -> decimal.Decimal:
    """Compute cos(x) using Taylor series with controlled precision"""
    x = decimal.Decimal(str(x))
    
    # Reduce x to [-π, π] range for better convergence
    pi = decimal.Decimal('3.1415926535897932384626433832795028841971693993751')
    while x > pi:
        x -= 2 * pi
    while x < -pi:
        x += 2 * pi
    
    # Taylor series: cos(x) = 1 - x²/2! + x⁴/4! - x⁶/6! + ...
    result = decimal.Decimal('1')
    x_squared = x * x
    term = decimal.Decimal('1')
    
    for n in range(1, precision // 2):
        term *= -x_squared / (decimal.Decimal(2*n-1) * decimal.Decimal(2*n))
        result += term
        if abs(term) < decimal.Decimal(10) ** (-precision + 10):
            break
    
    return result

def exponential_taylor(x: decimal.Decimal, precision: int) -> decimal.Decimal:
    """Compute e^x using Taylor series with controlled precision"""
    x = decimal.Decimal(str(x))
    
    # Taylor series: e^x = 1 + x + x²/2! + x³/3! + ...
    result = decimal.Decimal('1')
    term = decimal.Decimal('1')
    
    for n in range(1, precision * 2):
        term *= x / decimal.Decimal(n)
        result += term
        if abs(term) < decimal.Decimal(10) ** (-precision + 10):
            break
    
    return result

def sine_taylor(x: decimal.Decimal, precision: int) -> decimal.Decimal:
    """Compute sin(x) using Taylor series"""
    x = decimal.Decimal(str(x))
    
    # Reduce x to [-π, π] range
    pi = decimal.Decimal('3.1415926535897932384626433832795028841971693993751')
    while x > pi:
        x -= 2 * pi
    while x < -pi:
        x += 2 * pi
    
    # Taylor series: sin(x) = x - x³/3! + x⁵/5! - x⁷/7! + ...
    result = x
    x_squared = x * x
    term = x
    
    for n in range(1, precision // 2):
        term *= -x_squared / (decimal.Decimal(2*n) * decimal.Decimal(2*n+1))
        result += term
        if abs(term) < decimal.Decimal(10) ** (-precision + 10):
            break
    
    return result

def tangent_taylor(x: decimal.Decimal, precision: int) -> decimal.Decimal:
    """Compute tan(x) = sin(x)/cos(x)"""
    sin_x = sine_taylor(x, precision)
    cos_x = cosine_taylor(x, precision)
    
    if abs(cos_x) < decimal.Decimal(10) ** (-precision + 20):
        raise TFBEError("Tangent undefined at this point")
    
    return sin_x / cos_x

def compute_auxiliary_function(k: decimal.Decimal, m: decimal.Decimal, precision: int) -> decimal.Decimal:
    """
    Compute auxiliary function: ψ(k, m) = sin(k²m) + cos(km²) + tan(km/π/4)
    """
    k = decimal.Decimal(str(k))
    m = decimal.Decimal(str(m))
    
    # Compute sin(k²m)
    k_squared_m = k * k * m
    sin_term = sine_taylor(k_squared_m, precision)
    
    # Compute cos(km²)
    k_m_squared = k * m * m
    cos_term = cosine_taylor(k_m_squared, precision)
    
    # Compute tan(km/π/4)
    pi_over_4 = decimal.Decimal('0.78539816339744830961566084581987572104929234984378')
    tan_arg = k * m * pi_over_4
    tan_term = tangent_taylor(tan_arg, precision)
    
    return sin_term + cos_term + tan_term

def compute_transcendental(k: decimal.Decimal, m: decimal.Decimal, precision: int) -> decimal.Decimal:
    """
    Compute the transcendental component: e^(cos(km)) × ψ(k, m)
    """
    k = decimal.Decimal(str(k))
    m = decimal.Decimal(str(m))
    
    # Compute cos(km)
    km = k * m
    cos_km = cosine_taylor(km, precision)
    
    # Compute e^(cos(km))
    exp_cos = exponential_taylor(cos_km, precision)
    
    # Compute auxiliary function
    auxiliary = compute_auxiliary_function(k, m, precision)
    
    return exp_cos * auxiliary

def is_prime(n: int, k: int = 10) -> bool:
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

def generate_prime(bits: int) -> int:
    """Generate a random prime of specified bit length"""
    while True:
        n = random.getrandbits(bits)
        n |= (1 << bits - 1) | 1  # Set MSB and LSB
        if is_prime(n):
            return n

def secure_real_gen(bits: int) -> decimal.Decimal:
    """Generate a secure real number for use as secret key"""
    # Generate random bits and convert to decimal
    random_int = random.getrandbits(bits)
    
    # Convert to decimal in range [0.1, 0.9] to avoid edge cases
    decimal_str = "0." + str(random_int).zfill(bits // 4)
    k = decimal.Decimal(decimal_str)
    
    # Ensure k is in a safe range
    if k < decimal.Decimal('0.1'):
        k += decimal.Decimal('0.1')
    if k > decimal.Decimal('0.9'):
        k = decimal.Decimal('0.9')
    
    return k

def TFBE_keygen(security_level: int = 256) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """
    Generate TFBE key pair
    
    Args:
        security_level: Security level in bits (128, 256, or 512)
    
    Returns:
        (public_key, private_key) tuple
    """
    if security_level not in [128, 256, 512]:
        raise TFBEKeyError("Security level must be 128, 256, or 512")
    
    # Set precision based on security level
    precision = max(security_level, 128)
    set_precision(precision * 2)
    
    # Generate prime factors
    p = generate_prime(security_level // 2)
    q = generate_prime(security_level // 2)
    N = p * q
    
    # Generate secret real-valued key
    k = secure_real_gen(security_level)
    
    # Set precision parameter
    p_param = max(security_level, 128)
    
    # Compute verification value for key validation
    test_vector = 42  # Standard test vector
    v = TFBE_encrypt_internal(test_vector, k, N, p_param)
    
    # Public key
    public_key = {
        'N': N,
        'p': p_param,
        'v': v,
        'security_level': security_level
    }
    
    # Private key
    private_key = {
        'k': k,
        'p': p_param,
        'q': q,
        'N': N,
        'prime_p': p,
        'prime_q': q,
        'security_level': security_level
    }
    
    return public_key, private_key

def TFBE_encrypt_internal(m: int, k: decimal.Decimal, N: int, p: int) -> int:
    """
    Internal encryption function: f(m, k) = ⌊(m^k) × e^(cos(km)) × ψ(k, m) × 10^p⌋ mod N
    """
    if m <= 0 or m >= N:
        raise TFBEEncryptionError("Message must be in range (0, N)")
    
    m_decimal = decimal.Decimal(str(m))
    k_decimal = decimal.Decimal(str(k))
    
    # Set precision context with guard digits
    old_prec = decimal.getcontext().prec
    decimal.getcontext().prec = p + 64
    
    try:
        # Compute m^k using logarithms: m^k = e^(k * ln(m))
        ln_m = decimal.Decimal(str(math.log(float(m_decimal))))
        k_ln_m = k_decimal * ln_m
        
        # Ensure exponent is not too large
        if abs(k_ln_m) > 100:
            raise TFBEEncryptionError("Exponent too large for computation")
        
        exponential_component = exponential_taylor(k_ln_m, p)
        
        # Compute transcendental component
        transcendental_component = compute_transcendental(k_decimal, m_decimal, p)
        
        # Combine components
        result = exponential_component * transcendental_component
        
        # Apply precision scaling
        scaled_result = result * (decimal.Decimal(10) ** p)
        
        # Apply modular reduction
        ciphertext = int(scaled_result) % N
        
        return ciphertext
        
    finally:
        decimal.getcontext().prec = old_prec

def TFBE_encrypt(m: int, public_key: Dict[str, Any]) -> int:
    """
    Encrypt a message using TFBE
    
    Args:
        m: Message to encrypt (integer)
        public_key: Public key dictionary
    
    Returns:
        Encrypted ciphertext (integer)
    """
    # Extract public key parameters
    N = public_key['N']
    p = public_key['p']
    
    # For demonstration, we need to derive k from public parameters
    # In a real implementation, this would use a different approach
    # such as embedding k in the public key or using a key derivation function
    
    # This is a limitation of the current TFBE design - encryption typically
    # requires the secret key, making it more of a symmetric cipher
    raise TFBEEncryptionError(
        "TFBE encryption requires secret key k. "
        "This is a fundamental limitation of the transcendental function approach. "
        "Use TFBE_encrypt_with_private_key for testing purposes."
    )

def TFBE_encrypt_with_private_key(m: int, private_key: Dict[str, Any]) -> int:
    """
    Encrypt using private key (for testing and demonstration)
    
    Args:
        m: Message to encrypt
        private_key: Private key dictionary
    
    Returns:
        Encrypted ciphertext
    """
    k = private_key['k']
    N = private_key['N']
    p = private_key['p']
    
    return TFBE_encrypt_internal(m, k, N, p)

def compute_derivative(m: decimal.Decimal, k: decimal.Decimal, precision: int) -> decimal.Decimal:
    """
    Compute derivative df/dm for Newton-Raphson method
    This is a simplified version - full implementation would be more complex
    """
    # For demonstration, use numerical differentiation
    h = decimal.Decimal('0.0001')
    
    f_m = compute_transcendental(k, m, precision)
    f_m_plus_h = compute_transcendental(k, m + h, precision)
    
    derivative = (f_m_plus_h - f_m) / h
    return derivative

def TFBE_decrypt(ciphertext: int, private_key: Dict[str, Any], max_iterations: int = 100, tolerance: decimal.Decimal = None) -> int:
    """
    Decrypt a ciphertext using TFBE with Newton-Raphson method
    
    Args:
        ciphertext: Ciphertext to decrypt
        private_key: Private key dictionary
        max_iterations: Maximum Newton-Raphson iterations
        tolerance: Convergence tolerance
    
    Returns:
        Decrypted plaintext
    """
    k = private_key['k']
    N = private_key['N']
    p = private_key['p']
    
    if tolerance is None:
        tolerance = decimal.Decimal(10) ** (-p // 2)
    
    # Set precision context
    old_prec = decimal.getcontext().prec
    decimal.getcontext().prec = p + 64
    
    try:
        # Define target function F(x) = f(x, k) - c
        def target_function(x):
            computed = TFBE_encrypt_internal(int(x), k, N, p)
            return computed - ciphertext
        
        # Initial guess - use simple heuristic
        x = decimal.Decimal(str(ciphertext % 10000))  # Start with reasonable guess
        
        # Newton-Raphson iteration
        for iteration in range(max_iterations):
            # Compute function value
            f_x = target_function(x)
            
            if abs(f_x) < tolerance:
                break
            
            # Compute derivative (simplified)
            derivative = compute_derivative(x, k, p)
            
            if abs(derivative) < tolerance:
                raise TFBEDecryptionError("Derivative too small, cannot continue")
            
            # Newton-Raphson update
            x_new = x - decimal.Decimal(str(f_x)) / derivative
            
            # Check convergence
            if abs(x_new - x) < tolerance:
                break
            
            x = x_new
        
        # Validate result
        candidate = int(round(float(x)))
        if candidate <= 0 or candidate >= N:
            raise TFBEDecryptionError("Decryption result out of valid range")
        
        # Verify decryption
        verification = TFBE_encrypt_internal(candidate, k, N, p)
        if verification != ciphertext:
            raise TFBEDecryptionError("Decryption verification failed")
        
        return candidate
        
    except Exception as e:
        raise TFBEDecryptionError(f"Decryption failed: {str(e)}")
    finally:
        decimal.getcontext().prec = old_prec

def TFBE_key_validation(public_key: Dict[str, Any], private_key: Dict[str, Any]) -> bool:
    """
    Validate that a key pair is consistent
    
    Args:
        public_key: Public key dictionary
        private_key: Private key dictionary
    
    Returns:
        True if key pair is valid, False otherwise
    """
    try:
        # Check that N matches
        if public_key['N'] != private_key['N']:
            return False
        
        # Check precision parameter
        if public_key['p'] != private_key['p']:
            return False
        
        # Verify that private key can decrypt the verification value
        test_vector = 42
        encrypted_test = TFBE_encrypt_with_private_key(test_vector, private_key)
        
        # This should match the verification value in the public key
        return encrypted_test == public_key['v']
        
    except Exception:
        return False

def get_security_parameters(security_level: int) -> Dict[str, Any]:
    """
    Get recommended parameters for different security levels
    
    Args:
        security_level: Desired security level (128, 256, or 512)
    
    Returns:
        Dictionary with recommended parameters
    """
    if security_level == 128:
        return {
            'precision_digits': 128,
            'key_size_kb': 2.8,
            'prime_bits': 64,
            'applications': ['General communications', 'Email encryption']
        }
    elif security_level == 256:
        return {
            'precision_digits': 256,
            'key_size_kb': 4.1,
            'prime_bits': 128,
            'applications': ['Financial transactions', 'Corporate communications']
        }
    elif security_level == 512:
        return {
            'precision_digits': 512,
            'key_size_kb': 7.2,
            'prime_bits': 256,
            'applications': ['Military communications', 'Long-term archives']
        }
    else:
        raise TFBEError("Unsupported security level")

# Testing and demonstration functions
def test_tfbe_system():
    """Test the complete TFBE system"""
    print("=== TFBE System Test ===")
    
    try:
        # Test key generation
        print("Testing key generation...")
        pub_key, priv_key = TFBE_keygen(security_level=128)
        print(f"✓ Key generation successful")
        print(f"  Modulus N: {pub_key['N']}")
        print(f"  Precision: {pub_key['p']} digits")
        
        # Test key validation
        print("\nTesting key
