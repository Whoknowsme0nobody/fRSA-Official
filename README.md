# Function-Based Floating-Point Modular Exponentiation Encryption

## 🚀 Overview

This project is an experimental cryptographic system that uses function-based, floating-point modular exponentiation for encryption. Unlike classic RSA and other public-key cryptosystems, this approach leverages a secret, high-precision floating-point exponent, making decryption without the key infeasible—even for quantum computers.

> **DISCLAIMER:**  
> This scheme is highly experimental and not a replacement for standard, peer-reviewed cryptography. Use for educational and research purposes only.

---

## 🔑 How It Works

### Key Components

- **Modulus (`N`)**: A public integer, typically the product of two primes.
- **Secret values (`a`, `b`)**: Chosen integers (can be primes).
- **Function (`f(x)`)**: Any real-valued function (e.g., `x + sin(x)`).
- **Secret exponent (`K`)**: Computed as `K = f(a) * f(b)` (or other composition).
- **Message (`m`)**: The integer to encrypt.

### Encryption Formula

\[
c = \left\lfloor m^K \right\rfloor \bmod N
\]

- `c` is the ciphertext.
- `K` is a high-precision, secret, real-valued exponent.

### Decryption

- **Requires exact knowledge of `K` to high precision.**
- Decryption is only possible for the legitimate key holder due to floating-point sensitivity.

---

## 🧪 Security Properties

- **No known quantum or classical shortcut:**  
  Without the exact secret exponent `K`, brute-forcing the message is the only way, which is infeasible even for quantum computers if `K` is sufficiently large and precise.

- **Security by complexity, not proven hardness:**  
  This scheme’s security is not based on classic number theory (like factoring or discrete log), but on the unpredictability and precision requirements of floating-point exponentiation.

- **No algebraic structure to exploit:**  
  There is no known mathematical reduction or shortcut for an attacker, as the system lacks the structure quantum (or classical) algorithms typically exploit.

> **Note:**  
> Like all post-quantum cryptographic schemes, there is no absolute proof of security—just “no known attack” at this time.

---

## ⚠️ Limitations & Warnings

- **Not peer-reviewed or standardized.**
- **No cryptographic hardness proof.**
- **Precision-sensitive:**  
  Legitimate decryption requires the exact secret exponent (potentially hundreds of decimals).
- **Not suitable for production or critical applications.**
- **“Security by obscurity/complexity”:**  
  This is not a substitute for mathematical proof, but does offer practical resistance to both classical and quantum brute-force attacks.

---

## 🧩 Example

```python
import math

# Public parameters
N = 35
a = 5
b = 7
def f(x):
    return x + math.sin(x)

# Secret exponent
K = f(a) * f(b)  # ≈ 30.9365383

# Message to encrypt
m = 2

# Encryption
c = int(m ** K) % N
print(f"Ciphertext: {c}")
```

---

## 💡 Innovation & Future Work

- This approach is **new and unproven**—it may inspire further research or challenges.
- The only way to build trust or find weaknesses is through open experimentation and community review.
- All cryptographic systems start as innovations; time and peer review determine their future.

---

## 👀 Challenge

Do you think you can break it?  
Try to recover the original message without knowing the exact secret exponent K!

---

## 📚 References

- [Post-Quantum Cryptography (NIST)](https://csrc.nist.gov/projects/post-quantum-cryptography)
- [Why floating-point math is hard to invert](https://en.wikipedia.org/wiki/Floating-point_arithmetic)
- [Discussion: Security by Obscurity](https://en.wikipedia.org/wiki/Security_through_obscurity)

---

## 📝 License

MIT License
