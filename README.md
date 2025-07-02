# fRSA-Official
Quantum-resistant RSA variants via function recovery hardness.
# fRSA/rRSA: Post-Quantum RSA Variants  
**IACR ePrint 2024/XXXX | 10.5281/zenodo.15790722 

## Overview  
Implementation of:  
- **fRSA**: Function-transformed prime RSA  
- **rRSA**: Reverse RSA with public primes  

Security:  
- 128-512 bit post-quantum security via function recovery hardness  
- Resists Shor's algorithm (Theorem 2.1)  

## Installation  
```bash
git clone https://github.com/fRSA-Official/fRSA.git  
pip install -r requirements.txt  # pycryptodome, gmpy2
