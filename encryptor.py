import math

def f(x):
    return x + math.sin(x)

def compute_key(a, b, f=f):
    return f(a) * f(b)

def encrypt(m, K, N):
    return int(m ** K) % N

def decrypt_bruteforce(c, K, N, max_m=1000):
    candidates = []
    for m in range(1, max_m + 1):
        if int(m ** K) % N == c:
            candidates.append(m)
    return candidates
