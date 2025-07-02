import encryptor

# Example parameters
N = 35      # modulus
a = 5
b = 7
m = 2       # message to encrypt

# Generate the secret exponent K
K = encryptor.compute_key(a, b)

# Encrypt the message
c = encryptor.encrypt(m, K, N)
print(f"Encrypted ciphertext: {c}")

# (Demo) Brute-force decryption (for small N only!)
possible_ms = encryptor.decrypt_bruteforce(c, K, N)
print(f"Possible plaintexts found by brute force: {possible_ms}")
