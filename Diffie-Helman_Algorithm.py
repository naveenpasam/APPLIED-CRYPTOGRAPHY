# Diffie–Hellman Key Exchange Implementation

# Step 1: Publicly known prime number (p) and primitive root (g)
p = 23      # a prime number
g = 5       # primitive root modulo p

print("Publicly shared values:")
print("Prime number (p):", p)
print("Primitive root (g):", g)

# Step 2: Alice chooses a private key (a)
a = 6
# Compute Alice's public key
A = (g ** a) % p
print("\nAlice's Private Key (a):", a)
print("Alice's Public Key (A):", A)

# Step 3: Bob chooses a private key (b)
b = 15
# Compute Bob's public key
B = (g ** b) % p
print("\nBob's Private Key (b):", b)
print("Bob's Public Key (B):", B)

# Step 4: Exchange public keys and compute shared secret
# Alice computes the secret using Bob's public key
secret_key_Alice = (B ** a) % p

# Bob computes the secret using Alice's public key
secret_key_Bob = (A ** b) % p

print("\nShared Secret Computed by Alice:", secret_key_Alice)
print("Shared Secret Computed by Bob:", secret_key_Bob)

# Both keys should match
if secret_key_Alice == secret_key_Bob:
    print("\n✅ Key Exchange Successful! Shared secret key =", secret_key_Alice)
else:
    print("\n❌ Key Exchange Failed.")
