import hashlib
import random
from sympy import randprime, mod_inverse

# Generate RSA keys
def generate_rsa_keys(key_size=1024):
    # Generate two random primes of ~ key_size/2 bits
    p = randprime(2 ** (key_size // 2 - 1), 2 ** (key_size // 2))
    q = randprime(2 ** (key_size // 2 - 1), 2 ** (key_size // 2))
    n = p * q
    phi = (p - 1) * (q - 1)

    e = 65537  # common public exponent
    # Ensure e has an inverse modulo phi
    while mod_inverse(e, phi) is None:
        e = random.randrange(3, phi, 2)

    d = mod_inverse(e, phi)

    public_key = (n, e)
    private_key = (n, d)
    return public_key, private_key


# Sign message using private key
def sign_message(message, private_key):
    n, d = private_key
    # Hash the message
    message_hash = int(hashlib.sha256(message.encode()).hexdigest(), 16)
    if message_hash >= n:
        # truncate/rehash if hash >= modulus (simplified)
        message_hash = message_hash % n
    # Signature = hash^d mod n
    signature = pow(message_hash, d, n)
    return hex(signature)[2:]  # strip "0x"


# Verify signature using public key
def verify_signature(message, signature_hex, public_key):
    n, e = public_key
    # Hash the message
    message_hash = int(hashlib.sha256(message.encode()).hexdigest(), 16)
    if message_hash >= n:
        message_hash = message_hash % n

    # Decrypt signature
    signature = int(signature_hex, 16)
    decrypted_hash = pow(signature, e, n)

    return decrypted_hash == message_hash


# Demo
if __name__ == "__main__":
    # Key generation
    public_key, private_key = generate_rsa_keys(1024)
    print(f"Public key: n={public_key[0]}, e={public_key[1]}")
    print(f"Private key: n={private_key[0]}, d={private_key[1]}")

    # Original message
    message = "Hello, RSA Signature!"
    signature = sign_message(message, private_key)
    print(f"Signature: {signature}")

    # Verify valid signature
    is_valid = verify_signature(message, signature, public_key)
    print(f"Signature valid: {is_valid}")

    # Verify tampered message
    tampered_message = "Hello, RSA Signature!!"
    is_tampered_valid = verify_signature(tampered_message, signature, public_key)
    print(f"Tampered signature valid: {is_tampered_valid}")
