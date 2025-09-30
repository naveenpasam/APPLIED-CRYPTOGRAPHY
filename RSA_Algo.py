import secrets
import math


def is_probable_prime(n: int, k: int = 40) -> bool:
    if n < 2:
        return False
    small_primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29]
    for p in small_primes:
        if n % p == 0:
            return n == p
    s = 0
    d = n - 1
    while d % 2 == 0:
        d //= 2
        s += 1
    for _ in range(k):
        a = secrets.randbelow(n - 3) + 2  # a in [2, n-2]
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        composite = True
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                composite = False
                break
        if composite:
            return False
    return True


def generate_prime(bits: int) -> int:
    if bits < 2:
        raise ValueError("bits must be >= 2")
    while True:
        candidate = secrets.randbits(bits) | (1 << (bits - 1)) | 1
        if is_probable_prime(candidate):
            return candidate


def egcd(a: int, b: int):
    if b == 0:
        return a, 1, 0
    g, x1, y1 = egcd(b, a % b)
    return g, y1, x1 - (a // b) * y1


def modinv(a: int, m: int) -> int:
    g, x, _ = egcd(a, m)
    if g != 1:
        raise ValueError("modular inverse does not exist")
    return x % m


def generate_rsa_keypair(bits: int = 1024, e: int = 65537):
    if bits < 16:
        raise ValueError("bits too small")
    half = bits // 2
    while True:
        p = generate_prime(half)
        q = generate_prime(bits - half)
        if p == q:
            continue
        n = p * q
        if n.bit_length() != bits:
            continue
        phi = (p - 1) * (q - 1)
        if math.gcd(e, phi) != 1:
            continue
        d = modinv(e, phi)
        return (n, e, d)


def encrypt_int(m_int: int, pub):
    n, e = pub
    if m_int < 0 or m_int >= n:
        raise ValueError("message integer out of range (0 <= m < n)")
    return pow(m_int, e, n)


def decrypt_int(c_int: int, priv):
    n, d = priv
    return pow(c_int, d, n)


def bytes_to_int(b: bytes) -> int:
    return int.from_bytes(b, byteorder='big')


def int_to_bytes(i: int) -> bytes:
    if i == 0:
        return b'\x00'
    length = (i.bit_length() + 7) // 8
    return i.to_bytes(length, byteorder='big')


def encrypt_message(message: str, pub):
    b = message.encode('utf-8')
    m_int = bytes_to_int(b)
    n, _ = pub
    if m_int >= n:
        raise ValueError("message too long for given key size; use padding and chunking or larger key")
    c_int = encrypt_int(m_int, pub)
    return c_int


def decrypt_message(c_int: int, priv):
    m_int = decrypt_int(c_int, priv)
    b = int_to_bytes(m_int)
    return b.decode('utf-8', errors='strict')


if __name__ == "__main__":
    bits = 1024
    print(f"Generating RSA keypair with {bits} bits...")
    n, e, d = generate_rsa_keypair(bits=bits, e=65537)
    public_key = (n, e)
    private_key = (n, d)
    print("Keys generated.")
    print(f"Public modulus n has {n.bit_length()} bits.")

    message = "Hello RSA — this is a test!"
    print("Original message:", message)

    ciphertext = encrypt_message(message, public_key)
    print("Ciphertext (integer):", ciphertext)

    recovered = decrypt_message(ciphertext, private_key)
    print("Decrypted message:", recovered)

    assert message == recovered
    print("Success: decrypted message matches original.")
