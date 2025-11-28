# Simple Elliptic Curve over a prime field
# y^2 = x^3 + a*x + b (mod p)

p = 9739
a = 497
b = 1768

# Point addition
def add(P, Q):
    if P is None: return Q
    if Q is None: return P

    x1, y1 = P
    x2, y2 = Q

    if x1 == x2 and (y1 + y2) % p == 0:
        return None

    if P == Q:
        m = (3*x1*x1 + a) * pow(2*y1, -1, p)
    else:
        m = (y2 - y1) * pow(x2 - x1, -1, p)

    m %= p
    x3 = (m*m - x1 - x2) % p
    y3 = (m*(x1 - x3) - y1) % p

    return (x3, y3)

# Scalar multiplication (double-and-add)
def mul(k, P):
    R = None
    while k > 0:
        if k & 1:
            R = add(R, P)
        P = add(P, P)
        k >>= 1
    return R

# Generator point on curve
G = (1804, 5368)

# Key generation
import random
d = random.randint(1, p-1)   # private key
Q = mul(d, G)                # public key

print("Private key:", d)
print("Public key :", Q)
