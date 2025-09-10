from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256

# ---- Padding (PKCS7) ----
def pad(data: bytes) -> bytes:
    pad_len = 16 - (len(data) % 16)
    return data + bytes([pad_len]) * pad_len

def unpad(data: bytes) -> bytes:
    pad_len = data[-1]
    if pad_len < 1 or pad_len > 16:
        raise ValueError("Invalid padding")
    return data[:-pad_len]

# ---- Derive AES key from password ----
def get_key_from_password(password: bytes, salt: bytes) -> bytes:
    # PBKDF2 with SHA256, 100k iterations, 256-bit key
    return PBKDF2(password, salt, dkLen=32, count=100000, hmac_hash_module=SHA256)

# ---- AES Encrypt ----
def encrypt_aes(plaintext: str, password: str) -> bytes:
    salt = get_random_bytes(16)  # Random salt
    key = get_key_from_password(password.encode(), salt)

    iv = get_random_bytes(16)  # Initialization Vector
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ct = cipher.encrypt(pad(plaintext.encode()))

    # return salt + iv + ciphertext
    return salt + iv + ct

# ---- AES Decrypt ----
def decrypt_aes(data: bytes, password: str) -> str:
    salt = data[:16]
    iv = data[16:32]
    ct = data[32:]

    key = get_key_from_password(password.encode(), salt)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = cipher.decrypt(ct)
    return unpad(pt).decode()

# ---- Main program ----
if __name__ == "__main__":
    message = input("Enter message to encrypt: ")
    password = input("Enter password: ")

    encrypted = encrypt_aes(message, password)
    print("\nEncrypted (hex):", encrypted.hex())

    decrypted = decrypt_aes(encrypted, password)
    print("Decrypted:", decrypted)
    