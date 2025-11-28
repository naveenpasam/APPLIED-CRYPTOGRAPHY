from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad

# Key must be exactly 8 bytes
key = b'8bytekey' 
cipher = DES.new(key, DES.MODE_ECB)

text = "Hello DES"

# Encrypt (pad to 8-byte blocks)
encrypted = cipher.encrypt(pad(text.encode(), 8))
print(f"Encrypted (Hex): {encrypted.hex()}")

# Decrypt
decrypted = unpad(cipher.decrypt(encrypted), 8).decode()
print(f"Decrypted: {decrypted}")