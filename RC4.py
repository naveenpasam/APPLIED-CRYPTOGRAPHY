class RC4:
    def __init__(self, key: bytes):
        self.S = list(range(256))
        self.i = 0
        self.j = 0
        self._ksa(key)

    def _ksa(self, key: bytes):
        j = 0
        keylen = len(key)
        for i in range(256):
            j = (j + self.S[i] + key[i % keylen]) % 256
            self.S[i], self.S[j] = self.S[j], self.S[i]

    def process(self, data: bytes) -> bytes:
        output = bytearray()
        for byte in data:
            self.i = (self.i + 1) % 256
            self.j = (self.j + self.S[self.i]) % 256
            self.S[self.i], self.S[self.j] = self.S[self.j], self.S[self.i]
            K = self.S[(self.S[self.i] + self.S[self.j]) % 256]
            output.append(byte ^ K)
        return bytes(output)


# Helper: string to bytes
def str_to_bytes(s: str) -> bytes:
    return s.encode("utf-8")

# Helper: hex print
def to_hex(b: bytes) -> str:
    return "".join(f"{x:02x}" for x in b)


if __name__ == "__main__":
    key_str = "Naveen"         # key
    plaintext_str = "HelloGoodMorning" # plaintext

    key = str_to_bytes(key_str)
    plaintext = str_to_bytes(plaintext_str)

    # Encrypt
    rc4_enc = RC4(key)
    ciphertext = rc4_enc.process(plaintext)

    # Decrypt (new RC4 instance with same key)
    rc4_dec = RC4(key)
    recovered = rc4_dec.process(ciphertext)

    print("Key:       ", key_str)
    print("Plaintext: ", plaintext_str)
    print("Ciphertext (hex):", to_hex(ciphertext))
    print("Decrypted: ", recovered.decode("utf-8"))
