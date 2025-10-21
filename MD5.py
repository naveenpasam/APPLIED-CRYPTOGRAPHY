import hashlib

# Step 1: Sender generates a signature
message = input("Enter the original message: ")

# Generate MD5 hash (digital signature)
signature = hashlib.md5(message.encode()).hexdigest()
print("\nGenerated Signature (MD5 Hash):", signature)

print("\n--- Verification Phase ---")

# Step 2: Receiver enters received message and signature
received_message = input("Enter the received message: ")
received_signature = input("Enter the received signature: ")

# Step 3: Compute hash of the received message
computed_hash = hashlib.md5(received_message.encode()).hexdigest()

# Step 4: Compare signatures
if computed_hash == received_signature:
    print("\n✅ Signature Verified: Message is authentic and unaltered.")
else:
    print("\n❌ Verification Failed: Message may be modified or signature is invalid.")