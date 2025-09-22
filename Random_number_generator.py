import secrets
import string

# Function for secure random string from a custom subset of characters
def generate_secure_random_from_subset(subset, length):
    """
    Generates a cryptographically secure random string from a custom subset.
    Args:
        subset (str): The allowed characters (digits + alphabets subset).
        length (int): Length of the string to generate.
    Returns:
        str: Securely generated random string.
    """
    return ''.join(secrets.choice(subset) for _ in range(length))

if __name__ == "__main__":
    # Custom subset: digits 1-5 and uppercase letters A-E
    custom_subset = '12345ABCDE'
    desired_length = 10

    # Generate a secure random string from the subset
    secure_random_str = generate_secure_random_from_subset(custom_subset, desired_length)
    print("Secure random string from subset:", secure_random_str)

    # Example of larger subset using digits and alphabets (uppercase + lowercase)
    full_pool = string.ascii_letters + string.digits
    secure_random_str_full = generate_secure_random_from_subset(full_pool, desired_length)
    print("Secure random string from full digit+alphabet pool:", secure_random_str_full)
