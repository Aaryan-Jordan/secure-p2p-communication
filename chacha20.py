import os
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

class KeyStore:
    def __init__(self):
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        self.public_key = self.private_key.public_key()

    def get_public_key(self):
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def get_private_key(self):
        return self.private_key

def encrypt_data(data, public_key_pem):
    # Deserialize the public key
    public_key = serialization.load_pem_public_key(public_key_pem)

    # Generate a random 256-bit key
    key = os.urandom(32)  # ChaCha20 requires a 32-byte key

    # Encrypt the data with ChaCha20-Poly1305
    nonce = os.urandom(16)  # ChaCha20 requires a 128-bit nonce
    cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None)
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(data) + encryptor.finalize()

    # Encrypt the ChaCha20 key with the receiver's public key
    encrypted_key = public_key.encrypt(
        key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return encrypted_key, nonce, encrypted_data

def decrypt_data(encrypted_key, nonce, encrypted_data, private_key):
    # Decrypt the ChaCha20 key with the receiver's private key
    key = private_key.decrypt(
        encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Decrypt the data with ChaCha20-Poly1305
    cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None)
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

    return decrypted_data

'''
encrypted_key = 256
nonce = 16
encrypted_data = 29 len(data)

total = 256 + 16 + len(data)
'''
def main():
    # Create a KeyStore and get the public and private keys
    keystore = KeyStore()
    public_key_pem = keystore.get_public_key()
    private_key = keystore.get_private_key()

    # The data to encrypt
    data = b"This is some data to encrypt."

    # Encrypt the data
    encrypted_key, nonce, encrypted_data = encrypt_data(data, public_key_pem)

    print(encrypted_key)
    print(nonce)
    print(encrypted_data)

    # Decrypt the data
    decrypted_data = decrypt_data(encrypted_key, nonce, encrypted_data, private_key)

    # Print the original and decrypted data
    print("Original data:", data)
    print("Decrypted data:", decrypted_data)

if __name__ == "__main__":
    main()
