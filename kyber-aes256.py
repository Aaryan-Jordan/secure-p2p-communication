import sys
import oqs
import os
import gzip
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# KEM and signature algorithms
kem_alg_name = "Kyber512"
sig_alg_name = "Dilithium2"

class KeyStore:
    def __init__(self, kem_alg_name):
        self.kem_alg_name = kem_alg_name
        self.public_key = None
        self.secret_key = None

    def generate_keypair(self):
        with oqs.KeyEncapsulation(self.kem_alg_name) as kem:
            # Generate a public_key and secret_key
            # public_key: used to get encap_ciphertext, shared_secret
            #   encap_ciphertext: We transfer it to the other side.
            #       will be need to get the shared_secret when used with secret_key
            #   shared_secret: This is used as a key to AES algo.
            # secret_key: Used to get the shared_secret on the other side
            self.public_key = kem.generate_keypair()
            self.secret_key = kem.export_secret_key()

    def get_public_key(self):
        return self.public_key

    def get_secret_key(self):
        return self.secret_key

def encrypt_data(data, keystore):
    with oqs.KeyEncapsulation(kem_alg_name) as kem:
        keystore.generate_keypair()
        public_key = keystore.get_public_key()
        encap_ciphertext, shared_secret = kem.encap_secret(public_key)
        nonce = os.urandom(12)  # Generate a random nonce
        cipher = Cipher(algorithms.AES(shared_secret), modes.GCM(nonce))
        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(data) + encryptor.finalize()
        tag = encryptor.tag
        ciphertext = nonce + encrypted_data + tag

        # Sign the ciphertext
        with oqs.Signature(sig_alg_name) as signer:
            signer_public_key = signer.generate_keypair()
            signature = signer.sign(ciphertext)

    # Length of encap_ciphertext: always 768 bytes
    # Length of ciphertext: 12 bytes (nonce) + 16 bytes (tag) + len(data) bytes
    # Length of signature: always 2420 bytes
    # Length of signer_public_key: always 1312 bytes
    # Total length: 4500 bytes + len(data) bytes & 768 bytes + len(data) bytes (without data signature)
    return encap_ciphertext, ciphertext, signature, signer_public_key

def decrypt_data(encap_ciphertext, ciphertext, signature, signer_public_key, keystore):
    secret_key = keystore.get_secret_key()
    with oqs.KeyEncapsulation(kem_alg_name, secret_key=secret_key) as kem:
        decapsulated_secret = kem.decap_secret(encap_ciphertext)
        nonce = ciphertext[:12]
        encrypted_data = ciphertext[12:-16]
        tag = ciphertext[-16:]
        # print("Encap Ciphertext:\n", encap_ciphertext)
        # print("Ciphertext:\n",ciphertext)
        # print("Nonce:\n",nonce)
        # print("Encrypted Data:\n",encrypted_data)
        # print("Tag:\n",tag)

        print(sys.getsizeof(base64.b64encode(gzip.compress(encap_ciphertext))))


        cipher = Cipher(algorithms.AES(decapsulated_secret), modes.GCM(nonce))
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize_with_tag(tag)

        # Verify the signature
        with oqs.Signature(sig_alg_name) as verifier:
            is_valid = verifier.verify(ciphertext, signature, signer_public_key)
            if not is_valid:
                raise ValueError("Invalid signature!")

    return decrypted_data

if __name__ == "__main__":
    keystore = KeyStore(kem_alg_name)
 
    data_string = input("Enter data to encrypt: ")
    data_hex = data_string.encode("utf-8").hex()

    # Encrypt the data
    encap_ciphertext, ciphertext, signature, signer_public_key = encrypt_data(data_hex.encode(), keystore)

    # Decrypt the data
    decrypted_data_bytes = decrypt_data(encap_ciphertext, ciphertext, signature, signer_public_key, keystore)

    print("Decrypted data in bytes", decrypted_data_bytes)
    print("Decrypted data in string", bytes.fromhex(decrypted_data_bytes.decode("utf-8")).decode("utf-8"))