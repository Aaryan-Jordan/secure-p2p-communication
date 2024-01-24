from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac
import os
import concurrent.futures

class Entity:
    def __init__(self):
        self.generate_new_rsa_key_pair()

    def generate_new_rsa_key_pair(self):
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

    def encrypt_data(self, data, public_key_pem):
        aes_key = os.urandom(32)
        nonce = os.urandom(12)

        cipher_aes = Cipher(algorithms.AES(aes_key), modes.GCM(nonce))
        encryptor_aes = cipher_aes.encryptor()
        encrypted_data_aes = encryptor_aes.update(data) + encryptor_aes.finalize()
        tag_aes = encryptor_aes.tag

        h = hmac.HMAC(aes_key, hashes.SHA256())
        h.update(encrypted_data_aes)
        hmac_aes = h.finalize()

        public_key = serialization.load_pem_public_key(public_key_pem)
        encrypted_key_aes = public_key.encrypt(
            aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        return encrypted_key_aes, encrypted_data_aes, tag_aes, nonce, hmac_aes

    def decrypt_data(self, encrypted_key_aes, encrypted_data_aes, tag_aes, nonce, hmac_aes):
        aes_key = self.private_key.decrypt(
            encrypted_key_aes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        h = hmac.HMAC(aes_key, hashes.SHA256())
        h.update(encrypted_data_aes)
        h.verify(hmac_aes)

        cipher_aes = Cipher(algorithms.AES(aes_key), modes.GCM(nonce, tag_aes))
        decryptor_aes = cipher_aes.decryptor()
        decrypted_data = decryptor_aes.update(encrypted_data_aes) + decryptor_aes.finalize()

        return decrypted_data

def generate_and_encrypt(entity, receiver, data):
    entity.generate_new_rsa_key_pair()
    encrypted_data = entity.encrypt_data(data, receiver.get_public_key())
    return encrypted_data

def parallel_transfer_data(sender, receiver, data_chunks):
    with concurrent.futures.ThreadPoolExecutor() as executor:
        encrypted_data_chunks = list(executor.map(lambda chunk: generate_and_encrypt(sender, receiver, chunk), data_chunks))

    decrypted_data_chunks = [receiver.decrypt_data(*encrypted_chunk) for encrypted_chunk in encrypted_data_chunks]
    return decrypted_data_chunks

# Example usage:
mcs = Entity()
robot = Entity()

data_chunks = [b"Chunk1", b"Chunk2", b"Chunk3"]

decrypted_data_parallel = parallel_transfer_data(mcs, robot, data_chunks)
print("Decrypted Data (Parallel):", decrypted_data_parallel)
