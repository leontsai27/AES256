from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os

KEY_SIZE = 32  # 256 bits key size
IV_SIZE = 16   # 128 bits IV size

def generate_key():
    return os.urandom(KEY_SIZE)

def aes_encrypt(plaintext, key, iv):
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_plaintext = padder.update(plaintext) + padder.finalize()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
    return ciphertext

def aes_decrypt(ciphertext, key, iv):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
    return plaintext

def main():
    input_text = input("Input: ").encode('utf-8')
    key = generate_key()
    iv = os.urandom(IV_SIZE)
    print("Key (hex):", key.hex())

    print("Key :", key)

    # Encrypt the input
    ciphertext = aes_encrypt(input_text, key, iv)
    print("Encrypted Password (hex):", ciphertext.hex())

    # Decrypt the ciphertext
    plaintext = aes_decrypt(ciphertext, key, iv)
    print("Decrypted Password:", plaintext.decode('utf-8'))

if __name__ == "__main__":
    main()
