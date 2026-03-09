import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

KEY_SIZE = 32  # 256 bits key size
NONCE_SIZE = 12  # GCM 推薦的 Nonce (IV) 長度為 96 bits (12 bytes)

def generate_key():
    return os.urandom(KEY_SIZE)

def aes_gcm_encrypt(plaintext: bytes, key: bytes) -> bytes:
    # AES-GCM 不需要 Padding
    aesgcm = AESGCM(key)
    nonce = os.urandom(NONCE_SIZE)
    
    # 加密並自動產生驗證標籤 (Tag)，附加在密文後方
    ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data=None)
    
    # 實務上通常將 Nonce 與密文合併回傳，方便儲存或傳輸
    return nonce + ciphertext

def aes_gcm_decrypt(encrypted_data: bytes, key: bytes) -> bytes:
    aesgcm = AESGCM(key)
    
    # 拆分 Nonce 與實際密文
    nonce = encrypted_data[:NONCE_SIZE]
    ciphertext = encrypted_data[NONCE_SIZE:]
    
    try:
        # 解密時會自動驗證完整性 (Tag)，若被竄改會拋出 InvalidTag
        plaintext = aesgcm.decrypt(nonce, ciphertext, associated_data=None)
        return plaintext
    except InvalidTag:
        print("[-] 錯誤：密文已被竄改或金鑰錯誤！(Authentication Failed)")
        return None
    except Exception as e:
        print(f"[-] 解密發生未知的錯誤: {e}")
        return None

def main():
    try:
        input_text = input("Input: ").encode('utf-8')
    except KeyboardInterrupt:
        return

    key = generate_key()
    print("Key (hex):", key.hex())

    # Encrypt
    encrypted_data = aes_gcm_encrypt(input_text, key)
    print("Encrypted Data (Nonce + Ciphertext) (hex):", encrypted_data.hex())

    # Decrypt
    plaintext = aes_gcm_decrypt(encrypted_data, key)
    if plaintext:
        print("Decrypted Password:", plaintext.decode('utf-8'))

if __name__ == "__main__":
    main()
