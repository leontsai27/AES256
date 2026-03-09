#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rand.h> // 引入 OpenSSL 的隨機數庫

#define KEY_SIZE 32 // 256 bits key size
#define IV_SIZE 16  // 128 bits IV size

// 使用 OpenSSL 內建函數，跨平台且更簡潔
void generate_random_bytes(unsigned char *buffer, int length) {
    if (RAND_bytes(buffer, length) != 1) {
        fprintf(stderr, "Error generating random bytes.\n");
        exit(1);
    }
}

// ... (aes_encrypt 和 aes_decrypt 保持不變) ...

int main() {
    unsigned char input[33]; // 32 chars + 1 null terminator
    unsigned char key[KEY_SIZE];
    unsigned char iv[IV_SIZE];
    int cipher_len;
	
    printf("Input (max 32 chars): ");
    // 【修正】防止 Buffer Overflow
    if (scanf("%32s", input) != 1) {
        fprintf(stderr, "Input error\n");
        return 1;
    }

    // 【優化】使用統一的函數生成 Key 和 IV
    generate_random_bytes(key, KEY_SIZE);
    printf("Key (hex): ");
    for (int i = 0; i < KEY_SIZE; i++) printf("%02x", key[i]);
    printf("\n");

    generate_random_bytes(iv, IV_SIZE);
    printf("IV (hex): ");
    for (int i = 0; i < IV_SIZE; i++) printf("%02x", iv[i]);
    printf("\n");

    // Encrypt the input
    unsigned char *ciphertext = aes_encrypt(input, strlen((char *)input), key, iv, &cipher_len);
    if (ciphertext == NULL) {
        fprintf(stderr, "Encryption failed\n");
        return 1;
    }

    printf("Encrypted Password (hex): ");
    for (int i = 0; i < cipher_len; i++) {
        printf("%02x", ciphertext[i]);
    }
    printf("\n");

    // Decrypt the ciphertext
    int plaintext_len;
    unsigned char *plaintext = aes_decrypt(ciphertext, cipher_len, key, iv, &plaintext_len);
    if (plaintext == NULL) {
        fprintf(stderr, "Decryption failed\n");
        free(ciphertext);
        return 1;
    }

    printf("Decrypted Password: %s\n", plaintext);

    // 將密文轉為 Hex 字串儲存
    char* enc_ret = (char *)malloc(sizeof(char)*(2*cipher_len+1));
    if (enc_ret != NULL) {
        for (int i = 0; i < cipher_len; i++) {
            sprintf(enc_ret + i*2, "%02x", ciphertext[i]);
        }
        // printf("Hex String: %s\n", enc_ret);
        
        // 【修正】釋放記憶體
        free(enc_ret); 
    }

    // Free memory
    free(ciphertext);
    free(plaintext);
    return 0;
}
