#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>

#define KEY_SIZE 32 // 256 bits key size
#define IV_SIZE 16  // 128 bits IV size
#define INPUT_SIZE 9 // Size of input string including null terminator

// Function to generate a random key
void generate_key(unsigned char *key) {
    FILE *fp = fopen("/dev/urandom", "r");
    if (fp == NULL) {
        fprintf(stderr, "Failed to open /dev/urandom\n");
        exit(1);
    }
    if (fread(key, 1, KEY_SIZE, fp) != KEY_SIZE) {
        fprintf(stderr, "Failed to read from /dev/urandom\n");
        exit(1);
    }
    fclose(fp);
}

// Function to perform AES encryption
unsigned char *aes_encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key, unsigned char *iv, int *cipher_len) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int ciphertext_len;

    // Create and initialize the context
    if (!(ctx = EVP_CIPHER_CTX_new())) {
        fprintf(stderr, "Error creating EVP context\n");
        return NULL;
    }

    // Initialize the encryption operation
    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
        EVP_CIPHER_CTX_free(ctx);
        fprintf(stderr, "Error initializing encryption operation\n");
        return NULL;
    }

    // Perform encryption
    unsigned char *ciphertext = malloc(plaintext_len + EVP_CIPHER_CTX_block_size(ctx));
    if (!ciphertext) {
        EVP_CIPHER_CTX_free(ctx);
        fprintf(stderr, "Memory allocation failed\n");
        return NULL;
    }
    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len)) {
        EVP_CIPHER_CTX_free(ctx);
        free(ciphertext);
        fprintf(stderr, "Error performing encryption\n");
        return NULL;
    }
    ciphertext_len = len;

    // Finalize encryption
    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) {
        EVP_CIPHER_CTX_free(ctx);
        free(ciphertext);
        fprintf(stderr, "Error finalizing encryption\n");
        return NULL;
    }
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    *cipher_len = ciphertext_len;
    return ciphertext;
}

// Function to perform AES decryption
unsigned char *aes_decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key, unsigned char *iv, int *plaintext_len) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len_temp;

    // Create and initialize the context
    if (!(ctx = EVP_CIPHER_CTX_new())) {
        fprintf(stderr, "Error creating EVP context\n");
        return NULL;
    }

    // Initialize the decryption operation
    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
        EVP_CIPHER_CTX_free(ctx);
        fprintf(stderr, "Error initializing decryption operation\n");
        return NULL;
    }

    // Perform decryption
    unsigned char *plaintext = malloc(ciphertext_len + EVP_CIPHER_CTX_block_size(ctx));
    if (!plaintext) {
        EVP_CIPHER_CTX_free(ctx);
        fprintf(stderr, "Memory allocation failed\n");
        return NULL;
    }
    if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) {
        EVP_CIPHER_CTX_free(ctx);
        free(plaintext);
        fprintf(stderr, "Error performing decryption\n");
        return NULL;
    }
    plaintext_len_temp = len;

    // Finalize decryption
    if (1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) {
        EVP_CIPHER_CTX_free(ctx);
        free(plaintext);
        fprintf(stderr, "Error finalizing decryption\n");
        return NULL;
    }
    plaintext_len_temp += len;

    EVP_CIPHER_CTX_free(ctx);

    plaintext[plaintext_len_temp] = '\0'; // Ensure null termination
    *plaintext_len = plaintext_len_temp;
    return plaintext;
}

int main() {
    unsigned char input[33] ;
    unsigned char key[KEY_SIZE];
    unsigned char iv[IV_SIZE];
    int cipher_len;
    FILE *filep;
	
	printf("Input:");
	scanf("%s",input);

    // Generate a random key
    generate_key(key);
    printf("Key (hex): ");
    for (int i = 0; i < 32; i++) {
        printf("%02x", key[i]);
    }
    printf("\n");

    // Generate a random IV (Initialization Vector)
    FILE *fp = fopen("/dev/urandom", "r");
    if (fp == NULL) {
        fprintf(stderr, "Failed to open /dev/urandom\n");
        exit(1);
    }
    if (fread(iv, 1, IV_SIZE, fp) != IV_SIZE) {
        fprintf(stderr, "Failed to read from /dev/urandom\n");
        exit(1);
    }
    fclose(fp);


    printf("iv (hex): ");
    for (int i = 0; i < 16; i++) {
        printf("%02x", iv[i]);
    }
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

    // Print the decrypted password
    printf("Decrypted Password: %s\n", plaintext);

    char* enc_ret = (char *)malloc(sizeof(char)*(2*cipher_len+1));
    for (int i = 0; i < cipher_len; i++) {
        sprintf(enc_ret + i*2,"%02x",ciphertext[i]);
    }

    // Free memory
    free(ciphertext);
    free(plaintext);
    return 0;
}
