#include "common.h"
#include <stdarg.h>

unsigned char control_key[KEY_SIZE];
pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;

void log_message(const char *message) {
    pthread_mutex_lock(&log_mutex);
    printf("[LOG] %s\n", message);
    FILE *log_file = fopen(LOG_FILE, "a");
    if (log_file) {
        fprintf(log_file, "%s\n", message);
        fclose(log_file);
    }
    pthread_mutex_unlock(&log_mutex);
}

int encrypt_message(SecureMessage *msg, const unsigned char *key) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int ciphertext_len;
    
    if(!(ctx = EVP_CIPHER_CTX_new())) {
        log_message("Failed to create encryption context");
        return 0;
    }

    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, msg->iv)) {
        log_message("Encryption init failed");
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }

    if(1 != EVP_EncryptUpdate(ctx, (unsigned char*)msg->payload, &len, 
                             (unsigned char*)msg->payload, strlen(msg->payload)+1)) {
        log_message("Encryption update failed");
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }
    ciphertext_len = len;

    if(1 != EVP_EncryptFinal_ex(ctx, (unsigned char*)msg->payload + len, &len)) {
        log_message("Encryption final failed");
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return 1;
}

int decrypt_message(SecureMessage *msg, const unsigned char *key) {
    // Implement your decryption
    return 1; // Placeholder
}

int verify_message(SecureMessage *msg, const unsigned char *key) {
    // Implement verification
    return 1; // Placeholder
}

void init_crypto() {
    OpenSSL_add_all_algorithms();
}

void cleanup_crypto() {
    EVP_cleanup();
}

void generate_random_key(unsigned char *key, int size) {
    RAND_bytes(key, size);
}

