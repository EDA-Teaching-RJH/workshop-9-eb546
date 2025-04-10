#include "common.h"
#include <stdarg.h>
#include <sys/time.h>

// Global variables (if needed)
static pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;

// Initialize OpenSSL crypto
void init_crypto() {
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
}

// Cleanup OpenSSL
void cleanup_crypto() {
    EVP_cleanup();
    ERR_free_strings();
}

void log_message(const char *message) {
    pthread_mutex_lock(&log_mutex);
    
    // Log to console
    printf("[LOG] %s\n", message);
    
    // Log to file (optionally encrypted)
    FILE *log_file = fopen(LOG_FILE, "a");
    if (log_file) {
        time_t now = time(NULL);
        char *time_str = ctime(&now);
        time_str[strlen(time_str)-1] = '\0';
        
        // Create log entry
        char log_entry[BUFFER_SIZE * 2];
        snprintf(log_entry, sizeof(log_entry), "[%s] %s\n", time_str, message);
        
        // For encrypted logs:
        if (ENCRYPT_LOGS) {
            SecureMessage encrypted_log;
            strcpy(encrypted_log.sender, "LOGGER");
            strcpy(encrypted_log.payload, log_entry);
            if (encrypt_message(&encrypted_log, control_key)) {
                fwrite(&encrypted_log, sizeof(encrypted_log), 1, log_file);
            }
        } else {
            fputs(log_entry, log_file);
        }
        
        fclose(log_file);
    }
    
    pthread_mutex_unlock(&log_mutex);
}

// Handle errors (print and optionally exit)
void handle_error(const char *msg, bool fatal) {
    log_message(msg);
    if (fatal) {
        exit(EXIT_FAILURE);
    }
}

// Encrypt a message using AES-256-CBC
int encrypt_message(SecureMessage *msg, const unsigned char *key) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return 0;

    // Generate random IV
    RAND_bytes(msg->iv, IV_SIZE);

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, msg->iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }

    int len;
    int ciphertext_len = 0;

    if (EVP_EncryptUpdate(ctx, (unsigned char *)msg->payload, &len, 
                         (unsigned char *)msg->payload, strlen(msg->payload)) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }
    ciphertext_len += len;

    if (EVP_EncryptFinal_ex(ctx, (unsigned char *)msg->payload + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return 1;
}

// Enhanced decrypt_message function
int decrypt_message(SecureMessage *msg, const unsigned char *key) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        log_message("Failed to create cipher context for decryption");
        return 0;
    }

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, msg->iv) != 1) {
        log_message("Decryption initialization failed");
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }

    int len;
    int plaintext_len = 0;
    unsigned char buffer[BUFFER_SIZE] = {0};

    if (EVP_DecryptUpdate(ctx, buffer, &len, 
                         (unsigned char *)msg->payload, strlen(msg->payload)) != 1) {
        log_message("Decryption update failed");
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }
    plaintext_len += len;

    if (EVP_DecryptFinal_ex(ctx, buffer + len, &len) != 1) {
        log_message("Decryption finalization failed");
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }
    plaintext_len += len;

    // Copy decrypted data back to message
    memcpy(msg->payload, buffer, plaintext_len);
    msg->payload[plaintext_len] = '\0';
    
    EVP_CIPHER_CTX_free(ctx);
    
    // Log decrypted message for debugging
    char log_msg[BUFFER_SIZE + 50];
    snprintf(log_msg, sizeof(log_msg), "Decrypted message: %s", msg->payload);
    log_message(log_msg);
    
    return 1;
}

// New function to decrypt log files
void decrypt_log_file(const char* encrypted_log_path, const unsigned char* key) {
    FILE* encrypted_file = fopen(encrypted_log_path, "rb");
    if (!encrypted_file) {
        log_message("Failed to open encrypted log file");
        return;
    }

    FILE* decrypted_file = fopen("decrypted_log.txt", "w");
    if (!decrypted_file) {
        fclose(encrypted_file);
        log_message("Failed to create decrypted log file");
        return;
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    unsigned char iv[IV_SIZE];
    unsigned char buffer[BUFFER_SIZE];
    unsigned char decrypted[BUFFER_SIZE];
    size_t bytes_read;
    int len, plaintext_len;

    // Read IV from beginning of file
    if (fread(iv, 1, IV_SIZE, encrypted_file) != IV_SIZE) {
        log_message("Failed to read IV from log file");
        goto cleanup;
    }

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) {
        log_message("Log decryption initialization failed");
        goto cleanup;
    }

    while ((bytes_read = fread(buffer, 1, BUFFER_SIZE, encrypted_file)) > 0) {
        if (EVP_DecryptUpdate(ctx, decrypted, &len, buffer, bytes_read) != 1) {
            log_message("Log decryption update failed");
            goto cleanup;
        }
        plaintext_len = len;
        
        if (EVP_DecryptFinal_ex(ctx, decrypted + len, &len) != 1) {
            log_message("Log decryption finalization failed");
            goto cleanup;
        }
        plaintext_len += len;
        
        fwrite(decrypted, 1, plaintext_len, decrypted_file);
    }

    log_message("Successfully decrypted log file to decrypted_log.txt");

cleanup:
    EVP_CIPHER_CTX_free(ctx);
    fclose(encrypted_file);
    fclose(decrypted_file);
}

// Verify message authenticity (HMAC)
int verify_message(SecureMessage *msg, const unsigned char *key) {
    // In a real system, implement HMAC verification here
    return 1; // Placeholder
}

// Generate random key
void generate_random_key(unsigned char *key, int size) {
    RAND_bytes(key, size);
}

