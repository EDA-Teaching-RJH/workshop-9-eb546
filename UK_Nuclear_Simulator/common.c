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

// Log messages to file and stdout
void log_message(const char *message) {
    pthread_mutex_lock(&log_mutex);
    
    FILE *log_file = fopen(LOG_FILE, "a");
    if (log_file) {
        time_t now = time(NULL);
        char *time_str = ctime(&now);
        time_str[strlen(time_str)-1] = '\0'; // Remove newline
        
        fprintf(log_file, "[%s] %s\n", time_str, message);
        fclose(log_file);
    }
    
    printf("[LOG] %s\n", message);
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

// Decrypt a message
int decrypt_message(SecureMessage *msg, const unsigned char *key) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return 0;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, msg->iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }

    int len;
    int plaintext_len = 0;

    if (EVP_DecryptUpdate(ctx, (unsigned char *)msg->payload, &len, 
                         (unsigned char *)msg->payload, strlen(msg->payload)) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }
    plaintext_len += len;

    if (EVP_DecryptFinal_ex(ctx, (unsigned char *)msg->payload + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }
    plaintext_len += len;

    msg->payload[plaintext_len] = '\0';
    EVP_CIPHER_CTX_free(ctx);
    return 1;
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

// Add these new functions to common.c (or create a new file for encryption utilities)

// Caesar cipher encryption/decryption
void caesar_cipher(char *text, int shift, bool encrypt) {
    if (!text) return;
    
    shift = shift % 26; // Ensure shift is within alphabet range
    if (!encrypt) {
        shift = -shift; // Reverse for decryption
    }

    for (int i = 0; text[i] != '\0'; i++) {
        if (isalpha(text[i])) {
            char base = isupper(text[i]) ? 'A' : 'a';
            text[i] = ((text[i] - base + shift + 26)) % 26 + base;
        }
    }
}

// Madryga encryption (simplified version)
void madryga_encrypt(char *data, size_t len, const char *key, bool encrypt) {
    if (!data || !key || len == 0) return;
    
    size_t key_len = strlen(key);
    if (key_len == 0) return;
    
    for (size_t i = 0; i < len; i++) {
        if (encrypt) {
            data[i] = data[i] + (key[i % key_len] % 16);
        } else {
            data[i] = data[i] - (key[i % key_len] % 16);
        }
    }
}

// Modified log_message function with encryption options
void log_message(const char *message, bool encrypt_logs, const char *encryption_key) {
    pthread_mutex_lock(&log_mutex);
    
    // Create a copy of the message we can modify
    char log_buffer[BUFFER_SIZE];
    strncpy(log_buffer, message, sizeof(log_buffer) - 1);
    log_buffer[sizeof(log_buffer) - 1] = '\0';
    
    if (encrypt_logs && encryption_key) {
        // Apply both encryption methods (in real use, choose one)
        caesar_cipher(log_buffer, 5, true); // Caesar shift of 5
        madryga_encrypt(log_buffer, strlen(log_buffer), encryption_key, true);
    }
    
    FILE *log_file = fopen(LOG_FILE, "a");
    if (log_file) {
        time_t now = time(NULL);
        char *time_str = ctime(&now);
        time_str[strlen(time_str)-1] = '\0'; // Remove newline
        
        fprintf(log_file, "[%s] %s\n", time_str, log_buffer);
        fclose(log_file);
    }
    
    // For stdout, show the original message
    printf("[LOG] %s\n", message);
    pthread_mutex_unlock(&log_mutex);
}

// Function to decrypt log file
void decrypt_log_file(const char *filename, const char *encryption_key) {
    FILE *file = fopen(filename, "r");
    if (!file) {
        printf("Failed to open log file\n");
        return;
    }
    
    printf("\nDecrypted Log Contents:\n");
    printf("----------------------\n");
    
    char line[BUFFER_SIZE];
    while (fgets(line, sizeof(line), file)) {
        // Find where the actual message starts (after timestamp)
        char *message = strchr(line, ']');
        if (message && *(message + 1)) {
            message += 2; // Skip "] "
            
            // Create a copy we can modify
            char decrypted[BUFFER_SIZE];
            strncpy(decrypted, message, sizeof(decrypted) - 1);
            decrypted[sizeof(decrypted) - 1] = '\0';
            
            // Remove newline if present
            char *newline = strchr(decrypted, '\n');
            if (newline) *newline = '\0';
            
            // Apply decryption (reverse order of encryption)
            madryga_encrypt(decrypted, strlen(decrypted), encryption_key, false);
            caesar_cipher(decrypted, 5, false); // Reverse Caesar shift of 5
            
            // Print timestamp with decrypted message
            *message = '\0'; // Truncate original line at the message start
            printf("%s] %s\n", line, decrypted);
        } else {
            printf("%s", line); // Print line as-is if we can't parse it
        }
    }
    
    fclose(file);
    printf("----------------------\n");
}

