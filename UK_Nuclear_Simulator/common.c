#include "common.h"
#include <stdarg.h>
#include <sys/time.h>
#include <ctype.h>

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
void log_message(const char *message, bool encrypt_logs) {
    pthread_mutex_lock(&log_mutex);
    
    FILE *log_file = fopen(LOG_FILE, "a");
    if (log_file) {
        time_t now = time(NULL);
        char *time_str = ctime(&now);
        time_str[strlen(time_str)-1] = '\0';
        
        if (encrypt_logs) {
            char encrypted[BUFFER_SIZE];
            strncpy(encrypted, message, BUFFER_SIZE-1);
            caesar_cipher(encrypted, 5, true);
            madryga_encrypt(encrypted, strlen(encrypted), LOG_ENCRYPTION_KEY, true);
            fprintf(log_file, "[%s] %s\n", time_str, encrypted);
        } else {
            fprintf(log_file, "[%s] %s\n", time_str, message);
        }
        fclose(log_file);
    }
    
    printf("[LOG] %s\n", message); // Always show plaintext in console
    pthread_mutex_unlock(&log_mutex);
}

// Update handle_error to match
void handle_error(const char *msg, bool fatal) {
    log_message(msg, false); // Don't encrypt error messages
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
    // Actual implementation would go here
    (void)msg;  // Mark parameters as used to silence warnings
    (void)key;
    return 1; // Placeholder - in real system verify HMAC
}

// Generate random key
void generate_random_key(unsigned char *key, int size) {
    RAND_bytes(key, size);
}

// Caesar cipher implementation
void caesar_cipher(char *text, int shift, bool encrypt) {
    if (!text) return;
    
    shift = shift % 26;
    if (!encrypt) {
        shift = -shift;
    }

    for (int i = 0; text[i] != '\0'; i++) {
        if (isalpha(text[i])) {
            char base = isupper(text[i]) ? 'A' : 'a';
            text[i] = ((text[i] - base + shift + 26) % 26) + base;
        }
    }
}

// Madryga encryption (simplified)
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

// Add this to the process_message function in control_center.c
void some_function() {
    switch(msg->type) {
        case MSG_DECRYPT_LOGS:
            decrypt_log_file(...);
            break;
        // ...
    }
}

// Function to decrypt log file
void decrypt_log_file(const char *filename, const char *key) {
    FILE *file = fopen(filename, "r");
    if (!file) {
        log_message("Failed to open log file", false);
        return;
    }

    char line[BUFFER_SIZE * 2];
    while (fgets(line, sizeof(line), file)) {
        char *msg_start = strchr(line, ']');
        if (msg_start && *(msg_start+1)) {
            *msg_start = '\0';  // Separate timestamp
            char message[BUFFER_SIZE];
            strncpy(message, msg_start+2, sizeof(message)-1);
            
            char *nl = strchr(message, '\n');
            if (nl) *nl = '\0';
            
            madryga_encrypt(message, strlen(message), key, false);
            caesar_cipher(message, 5, false);
            
            printf("%s] %s\n", line, message);
        }
    }
    fclose(file);
}

// Remove the problematic some_function() entirely

void handle_message(SecureMessage *msg) {
    if (!msg) return;

    switch(msg->type) {
        case MSG_DECRYPT_LOGS:
            decrypt_log_file(LOG_FILE, LOG_ENCRYPTION_KEY);
            break;
        // ... other cases ...

        case MSG_REGISTER:
        case MSG_INTEL:
        case MSG_LAUNCH_ORDER:
        case MSG_LAUNCH_CONFIRM:
        case MSG_STATUS:
        case MSG_ERROR:
        case MSG_TEST:
            // Handle other message types
            break;
            
        default:
            log_message("Unknown message type in handle_message", true);
            break;
    }
}