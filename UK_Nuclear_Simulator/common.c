#include "common.h"

static pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;

void init_crypto(void) {
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
}

void cleanup_crypto(void) {
    EVP_cleanup();
    ERR_free_strings();
}

void log_message(const char *message, bool encrypt_logs) {
    if (!message) return;
    pthread_mutex_lock(&log_mutex);

    FILE *log_file = fopen(LOG_FILE, "a");
    if (log_file) {
        time_t now = time(NULL);
        char *time_str = ctime(&now);
        if (time_str) {
            time_str[strlen(time_str) - 1] = '\0';
        } else {
            time_str = "Unknown time";
        }

        if (encrypt_logs) {
            char encrypted[BUFFER_SIZE];
            strncpy(encrypted, message, BUFFER_SIZE - 1);
            encrypted[BUFFER_SIZE - 1] = '\0';
            caesar_cipher(encrypted, 5, true);
            madryga_encrypt(encrypted, strlen(encrypted), LOG_ENCRYPTION_KEY, true);
            fprintf(log_file, "[%s] %s\n", time_str, encrypted);
        } else {
            fprintf(log_file, "[%s] %s\n", time_str, message);
        }
        fclose(log_file);
    }

    printf("[LOG] %s\n", message);
    pthread_mutex_unlock(&log_mutex);
}

void handle_error(const char *msg, bool fatal) {
    log_message(msg, false);
    if (fatal) {
        exit(EXIT_FAILURE);
    }
}

int encrypt_message(SecureMessage *msg, const unsigned char *key) {
    if (!msg || !key) return 0;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return 0;

    RAND_bytes(msg->iv, IV_SIZE);

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, msg->iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }

    int len, ciphertext_len = 0;
    unsigned char plaintext[BUFFER_SIZE];
    int plaintext_len = strlen(msg->payload);
    if (plaintext_len >= BUFFER_SIZE) plaintext_len = BUFFER_SIZE - 1;
    memcpy(plaintext, msg->payload, plaintext_len);
    plaintext[plaintext_len] = '\0';

    if (EVP_EncryptUpdate(ctx, (unsigned char *)msg->payload, &len, plaintext, plaintext_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }
    ciphertext_len += len;

    if (EVP_EncryptFinal_ex(ctx, (unsigned char *)msg->payload + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }
    ciphertext_len += len;

    msg->payload[ciphertext_len] = '\0';
    EVP_CIPHER_CTX_free(ctx);
    return 1;
}

int decrypt_message(SecureMessage *msg, const unsigned char *key) {
    if (!msg || !key) return 0;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return 0;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, msg->iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }

    int len, plaintext_len = 0;
    unsigned char ciphertext[BUFFER_SIZE];
    int ciphertext_len = strlen(msg->payload);
    if (ciphertext_len >= BUFFER_SIZE) ciphertext_len = BUFFER_SIZE - 1;
    memcpy(ciphertext, msg->payload, ciphertext_len);
    ciphertext[ciphertext_len] = '\0';

    if (EVP_DecryptUpdate(ctx, (unsigned char *)msg->payload, &len, ciphertext, ciphertext_len) != 1) {
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

int verify_message(SecureMessage *msg, const unsigned char *key) {
    (void)msg;
    (void)key;
    return 1; // Placeholder
}

void generate_random_key(unsigned char *key, int size) {
    if (!key || size <= 0) return;
    RAND_bytes(key, size);
}

void caesar_cipher(char *text, int shift, bool encrypt) {
    if (!text) return;
    shift = shift % 26;
    if (!encrypt) shift = -shift;
    for (int i = 0; text[i] != '\0'; i++) {
        if (isalpha(text[i])) {
            char base = isupper(text[i]) ? 'A' : 'a';
            text[i] = ((text[i] - base + shift + 26) % 26) + base;
        }
    }
}

void madryga_encrypt(char *data, size_t len, const char *key, bool encrypt) {
    if (!data || !key || len == 0) return;
    size_t key_len = strlen(key);
    if (key_len == 0) return;
    for (size_t i = 0; i < len; i++) {
        data[i] = encrypt ? data[i] + (key[i % key_len] % 16)
                         : data[i] - (key[i % key_len] % 16);
    }
}

void decrypt_log_file(const char *filename, const char *key) {
    if (!filename || !key) return;
    FILE *file = fopen(filename, "r");
    if (!file) {
        log_message("Failed to open log file", false);
        return;
    }

    char line[BUFFER_SIZE * 2];
    while (fgets(line, sizeof(line), file)) {
        char *msg_start = strchr(line, ']');
        if (msg_start && *(msg_start + 1)) {
            *msg_start = '\0';
            char message[BUFFER_SIZE];
            strncpy(message, msg_start + 2, sizeof(message) - 1);
            message[sizeof(message) - 1] = '\0';
            char *nl = strchr(message, '\n');
            if (nl) *nl = '\0';
            madryga_encrypt(message, strlen(message), key, false);
            caesar_cipher(message, 5, false);
            printf("%s] %s\n", line, message);
        } else {
            printf("%s", line);
        }
    }
    fclose(file);
}

void handle_message(SecureMessage *msg) {
    if (!msg) return;
    switch (msg->type) {
        case MSG_DECRYPT_LOGS:
            decrypt_log_file(LOG_FILE, LOG_ENCRYPTION_KEY);
            break;
        case MSG_REGISTER:
        case MSG_INTEL:
        case MSG_LAUNCH_ORDER:
        case MSG_LAUNCH_CONFIRM:
        case MSG_STATUS:
        case MSG_ERROR:
        case MSG_TEST:
            break;
        default:
            log_message("Unknown message type in handle_message", true);
            break;
    }
}

