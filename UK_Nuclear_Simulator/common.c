#include "common.h"

static pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;

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

int encrypt_message(SecureMessage *msg, const uint8_t *key) {
    if (!msg || !key) return 0;
    // Use the first byte of the key as the shift value (1-255)
    int shift = key[0] % 95 + 1; // Ensure shift is between 1 and 95
    caesar_cipher(msg->payload, shift, true);
    return 1;
}

int decrypt_message(SecureMessage *msg, const uint8_t *key) {
    if (!msg || !key) return 0;
    // Use the same shift value as in encrypt_message
    int shift = key[0] % 95 + 1;
    caesar_cipher(msg->payload, shift, false);
    return 1;
}

int verify_message(SecureMessage *msg, const uint8_t *key) {
    (void)msg;
    (void)key;
    return 1; // Placeholder, no verification needed with Caesar cipher
}

void generate_random_key(uint8_t *key, int size) {
    if (!key || size <= 0) return;
    // Simple pseudo-random key generation using time and a loop
    srand((unsigned int)time(NULL));
    for (int i = 0; i < size; i++) {
        key[i] = (uint8_t)(rand() % 256);
    }
}

void caesar_cipher(char *text, int shift, bool encrypt) {
    if (!text) return;
    shift = shift % 95;
    if (!encrypt) shift = -shift;
    for (int i = 0; text[i] != '\0'; i++) {
        if (text[i] >= 32 && text[i] <= 126) {
            int val = text[i] - 32;
            val = (val + shift + 95) % 95;
            text[i] = (char)(val + 32);
        }
    }
}

void madryga_encrypt(char *data, size_t len, const char *key, bool encrypt) {
    if (!data || !key || len == 0) return;
    size_t key_len = strlen(key);
    if (key_len == 0) return;
    for (size_t i = 0; i < len; i++) {
        unsigned char val = (unsigned char)data[i];
        int shift = (key[i % key_len] % 16) + 1;
        if (!encrypt) shift = -shift;
        val = (val + shift + 256) % 256;
        data[i] = (char)val;
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
