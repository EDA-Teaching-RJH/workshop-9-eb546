#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#define BUFFER_SIZE 1024
#define LOG_FILE "nuclear_log.txt"
#define LOG_ENCRYPTION_KEY "NuclearLogEncryptKey123"

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

// Madryga encryption/decryption (simplified)
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

// Function to decrypt log file
void decrypt_log_file(const char *filename, const char *key) {
    FILE *file = fopen(filename, "r");
    if (!file) {
        fprintf(stderr, "Failed to open log file: %s\n", filename);
        return;
    }

    char line[BUFFER_SIZE * 2];
    while (fgets(line, sizeof(line), file)) {
        char *msg_start = strchr(line, ']');
        if (msg_start && *(msg_start + 1)) {
            *msg_start = '\0'; // Separate timestamp
            char message[BUFFER_SIZE];
            strncpy(message, msg_start + 2, sizeof(message) - 1);
            message[sizeof(message) - 1] = '\0';
            
            char *nl = strchr(message, '\n');
            if (nl) *nl = '\0';
            
            // Decrypt: Reverse Madryga first, then Caesar
            madryga_encrypt(message, strlen(message), key, false);
            caesar_cipher(message, 5, false);
            
            printf("%s] %s\n", line, message);
        } else {
            // Print lines that don't match expected format (e.g., errors)
            printf("%s", line);
        }
    }
    fclose(file);
}

int main(int argc, char *argv[]) {
    if (argc > 1 && strcmp(argv[1], "--help") == 0) {
        printf("Usage: %s [log_file]\n", argv[0]);
        printf("Decrypts nuclear simulator log file. Default: %s\n", LOG_FILE);
        return 0;
    }

    const char *filename = (argc > 1) ? argv[1] : LOG_FILE;
    decrypt_log_file(filename, LOG_ENCRYPTION_KEY);
    return 0;
}
