#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdbool.h>

#define BUFFER_SIZE 1024
#define LOG_FILE "nuclear_log.txt"
#define LOG_ENCRYPTION_KEY "NuclearLogEncryptKey123"

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

    const int min_ascii = 32;  // Space
    const int max_ascii = 126; // Tilde
    const int range = max_ascii - min_ascii + 1; // 95

    for (size_t i = 0; i < len; i++) {
        // Map character to 0-94 range
        int val = data[i] - min_ascii;
        if (val < 0 || val >= range) continue; // Skip if not in printable range

        // Compute shift based on key
        int shift = key[i % key_len] % 16;
        if (!encrypt) shift = -shift;

        // Apply shift and wrap around within printable range
        val = (val + shift + range) % range;
        data[i] = (char)(val + min_ascii);
    }
}

void decrypt_log_file(const char *filename, const char *key) {
    if (!filename || !key) return;
    FILE *file = fopen(filename, "r");
    if (!file) {
        fprintf(stderr, "Failed to open log file: %s\n", filename);
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

