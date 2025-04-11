#include <stdio.h>
#include <string.h>
#include <stdbool.h>

#define BUFFER_SIZE 1024
#define LOG_ENCRYPTION_KEY "NuclearLogEncryptKey123"

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

int main() {
    char msg[BUFFER_SIZE];
    strncpy(msg, "Intel from SUBMARINE: No hostile contacts detected", sizeof(msg) - 1);
    msg[sizeof(msg) - 1] = '\0';
    printf("Original: %s\n", msg);

    // Encrypt
    caesar_cipher(msg, 5, true);
    madryga_encrypt(msg, strlen(msg), LOG_ENCRYPTION_KEY, true);
    printf("Encrypted: %s\n", msg);

    // Decrypt
    madryga_encrypt(msg, strlen(msg), LOG_ENCRYPTION_KEY, false);
    caesar_cipher(msg, 5, false);
    printf("Decrypted: %s\n", msg);

    return 0;
}

