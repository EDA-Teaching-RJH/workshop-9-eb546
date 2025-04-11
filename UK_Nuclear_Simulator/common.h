#ifndef COMMON_H
#define COMMON_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/select.h>  // Added for fd_set and timeval
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <pthread.h>

#define CONTROL_PORT 8080
#define MAX_CLIENTS 10
#define BUFFER_SIZE 1024
#define KEY_SIZE 32
#define IV_SIZE 16
#define MAX_TARGETS 100
#define LOG_FILE "nuclear_log.txt"

// Message types
typedef enum {
    MSG_REGISTER = 0,
    MSG_INTEL,
    MSG_LAUNCH_ORDER, 
    MSG_LAUNCH_CONFIRM,
    MSG_STATUS,
    MSG_ERROR,
    MSG_TEST,
    MSG_DECRYPT_LOGS  // Unique value
} MessageType;

// Intel categories
typedef enum {
    INTEL_RADAR,
    INTEL_SATELLITE,
    INTEL_SUBMARINE
} IntelType;

// Target information
typedef struct {
    char name[50];
    double latitude;
    double longitude;
    int priority;
} Target;

// Message structure
typedef struct {
    MessageType type;
    char sender[20];
    char payload[BUFFER_SIZE - sizeof(MessageType) - sizeof(char[20])];
    unsigned char iv[IV_SIZE];
    unsigned char mac[EVP_MAX_MD_SIZE];
    int mac_len;
} SecureMessage;

// Function prototypes
void handle_error(const char *msg, bool fatal);
void init_crypto();
void cleanup_crypto();
int encrypt_message(SecureMessage *msg, const unsigned char *key);
int decrypt_message(SecureMessage *msg, const unsigned char *key);
int verify_message(SecureMessage *msg, const unsigned char *key);
void generate_random_key(unsigned char *key, int size);
void log_message(const char *message, bool encrypt_logs);
void print_hex(const char *label, const unsigned char *data, int len);
// Add these new function prototypes
void caesar_cipher(char *text, int shift, bool encrypt);
void madryga_encrypt(char *data, size_t len, const char *key, bool encrypt);
void decrypt_log_file(const char *filename, const char *encryption_key);

// Add log encryption key
#define LOG_ENCRYPTION_KEY "NuclearLogEncryptKey123"

#endif // COMMON_H

