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
#include <sys/select.h>
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
#define ENCRYPT_LOGS 1
#define LOG_VERBOSITY 1  // 0=errors only, 1=normal, 2=debug

typedef enum {
    MSG_REGISTER,
    MSG_INTEL,
    MSG_LAUNCH_ORDER,
    MSG_LAUNCH_CONFIRM,
    MSG_STATUS,
    MSG_ERROR,
    MSG_TEST
} MessageType;

typedef struct {
    char name[50];
    double latitude;
    double longitude;
    int priority;
} Target;

typedef struct {
    MessageType type;
    char sender[20];
    char payload[BUFFER_SIZE - sizeof(MessageType) - sizeof(char[20])];
    unsigned char iv[IV_SIZE];
    unsigned char mac[EVP_MAX_MD_SIZE];
    int mac_len;
} SecureMessage;

// Global declarations
extern unsigned char control_key[KEY_SIZE];
extern pthread_mutex_t log_mutex;

// Function prototypes
void handle_error(const char *msg, bool fatal);
void init_crypto();
void cleanup_crypto();
int encrypt_message(SecureMessage *msg, const unsigned char *key);
int decrypt_message(SecureMessage *msg, const unsigned char *key);
int verify_message(SecureMessage *msg, const unsigned char *key);
void generate_random_key(unsigned char *key, int size);
void log_message(const char *message);
void process_and_decrypt_message(int client_socket, SecureMessage *msg, const unsigned char *key);

#endif

