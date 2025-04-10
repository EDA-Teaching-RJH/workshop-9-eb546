#include "common.h"
#include <stdarg.h>
#include <sys/time.h>

// Global definitions
unsigned char control_key[KEY_SIZE];
pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;

void init_crypto() {
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
}

void cleanup_crypto() {
    EVP_cleanup();
    ERR_free_strings();
}

// [Implement all other functions from previous examples...]
// Make sure all functions are properly defined here

