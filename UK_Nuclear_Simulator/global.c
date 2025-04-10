#include "common.h"

// Shared global variables
unsigned char control_key[KEY_SIZE];
pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;

