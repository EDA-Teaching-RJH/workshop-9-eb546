#include "common.h"
#include <stdarg.h>
#include <sys/time.h>

// Global variables specific to nuclearControl
static Target targets[MAX_TARGETS];
static int target_count = 0;
static bool test_mode = false;
static pthread_mutex_t target_mutex = PTHREAD_MUTEX_INITIALIZER;

// Function implementations...

void *handle_client(void *arg) {
    int client_socket = *((int *)arg);
    free(arg);
    
    SecureMessage msg;
    int bytes_received;
    
    while ((bytes_received = recv(client_socket, &msg, sizeof(msg), 0)) > 0) {
        if (bytes_received != sizeof(msg)) {
            log_message("Received incomplete message");
            continue;
        }
        
        process_and_decrypt_message(client_socket, &msg, control_key);
    }
    
    close(client_socket);
    return NULL;
}

void process_and_decrypt_message(int client_socket, SecureMessage *msg, const unsigned char *key) {
    char log_msg[BUFFER_SIZE * 2];
    
    if (!verify_message(msg, key)) {
        log_message("Message verification failed - possible security breach!");
        return;
    }
    
    if (!decrypt_message(msg, key)) {
        log_message("Failed to decrypt message");
        return;
    }
    
    snprintf(log_msg, sizeof(log_msg), "Decrypted message from %s: %s", 
             msg->sender, msg->payload);
    log_message(log_msg);
    
    process_message(client_socket, msg);
}

// Rest of nuclearControl.c implementations...

