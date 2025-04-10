#include "common.h"
#include <sys/time.h>

static Target targets[MAX_TARGETS];
static int target_count = 0;
static bool test_mode = false;
static pthread_mutex_t target_mutex = PTHREAD_MUTEX_INITIALIZER;

void process_message(int client_socket, SecureMessage *msg) {
    char log_msg[BUFFER_SIZE];
    
    switch(msg->type) {
        case MSG_REGISTER:
            snprintf(log_msg, sizeof(log_msg), "%s registered with control", msg->sender);
            break;
        case MSG_INTEL:
            snprintf(log_msg, sizeof(log_msg), "INTEL RECEIVED from %s: %s", 
                     msg->sender, msg->payload);
            break;
        case MSG_LAUNCH_ORDER:
            snprintf(log_msg, sizeof(log_msg), "LAUNCH ORDER from %s: %s", 
                     msg->sender, msg->payload);
            // Add verification logic here
            break;
        case MSG_STATUS:
            snprintf(log_msg, sizeof(log_msg), "STATUS UPDATE from %s: %s", 
                     msg->sender, msg->payload);
            break;
        default:
            snprintf(log_msg, sizeof(log_msg), "UNKNOWN MESSAGE TYPE from %s", 
                     msg->sender);
    }
    
    log_message(log_msg);
}

void process_and_decrypt_message(int client_socket, SecureMessage *msg, const unsigned char *key) {
    if (!verify_message(msg, key)) {
        log_message("Verification failed!");
        return;
    }
    if (!decrypt_message(msg, key)) {
        log_message("Decryption failed!");
        return;
    }
    process_message(client_socket, msg);
}

void* handle_client(void *arg) {
    int client_socket = *((int*)arg);
    free(arg);
    SecureMessage msg;
    
    while (recv(client_socket, &msg, sizeof(msg), 0) > 0) {
        process_and_decrypt_message(client_socket, &msg, control_key);
    }
    close(client_socket);
    return NULL;
}

int main(int argc, char *argv[]) {
    // Initialize components
    init_crypto();
    generate_random_key(control_key, KEY_SIZE);
    
    // Create server socket
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in address = {
        .sin_family = AF_INET,
        .sin_addr.s_addr = INADDR_ANY,
        .sin_port = htons(CONTROL_PORT)
    };
    
    bind(server_fd, (struct sockaddr*)&address, sizeof(address));
    listen(server_fd, MAX_CLIENTS);
    
    log_message("Control Center started");
    
    while (1) {
        int new_socket = accept(server_fd, NULL, NULL);
        pthread_t thread_id;
        int *client_socket = malloc(sizeof(int));
        *client_socket = new_socket;
        pthread_create(&thread_id, NULL, handle_client, client_socket);
    }
    
    return 0;
}

void distribute_keys(int client_socket) {
    SecureMessage key_msg;
    memset(&key_msg, 0, sizeof(key_msg));
    
    key_msg.type = MSG_REGISTER;
    strcpy(key_msg.sender, "CONTROL");
    memcpy(key_msg.payload, control_key, KEY_SIZE);
    RAND_bytes(key_msg.iv, IV_SIZE);
    
    if(!encrypt_message(&key_msg, control_key)) {
        log_message("Failed to encrypt key message");
        return;
    }
    
    send(client_socket, &key_msg, sizeof(key_msg), 0);
}

