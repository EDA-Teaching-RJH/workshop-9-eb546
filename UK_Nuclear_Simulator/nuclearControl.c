#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#define PORT 8080
#define BUFFER_SIZE 1024

// In nuclearControl.c
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

int main() {
    int server_fd, client_socket;
    struct sockaddr_in server_addr, client_addr;
    socklen_t addr_len = sizeof(client_addr);

    // Create socket
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("Socket failed");
        exit(EXIT_FAILURE);
    }

    // Bind socket
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);

    if (bind(server_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Bind failed");
        exit(EXIT_FAILURE);
    }

    // Listen for incoming connections
    if (listen(server_fd, 3) < 0) {
        perror("Listen failed");
        exit(EXIT_FAILURE);
    }

    printf("Waiting for connections...\n");

    // Accept incoming connections
    while ((client_socket = accept(server_fd, (struct sockaddr *)&client_addr, &addr_len)) >= 0) {
        printf("Connection accepted\n");
        handle_client(client_socket);
    }

    if (client_socket < 0) {
        perror("Accept failed");
    }

    close(server_fd);
    return 0;
}

// Updated function in nuclearControl.c
void process_and_decrypt_message(int client_socket, SecureMessage *msg, unsigned char *key) {
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