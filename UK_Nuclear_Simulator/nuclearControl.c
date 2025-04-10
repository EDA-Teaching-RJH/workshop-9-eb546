#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#define PORT 8080
#define BUFFER_SIZE 1024

void handle_client(int client_socket) {
    char buffer[BUFFER_SIZE];
    int read_size;

    // Receive data from client
    while ((read_size = recv(client_socket, buffer, BUFFER_SIZE, 0)) > 0) {
        buffer[read_size] = '\0'; // Null-terminate the received string
        printf("Received: %s\n", buffer);

        // Process command and respond
        // Here you would implement logic to verify and respond to commands
        // For simplicity, we just echo back
        send(client_socket, buffer, strlen(buffer), 0);
    }

    if (read_size == 0) {
        printf("Client disconnected\n");
    } else {
        perror("recv failed");
    }

    close(client_socket);
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
    
    // Rest of your processing logic...
    process_message(client_socket, msg);
}