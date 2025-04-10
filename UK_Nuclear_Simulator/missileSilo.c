#include "common.h"
#include <sys/time.h>

// Add this near the top of missileSilo.c (after the includes)
#define SERVER_IP "127.0.0.1"  // Localhost IP

unsigned char silo_key[KEY_SIZE];

void launch_missile(const char *target) {
    printf("Launching missile at target: %s\n", target);
    // Actual launch implementation would go here
}

int main() {
    int sock;
    struct sockaddr_in server_addr;
    SecureMessage msg;
    
    init_crypto();
    
    // Create socket and connect
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Socket creation error");
        return -1;
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(CONTROL_PORT);
    inet_pton(AF_INET, SERVER_IP, &server_addr.sin_addr);

    if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Connection failed");
        return -1;
    }

    // Receive encryption key from control
    if(recv(sock, &msg, sizeof(msg), 0) <= 0) {
        perror("Key receive failed");
        return -1;
    }
    
    if(!verify_message(&msg, control_key) || !decrypt_message(&msg, control_key)) {
        printf("Key verification failed!\n");
        return -1;
    }
    
    memcpy(silo_key, msg.payload, KEY_SIZE);
    
    // Main loop
    while(1) {
        if(recv(sock, &msg, sizeof(msg), 0) > 0) {
            if(verify_message(&msg, silo_key) && decrypt_message(&msg, silo_key)) {
                if(msg.type == MSG_LAUNCH_ORDER) {
                    launch_missile(msg.payload);
                }
            }
        }
    }

    close(sock);
    return 0;
}

