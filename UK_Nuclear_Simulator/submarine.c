#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/aes.h>
#include <time.h>

#define SERVER_IP "127.0.0.1"
#define PORT 8080
#define BUFFER_SIZE 1024
#define KEY "0123456789abcdef0123456789abcdef"
#define LOG_FILE "submarine.log"

// Decrypt message
void decrypt_message(const char *input, int in_len, char *output) {
    AES_KEY dec_key;
    AES_set_decrypt_key((unsigned char *)KEY, 256, &dec_key);
    for (int i = 0; i < in_len; i += 16) {
        AES_decrypt((unsigned char *)input + i, (unsigned char *)output + i, &dec_key);
    }
}

// Log message
void log_message(FILE *fp, const char *msg) {
    time_t now = time(NULL);
    char *time_str = ctime(&now);
    time_str[strlen(time_str) - 1] = '\0';
    fprintf(fp, "[%s] %s\n", time_str, msg);
    fflush(fp);
}

int main() {
    // Initialize logging
    FILE *log_fp = fopen(LOG_FILE, "a");
    if (!log_fp) {
        printf("\n┌────────────────────────────────────────────┐\n");
        printf("│  CRITICAL ERROR: FAILED TO INITALIZE LOGGIN\n");
        printf("└──────────────────────────────────────────────┘\n\n");
        exit(1);
    }
    chmod(LOG_FILE, 0600);

    // Setup socket
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        printf("\n┌──────────────────────────────────────┐\n");
        printf("│  CRITICAL ERROR: SOCKET CREATION FAILED\n");
        printf("└────────────────────────────────────────┘\n\n");
        exit(1);
    }

    struct sockaddr_in server_addr = {0};
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);
    inet_pton(AF_INET, SERVER_IP, &server_addr.sin_addr);

    if (connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        printf("\n┌───────────────────────────────────────────────────┐\n");
        printf("│  CRITICAL ERROR: CONNECTION TO COMMAND SYSTEM FAILED\n");
        printf("└─────────────────────────────────────────────────────┘\n\n");
        close(sockfd);
        exit(1);
    }

    // Send client type
    char *type = "submarine";
    write(sockfd, type, strlen(type));
    log_message(log_fp, "Connected to command system");
    printf("\n┌─────────────────────────┐\n");
    printf("│  SYSTEM: SUBMARINE ONLINE │\n");
    printf("└───────────────────────────┘\n\n");

    // Simulate sending intelligence
    srand(time(NULL));
    char buffer[BUFFER_SIZE];
    while (1) {
        // Randomly send intelligence
        if (rand() % 10 < 2) {
            char intel[] = "SEA ---> ENEMY_SUB ---> Coordinates: 48.8566,2.3522";
            write(sockfd, intel, strlen(intel));
            log_message(log_fp, "Transmitted Intelligence: Sea-Based Threat");
            printf("\n┌─────────────────────────────┐\n");
            printf("│  INTEL TRANSMITTED: SEA THREAT\n");
            printf("├───────────────────────────────┤\n");
            printf("│ %s\n", intel);
            printf("└───────────────────────────────┘\n\n");
        }

        // Listen for commands
        memset(buffer, 0, BUFFER_SIZE);
        int n = read(sockfd, buffer, BUFFER_SIZE);
        if (n <= 0) {
            log_message(log_fp, "Disconnected from command system");
            printf("\n┌────────────────────────────────────────┐\n");
            printf("│  SYSTEM: DISCONNECTED FROM COMMAND SYSTEM\n");
            printf("└──────────────────────────────────────────┘\n");
            break;
        }

        // Decrypt message
        char decrypted[BUFFER_SIZE] = {0};
        decrypt_message(buffer, n, decrypted);
        char log_msg[BUFFER_SIZE];
        snprintf(log_msg, BUFFER_SIZE, "Received: %s", decrypted);
        log_message(log_fp, log_msg);
        printf("\n┌───────────────────────────────────┐\n");
        printf("│  COMMAND RECEIVED: %s\n", decrypted);
        printf("└─────────────────────────────────────┘\n");

        // Process launch command
        if (strstr(decrypted, "LAUNCH ---> TARGET_ENEMY_SUBMARINE")) {
            log_message(log_fp, "Launch command verified for sea target. Initiating sequence...");
            printf("\n┌──────────────────────────────┐\n");
            printf("│  STRATEGIC LAUNCH SEQUENCE     │\n");
            printf("├────────────────────────────────┤\n");
            printf("│  TARGET: SEA THREAT            │\n");
            printf("└────────────────────────────────┘\n");
            for (int i = 15; i >= 0; i--) {
                snprintf(log_msg, BUFFER_SIZE, "Launch in T-%d seconds", i);
                log_message(log_fp, log_msg);
                printf("│ T-%02d seconds to launch\n", i);
                sleep(1);
            }
            log_message(log_fp, "Missile deployed to sea target");
            printf("┌──────────────────────────────┐\n");
            printf("│ SUCCESS: MISSILE DEPLOYED    │\n");
            printf("└──────────────────────────────┘\n\n");
        }

        sleep(5);
    }

    // Cleanup
    fclose(log_fp);
    close(sockfd);
    return 0;
}

