#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <pthread.h>
#include <openssl/aes.h>
#include <time.h>

// Constants
#define PORT 8080
#define MAX_CLIENTS 4
#define BUFFER_SIZE 1024
#define KEY "0123456789abcdef0123456789abcdef" // 32-byte AES-256 key
#define LOG_FILE "nuclearControl.log"
#define LOG_FILES {"nuclearControl.log", "missileSilo.log", "submarine.log", "radar.log", "satellite.log"}
#define NUM_LOG_FILES 5

// Structure for client info
typedef struct {
    int sockfd;
    char *type;
} Client;

// Global variables
Client clients[MAX_CLIENTS] = {0};
int client_count = 0;
pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
FILE *log_fp = NULL;
char last_threat[BUFFER_SIZE] = {0};

// Encrypt message using AES-256
void encrypt_message(const char *input, char *output, int *out_len) {
    AES_KEY enc_key;
    AES_set_encrypt_key((unsigned char *)KEY, 256, &enc_key);
    int len = strlen(input) + 1;
    int pad_len = (len / 16 + 1) * 16;
    unsigned char *padded = calloc(pad_len, 1);
    strcpy((char *)padded, input);
    for (int i = 0; i < pad_len; i += 16) {
        AES_encrypt(padded + i, (unsigned char *)output + i, &enc_key);
    }
    *out_len = pad_len;
    free(padded);
}

// Decrypt message using AES-256
void decrypt_message(const char *input, int in_len, char *output) {
    AES_KEY dec_key;
    AES_set_decrypt_key((unsigned char *)KEY, 256, &dec_key);
    for (int i = 0; i < in_len; i += 16) {
        AES_decrypt((unsigned char *)input + i, (unsigned char *)output + i, &dec_key);
    }
}

// Log message to file
void log_message(const char *msg) {
    time_t now = time(NULL);
    char *time_str = ctime(&now);
    time_str[strlen(time_str) - 1] = '\0';
    fprintf(log_fp, "[%s] %s\n", time_str, msg);
    fflush(log_fp);
}

// Clear all log files
void clear_all_logs() {
    const char *log_files[] = LOG_FILES;
    int success = 1;
    printf("\n┌──────────────────────────────┐\n");
    printf("│ Clearing All System Logs     │\n");
    printf("└──────────────────────────────┘\n");

    for (int i = 0; i < NUM_LOG_FILES; i++) {
        FILE *fp = fopen(log_files[i], "w");
        if (!fp) {
            printf("│ ERROR: Failed to clear %s\n", log_files[i]);
            success = 0;
            continue;
        }
        fclose(fp);
        printf("│ SUCCESS: Cleared %s\n", log_files[i]);
    }

    if (success) {
        printf("└── All logs cleared successfully\n\n");
        // Reopen nuclearControl.log for logging
        log_fp = fopen(LOG_FILE, "a");
        if (!log_fp) {
            printf("\nCRITICAL ERROR: Failed to reopen %s\n\n", LOG_FILE);
            exit(1);
        }
        log_message("All system logs cleared");
    } else {
        printf("└── Partial failure in clearing logs\n\n");
        // Reopen nuclearControl.log if not already open
        if (!log_fp) {
            log_fp = fopen(LOG_FILE, "a");
            if (!log_fp) {
                printf("\nCRITICAL ERROR: Failed to reopen %s\n\n", LOG_FILE);
                exit(1);
            }
        }
        log_message("Partial failure in clearing all system logs");
    }
}

// Handle client communication
void *handle_client(void *arg) {
    int sockfd = *(int *)arg;
    char buffer[BUFFER_SIZE];
    free(arg);

    while (1) {
        memset(buffer, 0, BUFFER_SIZE);
        int n = read(sockfd, buffer, BUFFER_SIZE - 1);
        if (n <= 0) {
            log_message("Client disconnected");
            break;
        }

        buffer[n] = '\0';
        char log_msg[BUFFER_SIZE];
        snprintf(log_msg, BUFFER_SIZE, "Received: %s", buffer);
        log_message(log_msg);

        // Store threat for menu
        if (strstr(buffer, "THREAT")) {
            strncpy(last_threat, buffer, BUFFER_SIZE - 1);
        }
    }

    // Cleanup
    pthread_mutex_lock(&mutex);
    for (int i = 0; i < client_count; i++) {
        if (clients[i].sockfd == sockfd) {
            close(clients[i].sockfd);
            free(clients[i].type);
            clients[i] = clients[client_count - 1];
            client_count--;
            break;
        }
    }
    pthread_mutex_unlock(&mutex);
    return NULL;
}

// Menu system for user interaction
void *menu_system(void *arg) {
    char input[10];
    while (1) {
        printf("\n┌───────────────────────────────────────────┐\n");
        printf("│     Nuclear Command and Control System    │\n");
        printf("├───────────────────────────────────────────┤\n");
        printf("│ 1. Review and Decrypt System Logs         │\n");
        printf("│ 2. Authorize Launch Based on Threat       │\n");
        printf("│ 3. Purge All System Logs                  │\n");
        printf("│ 4. Terminate Command Interface            │\n");
        printf("└───────────────────────────────────────────┘\n");
        printf("Enter Selection: ");
        if (!fgets(input, sizeof(input), stdin)) continue;

        int choice = atoi(input);
        printf("\n");
        switch (choice) {
            case 1: {
                FILE *temp_fp = fopen(LOG_FILE, "r");
                if (!temp_fp) {
                    printf("┌──────────────────────────────┐\n");
                    printf("│ ERROR: Unable to access %s\n", LOG_FILE);
                    printf("└──────────────────────────────┘\n\n");
                    break;
                }
                printf("┌──────────────────────────────┐\n");
                printf("│       System Log Entries     │\n");
                printf("├──────────────────────────────┤\n");
                char line[BUFFER_SIZE];
                while (fgets(line, BUFFER_SIZE, temp_fp)) {
                    if (strstr(line, "Sent encrypted launch command")) {
                        printf("│ [DECRYPTED] %s", line);
                    } else {
                        printf("│ %s", line);
                    }
                }
                printf("└──────────────────────────────┘\n\n");
                fclose(temp_fp);
                break;
            }
            case 2: {
                if (strlen(last_threat) == 0) {
                    printf("┌──────────────────────────────┐\n");
                    printf("│ STATUS: No threats detected  │\n");
                    printf("└──────────────────────────────┘\n\n");
                    break;
                }
                printf("┌──────────────────────────────┐\n");
                printf("│ Latest Threat Intelligence   │\n");
                printf("├──────────────────────────────┤\n");
                printf("│ %s\n", last_threat);
                printf("└──────────────────────────────┘\n");
                printf("\n┌──────────────────────────────┐\n");
                printf("│ Select Strategic Asset       │\n");
                printf("├──────────────────────────────┤\n");
                printf("│ 1. Missile Silo              │\n");
                printf("│ 2. Submarine                 │\n");
                printf("│ 3. Cancel Operation          │\n");
                printf("└──────────────────────────────┘\n");
                printf("Enter Selection: ");
                if (!fgets(input, sizeof(input), stdin)) continue;

                int asset = atoi(input);
                if (asset == 3) {
                    printf("┌──────────────────────────────┐\n");
                    printf("│ OPERATION: Launch aborted    │\n");
                    printf("└──────────────────────────────┘\n\n");
                    break;
                }

                char launch_cmd[BUFFER_SIZE];
                if (asset == 1 && strstr(last_threat, "AIR")) {
                    snprintf(launch_cmd, BUFFER_SIZE, "LAUNCH:TARGET_AIR");
                } else if (asset == 2 && (strstr(last_threat, "SEA") || strstr(last_threat, "SPACE"))) {
                    snprintf(launch_cmd, BUFFER_SIZE, "LAUNCH ---> TARGET_SEA_SPACE");
                } else {
                    printf("┌──────────────────────────────┐\n");
                    printf("│ ERROR: Asset mismatch for threat\n");
                    printf("└──────────────────────────────┘\n\n");
                    break;
                }

                char encrypted[BUFFER_SIZE];
                int enc_len;
                encrypt_message(launch_cmd, encrypted, &enc_len);

                pthread_mutex_lock(&mutex);
                for (int i = 0; i < client_count; i++) {
                    if ((asset == 1 && strstr(clients[i].type, "silo")) ||
                        (asset == 2 && strstr(clients[i].type, "submarine"))) {
                        write(clients[i].sockfd, encrypted, enc_len);
                        char log_msg[BUFFER_SIZE];
                        snprintf(log_msg, BUFFER_SIZE, "Sent encrypted launch command to %s", clients[i].type);
                        log_message(log_msg);
                        printf("┌──────────────────────────────┐\n");
                        printf("│ SUCCESS: Command issued to %s\n", clients[i].type);
                        printf("└──────────────────────────────┘\n\n");
                    }
                }
                pthread_mutex_unlock(&mutex);
                break;
            }
            case 3:
                clear_all_logs();
                break;
            case 4:
                printf("┌──────────────────────────────┐\n");
                printf("│ SYSTEM: Interface terminated │\n");
                printf("└──────────────────────────────┘\n\n");
                return NULL;
            default:
                printf("┌──────────────────────────────┐\n");
                printf("│ ERROR: Invalid selection     │\n");
                printf("└──────────────────────────────┘\n\n");
        }
    }
    return NULL;
}

int main(int argc, char *argv[]) {
    int test_mode = 0;
    if (argc > 1 && strcmp(argv[1], "--test") == 0) {
        test_mode = 1;
        printf("\n┌──────────────────────────────┐\n");
        printf("│ SYSTEM: Initiated in test mode\n");
        printf("└──────────────────────────────┘\n\n");
    }

    // Initialize logging
    log_fp = fopen(LOG_FILE, "a");
    if (!log_fp) {
        printf("\n┌──────────────────────────────┐\n");
        printf("│ CRITICAL ERROR: Failed to initialize logging\n");
        printf("└──────────────────────────────┘\n\n");
        exit(1);
    }
    chmod(LOG_FILE, 0600);

    // Initialize random seed
    srand(time(NULL));

    // Setup server socket
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        printf("\n┌──────────────────────────────┐\n");
        printf("│ CRITICAL ERROR: Socket creation failed\n");
        printf("└──────────────────────────────┘\n\n");
        exit(1);
    }

    struct sockaddr_in server_addr = {0};
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);

    if (bind(server_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        printf("\n┌──────────────────────────────┐\n");
        printf("│ CRITICAL ERROR: Socket binding failed\n");
        printf("└──────────────────────────────┘\n\n");
        close(server_fd);
        exit(1);
    }

    if (listen(server_fd, 10) < 0) {
        printf("\n┌──────────────────────────────┐\n");
        printf("│ CRITICAL ERROR: Socket listening failed\n");
        printf("└──────────────────────────────┘\n\n");
        close(server_fd);
        exit(1);
    }

    log_message("Command system operational");
    printf("\n┌──────────────────────────────┐\n");
    printf("│ SYSTEM: Command system online at port %d\n", PORT);
    printf("└──────────────────────────────┘\n\n");

    // Start menu system
    pthread_t menu_thread;
    if (pthread_create(&menu_thread, NULL, menu_system, NULL) != 0) {
        printf("\n┌──────────────────────────────┐\n");
        printf("│ CRITICAL ERROR: Interface thread failed\n");
        printf("└──────────────────────────────┘\n\n");
        close(server_fd);
        exit(1);
    }
    pthread_detach(menu_thread);

    // Test mode: Simulate threat
    if (test_mode) {
        sleep(3);
        char threat[BUFFER_SIZE];
        int type = rand() % 2;
        if (type == 0) {
            snprintf(threat, BUFFER_SIZE, "THREAT ---> AIR ---> ENEMY_AIRCRAFT: Coordinate: 51.5074,-0.1278");
        } else {
            snprintf(threat, BUFFER_SIZE, "THREAT ---> SEA ---> ENEMY_SUB: Coordinate: 48.8566,2.3522");
        }
        char log_msg[BUFFER_SIZE];
        snprintf(log_msg, BUFFER_SIZE, "Test mode: Simulating %s", threat);
        log_message(log_msg);
        printf("\n┌──────────────────────────────┐\n");
        printf("│ TEST MODE: Simulated threat  │\n");
        printf("├──────────────────────────────┤\n");
        printf("│ %s\n", threat);
        printf("└──────────────────────────────┘\n\n");

        strncpy(last_threat, threat, BUFFER_SIZE - 1);
    }

    // Accept clients
    while (1) {
        struct sockaddr_in client_addr;
        socklen_t addr_len = sizeof(client_addr);
        int *client_fd = malloc(sizeof(int));
        *client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &addr_len);
        if (*client_fd < 0) {
            printf("\n┌──────────────────────────────┐\n");
            printf("│ ERROR: Client connection failed\n");
            printf("└──────────────────────────────┘\n\n");
            free(client_fd);
            continue;
        }

        // Receive client type
        char buffer[BUFFER_SIZE] = {0};
        read(*client_fd, buffer, BUFFER_SIZE - 1);
        log_message(buffer);
        printf("\n┌──────────────────────────────┐\n");
        printf("│ SYSTEM: New asset connected  │\n");
        printf("├──────────────────────────────┤\n");
        printf("│ Type: %s\n", buffer);
        printf("└──────────────────────────────┘\n\n");

        pthread_mutex_lock(&mutex);
        if (client_count < MAX_CLIENTS) {
            clients[client_count].sockfd = *client_fd;
            clients[client_count].type = strdup(buffer);
            client_count++;
        } else {
            log_message("Maximum assets reached");
            printf("\n┌──────────────────────────────┐\n");
            printf("│ WARNING: Maximum assets reached\n");
            printf("└──────────────────────────────┘\n\n");
            close(*client_fd);
            free(client_fd);
            pthread_mutex_unlock(&mutex);
            continue;
        }
        pthread_mutex_unlock(&mutex);

        // Start client thread
        pthread_t thread;
        if (pthread_create(&thread, NULL, handle_client, client_fd) != 0) {
            printf("\n┌──────────────────────────────┐\n");
            printf("│ ERROR: Asset thread creation failed\n");
            printf("└──────────────────────────────┘\n\n");
            close(*client_fd);
            free(client_fd);
        }
        pthread_detach(thread);
    }

    // Cleanup
    fclose(log_fp);
    close(server_fd);
    return 0;
}

