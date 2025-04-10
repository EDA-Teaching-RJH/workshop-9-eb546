#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <stdbool.h>
#include <signal.h>
#include <errno.h>
#include <sys/select.h>

#include "common.h"
#include "utils.h"

#define MY_ID ID_SUB "_Vanguard" // Unique ID for this sub instance
#define INTEL_UPDATE_INTERVAL 15  // Seconds
#define STATUS_UPDATE_INTERVAL 60 // Seconds
#define RETRY_INTERVAL 5 // Seconds

volatile sig_atomic_t keep_running = 1;
char current_status[50] = "OFFLINE";

void signal_handler(int signum) {
    if (signum == SIGINT || signum == SIGTERM) {
         keep_running = 0;
         const char msg[] = "\nSignal received. Shutting down submarine...\n";
         write(STDOUT_FILENO, msg, sizeof(msg) - 1);
    }
}

// --- Send Message Utility (Same as Silo) ---
bool send_message(int sock_fd, const char *message) {
    if (send(sock_fd, message, strlen(message), 0) < 0) {
        if (errno != EPIPE && errno != ECONNRESET) {
            perror("ERROR sending message");
        }
        log_message(MY_ID, "ERROR: Failed to send message: %s. Disconnecting.", strerror(errno));
        return false;
    }
    return true;
}

// --- Launch Simulation (Same as Silo, different message) ---
void simulate_launch(const char *target_info) {
    log_message(MY_ID, "VALID LAUNCH COMMAND RECEIVED. Target: %s", target_info);
    printf("[%s] *** LAUNCH SEQUENCE INITIATED (SLBM) ***\n", MY_ID);
    log_message(MY_ID, "Launch sequence initiated (SLBM).");
    strncpy(current_status, "LAUNCHING_SLBM", sizeof(current_status)-1);
    sleep(3); // Simulate preparation (e.g., flooding tubes)
    printf("[%s] *** SLBM LAUNCHED *** Target: %s\n", MY_ID, target_info);
    log_message(MY_ID, "SLBM LAUNCHED.");
    strncpy(current_status, "LAUNCHED_SLBM", sizeof(current_status)-1);
}

// --- Generate Simulated Intel ---
void generate_intel(char *intel_buffer, size_t buffer_size) {
    int type = rand() % 4;
    int x = rand() % 1000;
    int y = rand() % 1000;
    const char *status_desc;

    switch (type) {
        case 0: status_desc = "Passive sonar contact"; break;
        case 1: status_desc = "Active sonar ping detected"; break;
        case 2: status_desc = "Periscope depth observation"; break;
        case 3: // Simulate potential threat for War Test
              if (rand() % 8 == 0) { // Chance of generating specific threat intel
                  snprintf(intel_buffer, buffer_size, "Hostile submarine detected in patrol zone bearing %d", rand() % 360);
                  return;
              } // else fall through
              status_desc = "Environmental noise analysis"; break; // Added a default non-threat case
        default: status_desc = "Routine patrol data"; break;
    }
    snprintf(intel_buffer, buffer_size, "%s at approx grid %d,%d", status_desc, x, y);
}

// --- Main Client Logic (Structure similar to Missile Silo) ---
int main() {
    int sock_fd = -1;
    struct sockaddr_in server_addr;
    char buffer[BUFFER_SIZE];
    char intel_buffer[BUFFER_SIZE];
    time_t last_status_update = 0;
    time_t last_intel_update = 0;
    bool connected = false;

    if (!create_log_directory()) { exit(EXIT_FAILURE); }
    srand(time(NULL) ^ getpid()); // Seed random for intel generation, mix with PID

    log_message(MY_ID, "Submarine client starting...");
    printf("[%s] Submarine client starting...\n", MY_ID);
    strncpy(current_status, "INITIALIZING", sizeof(current_status)-1);

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = signal_handler;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    while (keep_running) {
        if (!connected) {
            // --- Attempt Connection ---
             if (sock_fd != -1) { close(sock_fd); sock_fd = -1; }
             strncpy(current_status, "CONNECTING", sizeof(current_status)-1);

            sock_fd = socket(AF_INET, SOCK_STREAM, 0);
            if (sock_fd < 0) {
                perror("ERROR opening socket"); log_message(MY_ID, "ERROR socket: %s", strerror(errno));
                sleep(RETRY_INTERVAL); continue;
            }

            memset(&server_addr, 0, sizeof(server_addr));
            server_addr.sin_family = AF_INET;
            server_addr.sin_port = htons(SERVER_PORT);
            if (inet_pton(AF_INET, SERVER_IP, &server_addr.sin_addr) <= 0) {
                perror("ERROR invalid IP"); log_message(MY_ID, "ERROR invalid IP: %s", SERVER_IP);
                close(sock_fd); sock_fd = -1; sleep(RETRY_INTERVAL); continue;
            }

            printf("[%s] Connecting to Nuclear Control %s:%d...\n", MY_ID, SERVER_IP, SERVER_PORT);
            if (connect(sock_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
                log_message(MY_ID, "INFO: Failed to connect: %s. Retrying...", strerror(errno));
                close(sock_fd); sock_fd = -1; sleep(RETRY_INTERVAL); continue;
            }

            // --- Connection successful ---
            connected = true;
            printf("[%s] Connected to Nuclear Control.\n", MY_ID);
            log_message(MY_ID, "Connected to server %s:%d.", SERVER_IP, SERVER_PORT);
             strncpy(current_status, "IDENTIFYING", sizeof(current_status)-1);

            // Send IDENTIFY
            snprintf(buffer, BUFFER_SIZE, "%s:%s%c", TAG_IDENTIFY, MY_ID, MSG_END);
            if (!send_message(sock_fd, buffer)) { connected = false; continue; }
            log_message(MY_ID, "Sent IDENTIFY message.");
            strncpy(current_status, "ON_PATROL", sizeof(current_status)-1);
            last_status_update = time(NULL);
            last_intel_update = time(NULL); // Send first intel/status soon after connecting
        }

        // --- Main loop when connected ---
        if (connected) {
            fd_set read_fds;
            struct timeval tv;
            int retval;

            FD_ZERO(&read_fds);
            if (sock_fd >= 0) { FD_SET(sock_fd, &read_fds); }
            else { connected = false; log_message(MY_ID, "ERROR: Socket FD invalid."); continue; }

            tv.tv_sec = 1; tv.tv_usec = 0;

            retval = select(sock_fd + 1, &read_fds, NULL, NULL, &tv);

            if (!keep_running) break;

            if (retval == -1) {
                 if (errno == EINTR) { continue; } // Interrupted by signal
                perror("ERROR in select()"); log_message(MY_ID, "ERROR select: %s. Disconnecting.", strerror(errno));
                connected = false; continue;
            } else if (retval > 0) {
                // Data available from server
                if (FD_ISSET(sock_fd, &read_fds)) {
                    memset(buffer, 0, BUFFER_SIZE);
                    int n = recv(sock_fd, buffer, BUFFER_SIZE - 1, 0);
                    if (n <= 0) {
                        if (n == 0) log_message(MY_ID, "INFO: Server closed connection.");
                        else {
                           if (errno != ECONNRESET && errno != ETIMEDOUT) perror("ERROR reading");
                           log_message(MY_ID, "ERROR recv: %s. Disconnecting.", strerror(errno));
                        }
                        connected = false; continue;
                    }
                    buffer[n] = '\0';

                    // Process potentially multiple messages
                    char *msg_start = buffer;
                    char *msg_end;
                    while ((msg_end = strchr(msg_start, MSG_END)) != NULL) {
                        *msg_end = '\0';
                        char *current_message = msg_start;
                        msg_start = msg_end + 1;

                        log_message(MY_ID, "Received raw: %s", current_message);

                        // --- Parse Command (Identical logic to Missile Silo for CMD tag) ---
                        char message_copy[BUFFER_SIZE];
                        strncpy(message_copy, current_message, BUFFER_SIZE -1);
                        message_copy[BUFFER_SIZE-1] = '\0';

                        char *type = strtok(message_copy, ":");
                        char *payload_encrypted = strtok(NULL, ":");
                        char *checksum_str = strtok(NULL, "\n");

                        if (type && strcmp(type, TAG_COMMAND) == 0 && payload_encrypted && checksum_str) {
                            char decrypted_payload[BUFFER_SIZE];
                            strncpy(decrypted_payload, payload_encrypted, BUFFER_SIZE -1);
                            decrypted_payload[BUFFER_SIZE-1] = '\0';
                            size_t decrypted_len = strlen(decrypted_payload);

                            encrypt_decrypt_xor(decrypted_payload, decrypted_len, SHARED_SECRET_KEY);
                            decrypted_payload[decrypted_len] = '\0'; // Re-terminate
                            log_message(MY_ID, "Decrypted payload: %s", decrypted_payload);

                            unsigned long received_checksum = strtoul(checksum_str, NULL, 10);
                            unsigned long calculated_checksum = simple_checksum(decrypted_payload, SHARED_SECRET_KEY);
                            log_message(MY_ID, "Received Checksum: %lu, Calculated Checksum: %lu", received_checksum, calculated_checksum);

                            if (received_checksum == calculated_checksum) {
                                log_message(MY_ID, "Checksum VERIFIED.");
                                char *command_type = strtok(decrypted_payload, ":");
                                char *command_data = strtok(NULL, "");

                                if (command_type) {
                                    if (strcmp(command_type, CMD_LAUNCH) == 0) {
                                        simulate_launch(command_data ? command_data : "UNKNOWN_TARGET");
                                        snprintf(buffer, BUFFER_SIZE, "%s:%s:SUCCESS%c", TAG_LAUNCH_ACK, MY_ID, MSG_END);
                                        if (!send_message(sock_fd, buffer)) connected = false;
                                        else log_message(MY_ID, "Sent LAUNCH ACK: SUCCESS");
                                    } else if (strcmp(command_type, CMD_STANDDOWN) == 0) {
                                        printf("[%s] Received STAND DOWN command. Reason: %s\n", MY_ID, command_data ? command_data : "N/A");
                                        log_message(MY_ID, "Received STAND DOWN command. Reason: %s", command_data ? command_data : "N/A");
                                        strncpy(current_status, "ON_PATROL", sizeof(current_status)-1);
                                    } else if (strcmp(command_type, CMD_QUERY_STATUS) == 0) {
                                        log_message(MY_ID, "Received Status Query. Sending status: %s", current_status);
                                        snprintf(buffer, BUFFER_SIZE, "%s:%s:%s%c", TAG_STATUS, MY_ID, current_status, MSG_END);
                                        if (!send_message(sock_fd, buffer)) connected = false;
                                    } else {
                                        log_message(MY_ID, "WARN: Unknown command type after decryption: %s", command_type);
                                    }
                                } else { log_message(MY_ID, "ERROR: Failed parse command type from decrypted payload."); }
                            } else {
                                log_message(MY_ID, "ERROR: Checksum FAILED! Ignoring command.");
                                snprintf(buffer, BUFFER_SIZE, "%s:%s:FAILURE Checksum_Mismatch%c", TAG_LAUNCH_ACK, MY_ID, MSG_END);
                                if (!send_message(sock_fd, buffer)) connected = false;
                                else log_message(MY_ID, "Sent LAUNCH NACK: Checksum Mismatch");
                            }
                        } else if (type) { log_message(MY_ID, "WARN: Received non-command message type: %s", type); }
                        else { log_message(MY_ID, "WARN: Received malformed message from server."); }
                    } // End while processing messages
                } // End if FD_ISSET
            } else { // select() timed out
                 time_t now = time(NULL);

                 // Send Periodic Intel
                 if (connected && sock_fd >= 0 && (now - last_intel_update >= INTEL_UPDATE_INTERVAL)) {
                     generate_intel(intel_buffer, sizeof(intel_buffer));
                     snprintf(buffer, BUFFER_SIZE, "%s:%s:%s%c", TAG_INTEL, MY_ID, intel_buffer, MSG_END);
                     log_message(MY_ID, "Sending intel: %s", intel_buffer);
                     if (!send_message(sock_fd, buffer)) { connected = false; continue; }
                     last_intel_update = now;
                 }

                 // Send Periodic Status
                 if (connected && sock_fd >= 0 && (now - last_status_update >= STATUS_UPDATE_INTERVAL)) {
                     snprintf(buffer, BUFFER_SIZE, "%s:%s:%s%c", TAG_STATUS, MY_ID, current_status, MSG_END);
                     log_message(MY_ID, "Sending periodic status update: %s", current_status);
                     if (!send_message(sock_fd, buffer)) { connected = false; continue; }
                     last_status_update = now;
                 }
            } // End select handling
        } // End if (connected)

        if (!connected && keep_running) {
            strncpy(current_status, "OFFLINE", sizeof(current_status)-1);
            sleep(1);
        }

    } // End while(keep_running)

    printf("[%s] Shutting down...\n", MY_ID);
    if (sock_fd != -1) close(sock_fd);
    log_message(MY_ID, "Submarine client stopped. Final status: %s", current_status);
    return 0;
}

