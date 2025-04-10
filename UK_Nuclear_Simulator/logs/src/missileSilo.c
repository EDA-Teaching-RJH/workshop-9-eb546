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
#include <sys/select.h> // Required for select()

#include "common.h"
#include "utils.h"

#define MY_ID ID_SILO "_Alpha" // Unique ID for this silo instance
#define STATUS_UPDATE_INTERVAL 30 // Seconds
#define RETRY_INTERVAL 5 // Seconds to wait before connection retry

volatile sig_atomic_t keep_running = 1; // Signal handler flag
char current_status[50] = "OFFLINE"; // Track current state

void signal_handler(int signum) {
    if (signum == SIGINT || signum == SIGTERM) {
         keep_running = 0;
         const char msg[] = "\nSignal received. Shutting down silo...\n";
         write(STDOUT_FILENO, msg, sizeof(msg) - 1); // Signal safe write
    }
}

// --- Send Message Utility ---
bool send_message(int sock_fd, const char *message) {
    if (send(sock_fd, message, strlen(message), 0) < 0) {
        if (errno != EPIPE && errno != ECONNRESET) { // Avoid spamming logs for normal disconnects
            perror("ERROR sending message");
        }
        log_message(MY_ID, "ERROR: Failed to send message: %s. Disconnecting.", strerror(errno));
        return false; // Indicate failure, likely disconnect
    }
    // log_message(MY_ID, "DEBUG: Sent: %s", message); // Verbose logging if needed
    return true;
}

// --- Launch Simulation ---
void simulate_launch(const char *target_info) {
    log_message(MY_ID, "VALID LAUNCH COMMAND RECEIVED. Target: %s", target_info);
    printf("[%s] *** LAUNCH SEQUENCE INITIATED ***\n", MY_ID);
    log_message(MY_ID, "Launch sequence initiated.");
    strncpy(current_status, "LAUNCHING", sizeof(current_status)-1);
    sleep(2); // Simulate preparation
    printf("[%s] *** MISSILE LAUNCHED *** Target: %s\n", MY_ID, target_info);
    log_message(MY_ID, "MISSILE LAUNCHED.");
    strncpy(current_status, "LAUNCHED", sizeof(current_status)-1);
    // State should change, report back to control happens via periodic status update
}

// --- Main Client Logic ---
int main() {
    int sock_fd = -1;
    struct sockaddr_in server_addr;
    char buffer[BUFFER_SIZE];
    time_t last_status_update = 0;
    bool connected = false;

    if (!create_log_directory()) { exit(EXIT_FAILURE); } // Ensure log dir exists

    log_message(MY_ID, "Missile Silo client starting...");
    printf("[%s] Missile Silo client starting...\n", MY_ID);
    strncpy(current_status, "INITIALIZING", sizeof(current_status)-1);

    // Setup signal handling
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = signal_handler;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    while (keep_running) {
        if (!connected) {
            // --- Attempt Connection ---
            if (sock_fd != -1) { close(sock_fd); sock_fd = -1; } // Close previous socket if any
            strncpy(current_status, "CONNECTING", sizeof(current_status)-1);

            sock_fd = socket(AF_INET, SOCK_STREAM, 0);
            if (sock_fd < 0) {
                perror("ERROR opening socket");
                log_message(MY_ID, "ERROR: Failed to create socket: %s", strerror(errno));
                sleep(RETRY_INTERVAL); // Wait before retry
                continue;
            }

            memset(&server_addr, 0, sizeof(server_addr));
            server_addr.sin_family = AF_INET;
            server_addr.sin_port = htons(SERVER_PORT);
            if (inet_pton(AF_INET, SERVER_IP, &server_addr.sin_addr) <= 0) {
                perror("ERROR invalid server IP address");
                log_message(MY_ID, "ERROR: Invalid server IP address %s", SERVER_IP);
                close(sock_fd); sock_fd = -1;
                sleep(RETRY_INTERVAL);
                continue;
            }

            printf("[%s] Connecting to Nuclear Control %s:%d...\n", MY_ID, SERVER_IP, SERVER_PORT);
            if (connect(sock_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
                // Don't use perror here as it's expected during server downtime
                log_message(MY_ID, "INFO: Failed to connect to %s:%d: %s. Retrying in %d sec...", SERVER_IP, SERVER_PORT, strerror(errno), RETRY_INTERVAL);
                close(sock_fd); sock_fd = -1;
                sleep(RETRY_INTERVAL); // Wait before retry
                continue;
            }

            // --- Connection successful ---
            connected = true;
            printf("[%s] Connected to Nuclear Control.\n", MY_ID);
            log_message(MY_ID, "Connected to server %s:%d.", SERVER_IP, SERVER_PORT);
            strncpy(current_status, "IDENTIFYING", sizeof(current_status)-1);

            // 1. Send IDENTIFY message
            snprintf(buffer, BUFFER_SIZE, "%s:%s%c", TAG_IDENTIFY, MY_ID, MSG_END);
            if (!send_message(sock_fd, buffer)) {
                connected = false; // send_message failed, likely disconnect
                continue;
            }
            log_message(MY_ID, "Sent IDENTIFY message.");
            strncpy(current_status, "READY", sizeof(current_status)-1);
            last_status_update = time(NULL); // Reset timer after successful connection/identification
        } // End if (!connected)


        // --- Main loop when connected ---
        if (connected) {
            fd_set read_fds;
            struct timeval tv;
            int retval;

            FD_ZERO(&read_fds);
            // Important: Check if sock_fd is valid before adding to set
            if (sock_fd >= 0) {
                 FD_SET(sock_fd, &read_fds);
            } else {
                 connected = false; // Socket became invalid somehow
                 log_message(MY_ID, "ERROR: Socket FD became invalid unexpectedly.");
                 continue;
            }


            // Set timeout for select (e.g., 1 second) to allow periodic checks
            tv.tv_sec = 1;
            tv.tv_usec = 0;

            retval = select(sock_fd + 1, &read_fds, NULL, NULL, &tv);

            if (!keep_running) break; // Check flag after potential select block

            if (retval == -1) {
                 if (errno == EINTR) { // Interrupted by signal handler
                     log_message(MY_ID, "INFO: Select interrupted by signal.");
                     continue; // Check keep_running flag again
                 }
                perror("ERROR in select()");
                log_message(MY_ID, "ERROR: select() failed: %s. Disconnecting.", strerror(errno));
                connected = false; // Assume connection is broken
                continue;
            } else if (retval > 0) {
                // Data is available to read from server
                if (FD_ISSET(sock_fd, &read_fds)) {
                    memset(buffer, 0, BUFFER_SIZE);
                    int n = recv(sock_fd, buffer, BUFFER_SIZE - 1, 0);

                    if (n <= 0) {
                        if (n == 0) {
                            printf("[%s] Server disconnected.\n", MY_ID);
                            log_message(MY_ID, "INFO: Server closed connection.");
                        } else {
                            if (errno != ECONNRESET && errno != ETIMEDOUT) { // Log real errors
                                perror("ERROR reading from socket");
                            }
                            log_message(MY_ID, "ERROR: Failed to receive data: %s. Disconnecting.", strerror(errno));
                        }
                        connected = false; // Disconnected
                        continue;
                    }

                    // Process received data (potentially multiple messages)
                    buffer[n] = '\0';
                    char *msg_start = buffer;
                    char *msg_end;

                    while ((msg_end = strchr(msg_start, MSG_END)) != NULL) {
                        *msg_end = '\0'; // Null-terminate current message
                        char *current_message = msg_start;
                        msg_start = msg_end + 1; // Move start for next iteration

                        log_message(MY_ID, "Received raw: %s", current_message);

                        // --- Parse Command ---
                        // Make a mutable copy for strtok
                        char message_copy[BUFFER_SIZE];
                        strncpy(message_copy, current_message, BUFFER_SIZE -1);
                        message_copy[BUFFER_SIZE-1] = '\0';

                        char *type = strtok(message_copy, ":");
                        char *payload_encrypted = strtok(NULL, ":"); // Might be encrypted payload
                        char *checksum_str = strtok(NULL, "\n"); // Might be checksum (no delimiter after this)

                        if (type && strcmp(type, TAG_COMMAND) == 0 && payload_encrypted && checksum_str) {
                            log_message(MY_ID, "Received potential command. Encrypted Payload: %s, Checksum str: %s", payload_encrypted, checksum_str);

                            // 1. Decrypt the payload
                            char decrypted_payload[BUFFER_SIZE];
                            strncpy(decrypted_payload, payload_encrypted, BUFFER_SIZE -1);
                            decrypted_payload[BUFFER_SIZE-1] = '\0';
                            size_t decrypted_len = strlen(decrypted_payload); // Use length for XOR

                            encrypt_decrypt_xor(decrypted_payload, decrypted_len, SHARED_SECRET_KEY);
                            // Null terminate again in case XOR created nulls mid-string before the original end
                            decrypted_payload[decrypted_len] = '\0';
                            log_message(MY_ID, "Decrypted payload: %s", decrypted_payload);

                            // 2. Verify checksum (against the decrypted payload)
                            unsigned long received_checksum = strtoul(checksum_str, NULL, 10);
                            // IMPORTANT: The checksum MUST be calculated on the exact same string that was checksummed on the server side.
                            // This is the "CommandType:Data" part.
                            unsigned long calculated_checksum = simple_checksum(decrypted_payload, SHARED_SECRET_KEY);

                            log_message(MY_ID, "Received Checksum: %lu, Calculated Checksum: %lu", received_checksum, calculated_checksum);

                            if (received_checksum == calculated_checksum) {
                                log_message(MY_ID, "Checksum VERIFIED.");

                                // 3. Parse the decrypted payload (CommandType:Data)
                                char *command_type = strtok(decrypted_payload, ":");
                                char *command_data = strtok(NULL, ""); // Rest is data

                                if (command_type) {
                                    if (strcmp(command_type, CMD_LAUNCH) == 0) {
                                        simulate_launch(command_data ? command_data : "UNKNOWN_TARGET");
                                        // Send ACK back to control
                                        snprintf(buffer, BUFFER_SIZE, "%s:%s:SUCCESS%c", TAG_LAUNCH_ACK, MY_ID, MSG_END);
                                        if (!send_message(sock_fd, buffer)) { connected = false; }
                                        else { log_message(MY_ID, "Sent LAUNCH ACK: SUCCESS"); }
                                    } else if (strcmp(command_type, CMD_STANDDOWN) == 0) {
                                        printf("[%s] Received STAND DOWN command. Reason: %s\n", MY_ID, command_data ? command_data : "N/A");
                                        log_message(MY_ID, "Received STAND DOWN command. Reason: %s", command_data ? command_data : "N/A");
                                        strncpy(current_status, "READY", sizeof(current_status)-1); // Go back to ready state
                                    } else if (strcmp(command_type, CMD_QUERY_STATUS) == 0) {
                                        log_message(MY_ID, "Received Status Query. Sending status: %s", current_status);
                                        snprintf(buffer, BUFFER_SIZE, "%s:%s:%s%c", TAG_STATUS, MY_ID, current_status, MSG_END);
                                        if (!send_message(sock_fd, buffer)) { connected = false; }
                                    } else {
                                        log_message(MY_ID, "WARN: Received unknown command type after decryption: %s", command_type);
                                    }
                                } else {
                                    log_message(MY_ID, "ERROR: Failed to parse command type from decrypted payload.");
                                }
                            } else {
                                log_message(MY_ID, "ERROR: Checksum verification FAILED! Ignoring command.");
                                // Send NACK back to control
                                snprintf(buffer, BUFFER_SIZE, "%s:%s:FAILURE Checksum_Mismatch%c", TAG_LAUNCH_ACK, MY_ID, MSG_END);
                                if (!send_message(sock_fd, buffer)) { connected = false; }
                                else { log_message(MY_ID, "Sent LAUNCH NACK: Checksum Mismatch"); }
                            }
                        } else if (type) {
                            // Handle other non-encrypted messages if needed
                            log_message(MY_ID, "WARN: Received non-command message type: %s", type);
                        } else {
                            log_message(MY_ID, "WARN: Received malformed message from server.");
                        }
                    } // End while processing messages in buffer
                } // End if FD_ISSET
            } else { // select() timed out (retval == 0)
                 // No data received, time for periodic tasks
                 time_t now = time(NULL);
                 if (connected && sock_fd >= 0 && (now - last_status_update >= STATUS_UPDATE_INTERVAL)) {
                     // Send status update
                     snprintf(buffer, BUFFER_SIZE, "%s:%s:%s%c", TAG_STATUS, MY_ID, current_status, MSG_END);
                     log_message(MY_ID, "Sending periodic status update: %s", current_status);
                     if (!send_message(sock_fd, buffer)) {
                         connected = false; // Sending failed, assume disconnect
                     }
                     last_status_update = now;
                 }
            } // End select handling
        } // End if (connected)

        // Small delay if not connected to prevent busy-looping on connection errors
        if (!connected && keep_running) {
             strncpy(current_status, "OFFLINE", sizeof(current_status)-1);
             sleep(1); // Short sleep before retry loop potentially starts
        }

    } // End while(keep_running)

    // --- Cleanup ---
    printf("[%s] Shutting down...\n", MY_ID);
    if (sock_fd != -1) {
        close(sock_fd);
    }
    log_message(MY_ID, "Missile Silo client stopped. Final status: %s", current_status);
    return 0;
}

