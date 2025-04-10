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

#define MY_ID ID_SAT "_Skynet" // Unique ID
#define INTEL_UPDATE_INTERVAL 25 // Seconds
#define STATUS_UPDATE_INTERVAL 120 // Seconds
#define RETRY_INTERVAL 5 // Seconds

volatile sig_atomic_t keep_running = 1;
char current_status[50] = "OFFLINE";

void signal_handler(int signum) {
    if (signum == SIGINT || signum == SIGTERM) {
         keep_running = 0;
         const char msg[] = "\nSignal received. Shutting down satellite...\n";
         write(STDOUT_FILENO, msg, sizeof(msg) - 1);
    }
}

// --- Send Message Utility (Same as others) ---
bool send_message(int sock_fd, const char *message) {
    if (send(sock_fd, message, strlen(message), 0) < 0) {
        if (errno != EPIPE && errno != ECONNRESET) perror("ERROR sending message");
        log_message(MY_ID, "ERROR: Failed to send message: %s. Disconnecting.", strerror(errno));
        return false;
    }
    return true;
}

// --- Generate Simulated Intel ---
void generate_intel(char *intel_buffer, size_t buffer_size) {
    int type = rand() % 5;
    int region_code = rand() % 900 + 100; // Geographic region code
    const char *obs_type;

    switch (type) {
        case 0: obs_type = "Optical imaging"; break;
        case 1: obs_type = "Infrared scan"; break;
        case 2: obs_type = "Signals intelligence"; break;
        case 3: // Simulate potential threat for War Test
              if (rand() % 12 == 0) { // Lower chance than radar/sub
                   snprintf(intel_buffer, buffer_size, "Unusual heat signature detected near hostile border, possible launch prep. Region %d", region_code);
                   return;
               } // else fall through
               obs_type = "Radar altimetry"; break;
        case 4: obs_type = "Atmospheric density measurement"; break;
        default: obs_type = "Routine system scan"; break;
    }
    snprintf(intel_buffer, buffer_size, "%s results for region %d: Nominal activity.", obs_type, region_code);
}


// --- Main Client Logic (Similar structure to Radar) ---
int main() {
    int sock_fd = -1;
    struct sockaddr_in server_addr;
    char buffer[BUFFER_SIZE];
    char intel_buffer[BUFFER_SIZE];
    time_t last_status_update = 0;
    time_t last_intel_update = 0;
    bool connected = false;

    if (!create_log_directory()) { exit(EXIT_FAILURE); }
    srand(time(NULL) ^ getpid());

    log_message(MY_ID, "Satellite client starting...");
    printf("[%s] Satellite client starting...\n", MY_ID);
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
            if (sock_fd < 0) { perror("socket"); log_message(MY_ID,"ERROR socket: %s", strerror(errno)); sleep(RETRY_INTERVAL); continue; }

            memset(&server_addr, 0, sizeof(server_addr));
            server_addr.sin_family = AF_INET;
            server_addr.sin_port = htons(SERVER_PORT);
            if (inet_pton(AF_INET, SERVER_IP, &server_addr.sin_addr) <= 0) { perror("inet_pton"); log_message(MY_ID,"ERROR invalid IP: %s", SERVER_IP); close(sock_fd); sock_fd = -1; sleep(RETRY_INTERVAL); continue; }

            printf("[%s] Connecting to Nuclear Control %s:%d...\n", MY_ID, SERVER_IP, SERVER_PORT);
            if (connect(sock_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) { log_message(MY_ID, "INFO connect: %s. Retrying...", strerror(errno)); close(sock_fd); sock_fd = -1; sleep(RETRY_INTERVAL); continue; }

            // --- Connection successful ---
            connected = true;
            printf("[%s] Connected to Nuclear Control.\n", MY_ID);
            log_message(MY_ID, "Connected to server %s:%d.", SERVER_IP, SERVER_PORT);
             strncpy(current_status, "IDENTIFYING", sizeof(current_status)-1);

            // Send IDENTIFY
            snprintf(buffer, BUFFER_SIZE, "%s:%s%c", TAG_IDENTIFY, MY_ID, MSG_END);
            if (!send_message(sock_fd, buffer)) { connected = false; continue; }
            log_message(MY_ID, "Sent IDENTIFY message.");
            strncpy(current_status, "NOMINAL", sizeof(current_status)-1);
            last_status_update = last_intel_update = time(NULL);
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
                 if (errno == EINTR) { continue; }
                perror("select"); log_message(MY_ID, "ERROR select: %s. Disconnecting.", strerror(errno)); close(sock_fd); sock_fd = -1; connected = false; continue;
            } else if (retval > 0) {
                // Data available from server
                if (FD_ISSET(sock_fd, &read_fds)) {
                    memset(buffer, 0, BUFFER_SIZE);
                    int n = recv(sock_fd, buffer, BUFFER_SIZE - 1, 0);
                    if (n <= 0) {
                        if (n == 0) log_message(MY_ID, "INFO: Server closed connection.");
                        else {
                           if(errno != ECONNRESET && errno != ETIMEDOUT) perror("recv");
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
                        // Basic command handling (e.g., status query)
                         char message_copy[BUFFER_SIZE];
                        strncpy(message_copy, current_message, BUFFER_SIZE-1);
                        message_copy[BUFFER_SIZE-1] = '\0';

                        char *type = strtok(message_copy, ":");
                        char *payload = strtok(NULL, ""); // Allow empty payload

                         if (type && strcmp(type, TAG_COMMAND) == 0 && payload) {
                             // Satellite also does not expect complex commands
                             char *cmd_type = strtok(payload, ":");
                              if(cmd_type && strcmp(cmd_type, CMD_QUERY_STATUS) == 0) {
                                  log_message(MY_ID, "Received Status Query. Sending status: %s", current_status);
                                  snprintf(buffer, BUFFER_SIZE, "%s:%s:%s%c", TAG_STATUS, MY_ID, current_status, MSG_END);
                                  if (!send_message(sock_fd, buffer)) connected = false;
                              } else {
                                   log_message(MY_ID, "WARN: Received unhandled/unexpected command type: %s", cmd_type ? cmd_type : "<null>");
                              }
                         } else if (type) {
                              log_message(MY_ID, "WARN: Received unexpected message type: %s", type);
                         } else {
                              log_message(MY_ID, "WARN: Received malformed message from server.");
                         }
                    } // end while processing messages
                }
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
            }
        } // end if(connected)

        if (!connected && keep_running) {
             strncpy(current_status, "OFFLINE", sizeof(current_status)-1);
             sleep(1);
        }
    } // end while(keep_running)

    printf("\n[%s] Shutting down...\n", MY_ID);
    if (sock_fd != -1) close(sock_fd);
    log_message(MY_ID, "Satellite client stopped. Final status: %s", current_status);
    return 0;
}

