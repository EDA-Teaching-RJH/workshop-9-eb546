#define _DEFAULT_SOURCE // For NI_MAXHOST, NI_MAXSERV with glibc >= 2.22
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h> // For signal handling
#include <time.h>   // For seeding rand()
#include <stdbool.h> // For bool type
#include <netdb.h> // For getnameinfo
#include <sys/select.h> // Include for select within threads if needed, though primarily recv blocking here

#include "common.h"
#include "utils.h"

#define MAX_PENDING_CONNECTIONS 5

// Structure to hold client information
typedef struct {
    int socket_fd;
    struct sockaddr_in address;
    char client_id[50]; // Store ID like "SILO_1", "SUB_ALPHA", "RADAR_NORTH" etc.
    bool active;
    pthread_t thread_id;
} client_info_t;

client_info_t clients[MAX_CLIENTS];
pthread_mutex_t clients_mutex = PTHREAD_MUTEX_INITIALIZER;
int client_count = 0;
volatile sig_atomic_t run_server = 1; // Flag to control server loop, use sig_atomic_t for signal safety
bool war_test_mode = false;
int server_socket_fd = -1;

// Function Prototypes
void *handle_client(void *arg);
void initialize_clients();
int add_client(int socket_fd, struct sockaddr_in address);
void remove_client(int client_index);
void send_to_client(int client_index, const char *message);
bool send_secure_launch_command(const char* target_client_id_prefix, const char* target_info);
void *war_test_monitor(void *arg);
void cleanup_server();
void signal_handler(int signum);
void assess_threat_and_decide(const char* intel_source, const char* intel_data);


// --- Main Server Logic ---
int main(int argc, char *argv[]) {
    srand(time(NULL)); // Seed random number generator

    // Ensure log directory exists before logging anything critical
    if (!create_log_directory()) {
       exit(EXIT_FAILURE); // Cannot proceed without logging capability
    }

    log_message(ID_CONTROL, "Nuclear Control Server starting...");

    // Check for command line arguments
    if (argc > 1 && strcmp(argv[1], "--test") == 0) {
        war_test_mode = true;
        printf("INFO: War test mode enabled.\n");
        log_message(ID_CONTROL, "War test mode enabled.");
    }

    // Setup signal handling for graceful shutdown
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = signal_handler;
    sigaction(SIGINT, &sa, NULL);  // Handle Ctrl+C
    sigaction(SIGTERM, &sa, NULL); // Handle termination signal


    initialize_clients();

    struct sockaddr_in server_addr;

    // 1. Create socket
    server_socket_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket_fd < 0) {
        perror("ERROR opening socket");
        log_message(ID_CONTROL, "FATAL: Failed to create server socket: %s", strerror(errno));
        exit(EXIT_FAILURE);
    }
    log_message(ID_CONTROL, "Server socket created (fd: %d).", server_socket_fd);

    // Set SO_REUSEADDR to allow immediate reuse of the port after server stops
    int optval = 1;
    if (setsockopt(server_socket_fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) < 0) {
        perror("setsockopt(SO_REUSEADDR) failed");
        log_message(ID_CONTROL, "WARN: setsockopt(SO_REUSEADDR) failed: %s", strerror(errno));
    }


    // 2. Bind socket
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr(SERVER_IP); // Or INADDR_ANY for all interfaces
    server_addr.sin_port = htons(SERVER_PORT);

    if (bind(server_socket_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("ERROR on binding");
        log_message(ID_CONTROL, "FATAL: Failed to bind server socket to %s:%d: %s", SERVER_IP, SERVER_PORT, strerror(errno));
        close(server_socket_fd);
        exit(EXIT_FAILURE);
    }
    log_message(ID_CONTROL, "Server socket bound to %s:%d.", SERVER_IP, SERVER_PORT);

    // 3. Listen for connections
    if (listen(server_socket_fd, MAX_PENDING_CONNECTIONS) < 0) {
        perror("ERROR on listen");
        log_message(ID_CONTROL, "FATAL: Failed to listen on server socket: %s", strerror(errno));
        close(server_socket_fd);
        exit(EXIT_FAILURE);
    }
    printf("Nuclear Control Server listening on %s:%d...\n", SERVER_IP, SERVER_PORT);
    log_message(ID_CONTROL, "Server listening...");


    // Start War Test Monitor thread if enabled
    pthread_t war_test_thread_id = 0; // Initialize to 0 or PTHREAD_T_NULL if defined
    if (war_test_mode) {
        if (pthread_create(&war_test_thread_id, NULL, war_test_monitor, NULL) != 0) {
            perror("Failed to create war test monitor thread");
            log_message(ID_CONTROL, "ERROR: Failed to start war test monitor thread.");
            // Decide if this is fatal? Let's continue but without the test functionality.
        } else {
             log_message(ID_CONTROL, "War test monitor thread started.");
             // Detach the thread so we don't need to join it later
             pthread_detach(war_test_thread_id);
        }
    }


    // 4. Accept connections in a loop
    while (run_server) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        int newsockfd;

        // Using select to make accept non-blocking and responsive to shutdown signal
        fd_set read_fds;
        struct timeval tv;
        FD_ZERO(&read_fds);
        FD_SET(server_socket_fd, &read_fds);
        tv.tv_sec = 1; // Check every second
        tv.tv_usec = 0;

        int activity = select(server_socket_fd + 1, &read_fds, NULL, NULL, &tv);

        if ((activity < 0) && (errno != EINTR)) {
            perror("select error on listen socket");
            log_message(ID_CONTROL, "WARN: select() error on listen socket: %s", strerror(errno));
            continue; // Or potentially break if error is severe
        }

        if (!run_server) break; // Check flag after select

        // If select indicated activity on the listening socket
        if (activity > 0 && FD_ISSET(server_socket_fd, &read_fds)) {
            newsockfd = accept(server_socket_fd, (struct sockaddr *)&client_addr, &client_len);

            if (newsockfd < 0) {
                // Don't exit on accept error unless it's critical or we are shutting down
                if (errno != EINTR || run_server) {
                    perror("ERROR on accept");
                    log_message(ID_CONTROL, "WARN: Error accepting new connection: %s", strerror(errno));
                }
                continue; // Try to accept the next connection
            }

            // Add client to our list and start a handler thread
            int client_index = add_client(newsockfd, client_addr);
            if (client_index != -1) {
                // Pass the client index as argument
                 if (pthread_create(&clients[client_index].thread_id, NULL, handle_client, (void *)(intptr_t)client_index) != 0) {
                     perror("ERROR creating client handler thread");
                     log_message(ID_CONTROL, "ERROR: Failed to create thread for client %d.", newsockfd);
                     close(newsockfd);
                     remove_client(client_index); // Clean up partially added client
                 } else {
                     // Thread created successfully, detaching so we don't need to join it
                     pthread_detach(clients[client_index].thread_id);
                 }
            } else {
                // Failed to add client (e.g., max clients reached)
                log_message(ID_CONTROL, "WARN: Rejected connection from fd %d: too many clients.", newsockfd);
                const char *reject_msg = "ERROR: Server busy. Too many clients.\n";
                send(newsockfd, reject_msg, strlen(reject_msg), 0); // Send rejection message
                close(newsockfd); // Close the connection
            }
        } // end if FD_ISSET
    } // End while(run_server)

    // --- Cleanup ---
    cleanup_server();
    printf("Nuclear Control Server shut down.\n");
    log_message(ID_CONTROL, "Server shut down complete.");
    pthread_mutex_destroy(&clients_mutex); // Clean up mutex
    return 0;
}

// --- Client Handling Thread ---
void *handle_client(void *arg) {
    int client_index = (intptr_t)arg; // Retrieve client index from argument
    int sock_fd;
    char buffer[BUFFER_SIZE];
    int n;
    char client_ip[NI_MAXHOST];
    char client_port[NI_MAXSERV];
    bool client_identified = false;
    char current_client_id[50] = "unknown"; // Local copy for logging after removal

    // Safely get initial socket descriptor and address
    pthread_mutex_lock(&clients_mutex);
    if (client_index < 0 || client_index >= MAX_CLIENTS || !clients[client_index].active) {
         pthread_mutex_unlock(&clients_mutex);
         log_message(ID_CONTROL, "ERROR: Invalid client index %d in handle_client start.", client_index);
         return NULL; // Exit thread if client is already gone
    }
    sock_fd = clients[client_index].socket_fd;
    struct sockaddr_in addr = clients[client_index].address;
    pthread_mutex_unlock(&clients_mutex);

    // Get client address string for logging
    if (getnameinfo((struct sockaddr*)&addr, sizeof(addr), client_ip, sizeof(client_ip),
                    client_port, sizeof(client_port), NI_NUMERICHOST | NI_NUMERICSERV) == 0) {
        log_message(ID_CONTROL, "INFO: Handling client fd %d from %s:%s (Index %d).", sock_fd, client_ip, client_port, client_index);
    } else {
        log_message(ID_CONTROL, "INFO: Handling client fd %d (address lookup failed, Index %d).", sock_fd, client_index);
        strncpy(client_ip, "?.?.?.?", sizeof(client_ip)-1); // Default if lookup fails
        client_ip[sizeof(client_ip)-1] = '\0';
    }

    // Client interaction loop
    while (run_server) {
        memset(buffer, 0, BUFFER_SIZE);
        // Use recv() which will block until data arrives or an error/disconnect occurs
        n = recv(sock_fd, buffer, BUFFER_SIZE - 1, 0);

        if (!run_server) break; // Check flag immediately after potentially blocking recv

        if (n <= 0) {
            if (n == 0) {
                // Connection closed gracefully by client
                log_message(ID_CONTROL, "INFO: Client %s (%s:%s, fd %d, Index %d) disconnected gracefully.", current_client_id, client_ip, client_port, sock_fd, client_index);
            } else {
                // Error receiving data (could be disconnect, could be other error)
                if (errno != ECONNRESET && errno != ETIMEDOUT) { // Log real errors, ignore common disconnect types
                    perror("ERROR reading from socket");
                }
                log_message(ID_CONTROL, "INFO: Client %s (%s:%s, fd %d, Index %d) disconnected: %s.", current_client_id, client_ip, client_port, sock_fd, client_index, strerror(errno));
            }
            break; // Exit loop on error or disconnect
        }

        // Null-terminate received data (important!)
        buffer[n] = '\0';

        // Process potentially multiple messages in the buffer (if they arrived together)
        char *msg_start = buffer;
        char *msg_end;
        while ((msg_end = strchr(msg_start, MSG_END)) != NULL) {
             *msg_end = '\0'; // Null-terminate the current message
             char *current_message = msg_start;
             msg_start = msg_end + 1; // Move start to the beginning of the next potential message

            // Process the single, null-terminated message
            log_message(ID_CONTROL, "DEBUG: Raw message from %s: %s", current_client_id, current_message);

            // Make a mutable copy for strtok
            char message_copy[BUFFER_SIZE];
            strncpy(message_copy, current_message, BUFFER_SIZE - 1);
            message_copy[BUFFER_SIZE - 1] = '\0';

            char *type = strtok(message_copy, ":");
            char *payload = strtok(NULL, ""); // Get the rest of the line (handle potential lack of payload)

            if (type == NULL) {
                log_message(ID_CONTROL, "WARN: Received empty or malformed message from %s (fd %d).", current_client_id, sock_fd);
                continue; // Process next message in buffer if any
            }

            // --- Message Handling Logic ---
            if (!client_identified) {
                // First message must be IDENTIFY
                if (strcmp(type, TAG_IDENTIFY) == 0 && payload != NULL) {
                    bool success = false;
                    pthread_mutex_lock(&clients_mutex);
                    // Check client still exists at this index before modifying
                    if (clients[client_index].active && clients[client_index].socket_fd == sock_fd) {
                        strncpy(clients[client_index].client_id, payload, sizeof(clients[client_index].client_id) - 1);
                        clients[client_index].client_id[sizeof(clients[client_index].client_id) - 1] = '\0'; // Ensure null termination
                        strncpy(current_client_id, payload, sizeof(current_client_id) - 1); // Update local copy
                        current_client_id[sizeof(current_client_id) - 1] = '\0';
                        client_identified = true;
                        success = true;
                        log_message(ID_CONTROL, "INFO: Client fd %d (Index %d) identified as %s.", sock_fd, client_index, current_client_id);
                    } else {
                         log_message(ID_CONTROL, "WARN: Client fd %d (Index %d) became inactive during identification.", sock_fd, client_index);
                    }
                    pthread_mutex_unlock(&clients_mutex);

                    if(!success) break; // Client removed while identifying? Exit thread.

                } else {
                    log_message(ID_CONTROL, "WARN: Client fd %d sent invalid first message (expected IDENTIFY): %s", sock_fd, type);
                    break; // Disconnect unidentified client sending wrong message
                }
            } else {
                // Handle subsequent messages from identified client
                // Log from the client's perspective (using their ID)
                 log_message(current_client_id, "Received: Type=%s, Payload=%s", type, payload ? payload : "<NONE>");

                if (strcmp(type, TAG_INTEL) == 0 && payload != NULL) {
                    // Intel messages contain source and data separated by ':'
                    char *intel_source_part = strtok(payload, ":"); // Source ID like SUB_Vanguard
                    char *intel_data_part = strtok(NULL, ""); // Rest is the intel data

                    if (intel_source_part && intel_data_part) {
                        log_message(ID_CONTROL, "INTEL received via %s from %s: %s", current_client_id, intel_source_part, intel_data_part);
                        // Assess threat based on received intel
                        assess_threat_and_decide(intel_source_part, intel_data_part);
                    } else {
                        log_message(ID_CONTROL, "WARN: Malformed INTEL message from %s.", current_client_id);
                    }
                } else if (strcmp(type, TAG_STATUS) == 0 && payload != NULL) {
                    log_message(ID_CONTROL, "STATUS update from %s: %s", current_client_id, payload);
                    // Update internal state if necessary (e.g., track readiness)
                } else if (strcmp(type, TAG_LAUNCH_ACK) == 0 && payload != NULL) {
                    log_message(ID_CONTROL, "LAUNCH ACK from %s: %s", current_client_id, payload);
                    // Handle launch confirmation/failure
                } else if (strcmp(type, TAG_IDENTIFY) == 0) {
                    log_message(ID_CONTROL, "WARN: Client %s sent IDENTIFY message again.", current_client_id);
                    // Ignore or handle as error? Ignore for now.
                } else {
                    log_message(ID_CONTROL, "WARN: Received unknown message type '%s' from %s.", type, current_client_id);
                }
            } // end if(client_identified)
        } // end while loop processing messages in buffer
    } // End while(run_server)

    // --- Client Disconnected or Error ---
    log_message(ID_CONTROL, "INFO: Closing connection handler for client %s (fd %d, Index %d).", current_client_id, sock_fd, client_index);
    close(sock_fd);
    remove_client(client_index); // Remove from the active list

    return NULL;
}

// --- War Test Monitor Thread ---
// Only runs if --test is specified
void *war_test_monitor(void *arg) {
    UNUSED(arg);
    log_message(ID_CONTROL, "War Test Monitor active.");
    const char* potential_threats[] = {
        "RADAR:Possible incoming ballistic missile detected.",
        "SATELLITE:Unusual heat signature detected near hostile border.",
        "SUBMARINE:Hostile submarine detected in patrol zone.",
        "RADAR:Multiple unidentified aircraft approaching airspace.",
        "SATELLITE:Large scale troop movement observed.",
    };
    int num_threats = sizeof(potential_threats) / sizeof(potential_threats[0]);

    while (run_server) {
        // Wait for a random interval (e.g., 20-70 seconds)
        int delay = 20 + rand() % 51;
        for(int i = 0; i < delay && run_server; ++i) {
            sleep(1); // Sleep in 1-second intervals to check run_server flag
        }

        if (!run_server) break; // Check after sleep loop

        // Simulate receiving a random threat intel report
        int threat_index = rand() % num_threats;
        char simulated_intel[BUFFER_SIZE];
        // Make a mutable copy for strtok
        strncpy(simulated_intel, potential_threats[threat_index], BUFFER_SIZE - 1);
        simulated_intel[BUFFER_SIZE - 1] = '\0';

        char *source = strtok(simulated_intel, ":");
        char *data = strtok(NULL, ""); // Get rest of payload

        if (source && data) {
             log_message(ID_CONTROL, "[WAR TEST] Simulated Intel Received from %s: %s", source, data);
             // Assess the simulated threat
             assess_threat_and_decide(source, data);
        }
    }
    log_message(ID_CONTROL, "War Test Monitor stopping.");
    return NULL;
}

// --- Threat Assessment & Decision Logic ---
// Basic example: Launch if specific keywords are detected IN WAR TEST MODE
void assess_threat_and_decide(const char* intel_source, const char* intel_data) {
    log_message(ID_CONTROL, "Assessing threat from %s: '%s'", intel_source, intel_data);

    bool launch_condition_met = false;
    const char* target_info = "DefaultTarget"; // Example target

    // Simple keyword-based assessment
    if (strstr(intel_data, "ballistic missile detected") != NULL) {
        log_message(ID_CONTROL, "CRITICAL THREAT DETECTED: Potential incoming missile!");
        launch_condition_met = true;
        target_info = "Counterforce_Target_A";
    } else if (strstr(intel_data, "hostile border") != NULL && strstr(intel_data, "heat signature") != NULL) {
         log_message(ID_CONTROL, "HIGH ALERT: Potential enemy launch preparation detected.");
         launch_condition_met = true;
         target_info = "Preemptive_Target_B";
    } else if (strstr(intel_data, "Hostile submarine") != NULL && strstr(intel_data, "patrol zone") != NULL) {
        log_message(ID_CONTROL, "ALERT: Hostile submarine detected.");
        launch_condition_met = true;
        target_info = "AntiSubmarine_Target_C";
    }
     else {
        log_message(ID_CONTROL, "Assessment: Threat level not critical for immediate launch based on current intel.");
        return; // No launch decision
    }


    if (launch_condition_met && war_test_mode) {
        log_message(ID_CONTROL, "[WAR TEST] LAUNCH CONDITION MET. Initiating launch sequence...");

        // Decide which asset to use (simple example: prefer Silo if available)
        bool launched = false;
        launched = send_secure_launch_command(ID_SILO, target_info); // Try Silo first

        if (!launched) {
             log_message(ID_CONTROL, "[WAR TEST] Silo launch failed or no Silo available. Trying Submarine...");
             launched = send_secure_launch_command(ID_SUB, target_info); // Try Sub if Silo failed/absent
        }

        if (!launched) {
             log_message(ID_CONTROL, "[WAR TEST] Launch command failed for both Silo and Submarine (or none connected).");
        }

    } else if (launch_condition_met && !war_test_mode) {
         log_message(ID_CONTROL, "INFO: Launch condition met, but War Test Mode is OFF. No launch initiated.");
    }
}


// --- Send Secure Launch Command ---
// Sends an encrypted and checksummed launch command to the first available client matching the ID prefix.
// Returns true if command was sent successfully, false otherwise.
bool send_secure_launch_command(const char* target_client_id_prefix, const char* target_info) {
    char command_data_plain[BUFFER_SIZE]; // Plaintext: Command:Target
    char command_payload_encrypted[BUFFER_SIZE]; // Will hold encrypted Command:Target
    char message_to_send[BUFFER_SIZE]; // Full message: TAG:<encrypted>:<checksum>
    unsigned long checksum;
    int target_client_index = -1;
    bool sent = false;

    // 1. Format the command data (CommandType:Data) - this is what gets checksummed and encrypted
    snprintf(command_data_plain, sizeof(command_data_plain), "%s:%s", CMD_LAUNCH, target_info);

    // 2. Calculate checksum based on the *plaintext* command data and secret key
    checksum = simple_checksum(command_data_plain, SHARED_SECRET_KEY);

    // 3. Prepare the payload for encryption (copy plaintext)
    strncpy(command_payload_encrypted, command_data_plain, sizeof(command_payload_encrypted) -1);
    command_payload_encrypted[sizeof(command_payload_encrypted) -1] = '\0';
    size_t payload_len = strlen(command_payload_encrypted); // Length of data to encrypt

    // 4. Encrypt the payload (in-place)
    encrypt_decrypt_xor(command_payload_encrypted, payload_len, SHARED_SECRET_KEY);
    // Note: command_payload_encrypted now holds the encrypted bytes. It might contain nulls.

    // 5. Format the full message (TAG_COMMAND:<EncryptedPayload>:<Checksum>\n)
    //    We need to handle potential nulls in the encrypted payload carefully if sending as a C string.
    //    A safer approach is to know the length and send raw bytes, but for this text protocol:
    //    Let's assume XOR encryption won't create problematic characters for our simple parsing,
    //    but in real crypto, base64 encoding or similar would be needed here.
    snprintf(message_to_send, sizeof(message_to_send), "%s:%s:%lu%c",
             TAG_COMMAND, command_payload_encrypted, checksum, MSG_END);
    // This snprintf might truncate if encrypted payload + checksum is too long. Check buffer sizes.


    // Find the target client (first match) - MUST lock mutex
    pthread_mutex_lock(&clients_mutex);
    for (int i = 0; i < MAX_CLIENTS; ++i) {
        if (clients[i].active && strncmp(clients[i].client_id, target_client_id_prefix, strlen(target_client_id_prefix)) == 0) {
            target_client_index = i;
            break;
        }
    }
    pthread_mutex_unlock(&clients_mutex);


    if (target_client_index == -1) {
        log_message(ID_CONTROL, "ERROR: Cannot send launch command. No active client found with prefix: %s", target_client_id_prefix);
        return false;
    }

    // 6. Send the message
    log_message(ID_CONTROL, "Sending LAUNCH command to %s (Index %d). Target: %s",
                clients[target_client_index].client_id, target_client_index, target_info);
    // log_message(ID_CONTROL, "DEBUG: Final message being sent (payload encrypted): %s", message_to_send);

    // Use the helper function which handles mutex locking implicitly if needed (it doesn't currently, but could)
    send_to_client(target_client_index, message_to_send);
    // Assume send_to_client logs errors if send fails. We consider it "sent" if we reach here.
    sent = true; // Simplification: Assume sent if client was found. Real check involves send() return value.

    return sent;
}


// --- Utility Functions ---

// Initialize the clients array
void initialize_clients() {
    pthread_mutex_lock(&clients_mutex);
    for (int i = 0; i < MAX_CLIENTS; ++i) {
        clients[i].socket_fd = -1;
        clients[i].active = false;
        clients[i].client_id[0] = '\0';
        clients[i].thread_id = 0;
    }
    client_count = 0;
    pthread_mutex_unlock(&clients_mutex);
     log_message(ID_CONTROL, "Client list initialized.");
}

// Add a new client connection
int add_client(int socket_fd, struct sockaddr_in address) {
    pthread_mutex_lock(&clients_mutex);
    int client_index = -1;
    if (client_count >= MAX_CLIENTS) {
        log_message(ID_CONTROL, "WARN: Cannot add client fd %d. Maximum client limit (%d) reached.", socket_fd, MAX_CLIENTS);
        pthread_mutex_unlock(&clients_mutex);
        return -1; // Indicate failure
    }

    // Find an empty slot
    for (int i = 0; i < MAX_CLIENTS; ++i) {
        if (!clients[i].active) {
            clients[i].socket_fd = socket_fd;
            clients[i].address = address;
            clients[i].active = true;
            clients[i].client_id[0] = '\0'; // Clear ID until identified
            clients[i].thread_id = 0; // Thread ID set later when created
            client_index = i;
            client_count++;
            log_message(ID_CONTROL, "INFO: Client fd %d added at index %d. Total clients: %d.", socket_fd, i, client_count);
            break;
        }
    }
    pthread_mutex_unlock(&clients_mutex);

    if (client_index == -1) {
        // This shouldn't happen if client_count was checked correctly, but defensively:
        log_message(ID_CONTROL, "ERROR: Failed to find empty slot for client fd %d despite count check.", socket_fd);
    }
    return client_index;
}

// Remove a client (e.g., on disconnect in handle_client)
void remove_client(int client_index) {
    pthread_mutex_lock(&clients_mutex);
    if (client_index >= 0 && client_index < MAX_CLIENTS && clients[client_index].active) {
        log_message(ID_CONTROL, "INFO: Removing client %s (Index %d, fd %d).",
                    clients[client_index].client_id[0] ? clients[client_index].client_id : "unknown",
                    client_index, clients[client_index].socket_fd);

        clients[client_index].active = false;
        // Socket is closed by the handle_client thread itself before calling remove_client
        clients[client_index].socket_fd = -1; // Mark socket as invalid in our structure
        clients[client_index].client_id[0] = '\0';
        clients[client_index].thread_id = 0; // Reset thread ID
        client_count--;
        log_message(ID_CONTROL, "INFO: Total clients: %d.", client_count);
    } else {
         log_message(ID_CONTROL, "WARN: Attempted to remove inactive or invalid client index %d.", client_index);
    }
    pthread_mutex_unlock(&clients_mutex);
}

// Send a message to a specific client by index
void send_to_client(int client_index, const char *message) {
    int sock_fd = -1;
    char client_id_copy[50] = "unknown";

    pthread_mutex_lock(&clients_mutex);
    if (client_index >= 0 && client_index < MAX_CLIENTS && clients[client_index].active) {
        sock_fd = clients[client_index].socket_fd;
        // Copy ID for logging outside lock
        strncpy(client_id_copy, clients[client_index].client_id, sizeof(client_id_copy)-1);
        client_id_copy[sizeof(client_id_copy)-1] = '\0';
    }
    pthread_mutex_unlock(&clients_mutex);

    if (sock_fd != -1) {
        ssize_t bytes_sent = send(sock_fd, message, strlen(message), 0);
        if (bytes_sent < 0) {
            // Avoid logging spam if client just disconnected. The read thread will handle it.
             if (errno != EPIPE && errno != ECONNRESET) {
                perror("ERROR writing to socket");
                log_message(ID_CONTROL,"ERROR: Failed to send to client %s (Index %d, fd %d): %s", client_id_copy, client_index, sock_fd, strerror(errno));
             } else {
                 log_message(ID_CONTROL,"INFO: Send to client %s (Index %d, fd %d) failed, likely disconnected.", client_id_copy, client_index, sock_fd);
             }
             // Consider marking client for removal here, though read thread usually detects first.
        } else if ((size_t)bytes_sent < strlen(message)) {
             log_message(ID_CONTROL,"WARN: Partial send to client %s (Index %d, fd %d). Sent %zd of %zu bytes.", client_id_copy, client_index, sock_fd, bytes_sent, strlen(message));
        } else {
             // Log successful send for important messages if needed (e.g., commands)
             // log_message(ID_CONTROL,"DEBUG: Sent message to %s (Index %d): %s", client_id_copy, client_index, message);
        }
    } else {
         log_message(ID_CONTROL, "WARN: Attempted to send to inactive/invalid client index %d.", client_index);
    }
}

// Signal handler for graceful shutdown
void signal_handler(int signum) {
    if (signum == SIGINT || signum == SIGTERM) {
        // Use write for signal safety if possible, though printf/log might be okay for simple termination
        const char msg[] = "\nSignal received. Shutting down server...\n";
        write(STDOUT_FILENO, msg, sizeof(msg) - 1);
        log_message(ID_CONTROL, "INFO: Signal %d received. Initiating shutdown...", signum);
        run_server = 0; // Signal loops to stop (atomic write)

        // Close the listening socket here to prevent new connections immediately
        if (server_socket_fd != -1) {
             shutdown(server_socket_fd, SHUT_RDWR); // Stop further send/receive
             close(server_socket_fd);
             server_socket_fd = -1; // Mark as closed
             log_message(ID_CONTROL, "INFO: Listening socket closed.");
        }
        // Client sockets are closed by their respective threads when recv fails or run_server is checked.
    }
}

// Cleanup resources before exiting
void cleanup_server() {
    printf("Cleaning up server resources...\n");
    log_message(ID_CONTROL, "Starting server cleanup...");

    // Close listening socket if not already closed by signal handler
    if (server_socket_fd != -1) {
        close(server_socket_fd);
        server_socket_fd = -1;
        log_message(ID_CONTROL, "INFO: Closed listening socket during cleanup.");
    }

    // Close all active client sockets (signal handler threads should be exiting)
    // This is a failsafe in case threads didn't exit cleanly
    pthread_mutex_lock(&clients_mutex);
    for (int i = 0; i < MAX_CLIENTS; ++i) {
        if (clients[i].active && clients[i].socket_fd != -1) {
            log_message(ID_CONTROL, "INFO: Closing connection to client %s (fd %d) during final cleanup.",
                        clients[i].client_id[0] ? clients[i].client_id : "unknown",
                        clients[i].socket_fd);
            shutdown(clients[i].socket_fd, SHUT_RDWR); // Stop send/receive
            close(clients[i].socket_fd);
            clients[i].socket_fd = -1;
            clients[i].active = false;
        }
    }
    client_count = 0;
    pthread_mutex_unlock(&clients_mutex);

    log_message(ID_CONTROL, "Server cleanup finished.");
}

