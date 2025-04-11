#include "common.h"

static uint8_t control_key[KEY_SIZE];
static Target targets[MAX_TARGETS];
static int target_count = 0;
static bool test_mode = false;
static pthread_mutex_t target_mutex = PTHREAD_MUTEX_INITIALIZER;

void load_targets(void) {
    FILE *file = fopen("targets.dat", "rb");
    if (file) {
        pthread_mutex_lock(&target_mutex);
        target_count = fread(targets, sizeof(Target), MAX_TARGETS, file);
        pthread_mutex_unlock(&target_mutex);
        fclose(file);
        log_message("Loaded targets from file", true);
    } else {
        log_message("No targets file found, starting with empty target list", true);
    }
}

void save_targets(void) {
    FILE *file = fopen("targets.dat", "wb");
    if (file) {
        pthread_mutex_lock(&target_mutex);
        fwrite(targets, sizeof(Target), target_count, file);
        pthread_mutex_unlock(&target_mutex);
        fclose(file);
        log_message("Saved targets to file", true);
    }
}

void process_message(int client_socket, SecureMessage *msg) {
    if (!msg) return;
    char log_msg[BUFFER_SIZE];
    switch (msg->type) {
        case MSG_REGISTER:
            snprintf(log_msg, sizeof(log_msg), "%s registered with control", msg->sender);
            log_message(log_msg, true);
            SecureMessage response = { .type = MSG_STATUS, .sender = "CONTROL" };
            strncpy(response.payload, "Registered successfully", sizeof(response.payload) - 1);
            response.payload[sizeof(response.payload) - 1] = '\0';
            encrypt_message(&response, control_key);
            send(client_socket, &response, sizeof(response), 0);
            break;
        case MSG_INTEL:
            snprintf(log_msg, sizeof(log_msg), "Intel from %s: %s", msg->sender, msg->payload);
            log_message(log_msg, true);
            if (test_mode && rand() % 100 < 30 && target_count > 0) {
                log_message("TEST MODE: Simulated threat detected!", true);
                pthread_mutex_lock(&target_mutex);
                int target_idx = rand() % target_count;
                Target target = targets[target_idx];
                pthread_mutex_unlock(&target_mutex);
                const char *platform = (target.longitude < -30) ? "SUBMARINE" : "MISSILE_SILO";
                snprintf(log_msg, sizeof(log_msg), "TEST MODE: Launching nuclear strike on %s via %s", target.name, platform);
                log_message(log_msg, true);
                SecureMessage launch_order = { .type = MSG_LAUNCH_ORDER, .sender = "CONTROL" };
                snprintf(launch_order.payload, sizeof(launch_order.payload), "TARGET:%s,LAT:%f,LON:%f", target.name, target.latitude, target.longitude);
                encrypt_message(&launch_order, control_key);
                send(client_socket, &launch_order, sizeof(launch_order), 0);
            }
            break;
        case MSG_DECRYPT_LOGS:
            decrypt_log_file(LOG_FILE, LOG_ENCRYPTION_KEY);
            break;
        case MSG_LAUNCH_CONFIRM:
            snprintf(log_msg, sizeof(log_msg), "Launch confirmed by %s: %s", msg->sender, msg->payload);
            log_message(log_msg, true);
            break;
        default:
            snprintf(log_msg, sizeof(log_msg), "Unknown message type: %d", (int)msg->type);
            log_message(log_msg, true);
            break;
    }
}

void *handle_client(void *arg) {
    int client_socket = *(int *)arg;
    free(arg);
    SecureMessage msg;
    while (recv(client_socket, &msg, sizeof(msg), 0) > 0) {
        if (verify_message(&msg, control_key)) {
            decrypt_message(&msg, control_key);
            process_message(client_socket, &msg);
        } else {
            log_message("Message verification failed - possible security breach!", true);
        }
    }
    close(client_socket);
    return NULL;
}

int main(int argc, char *argv[]) {
    test_mode = (argc > 1 && strcmp(argv[1], "--test") == 0);
    if (test_mode) log_message("TEST MODE ACTIVATED - Simulated war scenario", true);

    generate_random_key(control_key, KEY_SIZE);
    load_targets();

    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) handle_error("Socket creation failed", true);

    int opt = 1;
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) handle_error("Setsockopt failed", true);

    struct sockaddr_in address = { .sin_family = AF_INET, .sin_addr.s_addr = INADDR_ANY, .sin_port = htons(CONTROL_PORT) };
    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) handle_error("Bind failed", true);
    if (listen(server_fd, MAX_CLIENTS) < 0) handle_error("Listen failed", true);

    log_message("Nuclear Control Center operational and listening for connections", true);

    while (1) {
        int addrlen = sizeof(address);
        int new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t *)&addrlen);
        if (new_socket < 0) {
            handle_error("Accept failed", false);
            continue;
        }

        char ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &address.sin_addr, ip_str, INET_ADDRSTRLEN);
        char log_msg[100];
        snprintf(log_msg, sizeof(log_msg), "New connection from %s", ip_str);
        log_message(log_msg, true);

        int *client_socket = malloc(sizeof(int));
        if (!client_socket) {
            handle_error("Memory allocation failed", false);
            close(new_socket);
            continue;
        }
        *client_socket = new_socket;

        pthread_t thread_id;
        if (pthread_create(&thread_id, NULL, handle_client, client_socket) < 0) {
            handle_error("Thread creation failed", false);
            free(client_socket);
            close(new_socket);
        } else {
            pthread_detach(thread_id);
        }
    }

    close(server_fd);
    save_targets();
    return 0;
}