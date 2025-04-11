#include "common.h"

static unsigned char submarine_key[KEY_SIZE];
static bool launch_capability = true;
static bool stealth_mode = false;

void launch_missile(const char *target_info) {
    char log_msg[BUFFER_SIZE];
    snprintf(log_msg, sizeof(log_msg), "SUBMARINE: Launching missile at %s", target_info);
    log_message(log_msg, true);
    for (int i = 5; i > 0; i--) {
        snprintf(log_msg, sizeof(log_msg), "Underwater launch in %d...", i);
        log_message(log_msg, true);
        sleep(1);
    }
    log_message("Missile launched! Engaging stealth mode", true);
    stealth_mode = true;
}

void gather_intel(int sock, unsigned char *key) {
    const char *intel_reports[] = {
        "No hostile contacts detected",
        "Commercial shipping traffic normal",
        "Detected possible submarine activity at grid DH-34",
        "Sonar contacts clean",
        "Thermal layer detected at 200m",
        "Possible enemy warship at grid FJ-12"
    };
    int report_idx = rand() % (sizeof(intel_reports) / sizeof(intel_reports[0]));
    SecureMessage msg = { .type = MSG_INTEL, .sender = "SUBMARINE" };
    strncpy(msg.payload, intel_reports[report_idx], sizeof(msg.payload) - 1);
    msg.payload[sizeof(msg.payload) - 1] = '\0';
    encrypt_message(&msg, key);
    send(sock, &msg, sizeof(msg), 0);
}

int main(void) {
    init_crypto();
    memcpy(submarine_key, "SECRET_KEY_SUBMARINE_1234567890", KEY_SIZE);

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) handle_error("Socket creation failed", true);

    struct sockaddr_in serv_addr = { .sin_family = AF_INET, .sin_port = htons(CONTROL_PORT) };
    if (inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr) <= 0) handle_error("Invalid address", true);
    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) handle_error("Connection failed", true);

    log_message("Submarine connected to Control", true);

    SecureMessage msg = { .type = MSG_REGISTER, .sender = "SUBMARINE" };
    strncpy(msg.payload, "Ready for commands", sizeof(msg.payload) - 1);
    msg.payload[sizeof(msg.payload) - 1] = '\0';
    encrypt_message(&msg, submarine_key);
    send(sock, &msg, sizeof(msg), 0);

    while (1) {
        if (rand() % 10 < 3) gather_intel(sock, submarine_key);

        fd_set read_fds;
        FD_ZERO(&read_fds);
        FD_SET(sock, &read_fds);
        struct timeval tv = { .tv_sec = 1, .tv_usec = 0 };
        if (select(sock + 1, &read_fds, NULL, NULL, &tv) > 0 && FD_ISSET(sock, &read_fds)) {
            if (recv(sock, &msg, sizeof(msg), 0) <= 0) {
                handle_error("Connection lost", false);
                break;
            }
            if (verify_message(&msg, submarine_key) && decrypt_message(&msg, submarine_key)) {
                switch (msg.type) {
                    case MSG_LAUNCH_ORDER:
                        if (launch_capability && !stealth_mode) {
                            launch_missile(msg.payload);
                            SecureMessage response = { .type = MSG_LAUNCH_CONFIRM, .sender = "SUBMARINE" };
                            strncpy(response.payload, "Underwater launch completed", sizeof(response.payload) - 1);
                            response.payload[sizeof(response.payload) - 1] = '\0';
                            encrypt_message(&response, submarine_key);
                            send(sock, &response, sizeof(response), 0);
                        } else {
                            log_message("Launch order received but capability offline or in stealth", true);
                        }
                        break;
                    case MSG_STATUS:
                        log_message(msg.payload, true);
                        break;
                    default:
                        log_message("Received unknown message type", true);
                        break;
                }
            } else {
                log_message("Message verification failed - possible security breach!", true);
            }
        }
        sleep(5);
    }

    close(sock);
    cleanup_crypto();
    return 0;
}
