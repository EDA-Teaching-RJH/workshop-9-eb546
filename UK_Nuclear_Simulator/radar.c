#include "common.h"

static unsigned char radar_key[KEY_SIZE];

void perform_radar_sweep(int sock, unsigned char *key) {
    const char *reports[] = {
        "Airspace clear",
        "Detected commercial aircraft at 30,000ft",
        "Unidentified contact at 45,000ft bearing 245"
    };
    int idx = rand() % (sizeof(reports) / sizeof(reports[0]));
    SecureMessage msg = { .type = MSG_INTEL, .sender = "RADAR" };
    strncpy(msg.payload, reports[idx], sizeof(msg.payload) - 1);
    msg.payload[sizeof(msg.payload) - 1] = '\0';
    encrypt_message(&msg, key);
    send(sock, &msg, sizeof(msg), 0);
}

int main(void) {
    init_crypto();
    memcpy(radar_key, "SECRET_KEY_RADAR_1234567890", KEY_SIZE);

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) handle_error("Socket creation failed", true);

    struct sockaddr_in serv_addr = { .sin_family = AF_INET, .sin_port = htons(CONTROL_PORT) };
    if (inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr) <= 0) handle_error("Invalid address", true);
    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) handle_error("Connection failed", true);

    log_message("Radar station connected to Control", true);

    SecureMessage msg = { .type = MSG_REGISTER, .sender = "RADAR" };
    strncpy(msg.payload, "Radar operational", sizeof(msg.payload) - 1);
    msg.payload[sizeof(msg.payload) - 1] = '\0';
    encrypt_message(&msg, radar_key);
    send(sock, &msg, sizeof(msg), 0);

    while (1) {
        perform_radar_sweep(sock, radar_key);

        fd_set read_fds;
        FD_ZERO(&read_fds);
        FD_SET(sock, &read_fds);
        struct timeval tv = { .tv_sec = 10, .tv_usec = 0 };
        if (select(sock + 1, &read_fds, NULL, NULL, &tv) > 0 && FD_ISSET(sock, &read_fds)) {
            if (recv(sock, &msg, sizeof(msg), 0) <= 0) {
                handle_error("Connection lost", false);
                break;
            }
            if (verify_message(&msg, radar_key) && decrypt_message(&msg, radar_key)) {
                log_message(msg.payload, true);
            } else {
                log_message("Message verification failed", true);
            }
        }
    }

    close(sock);
    cleanup_crypto();
    return 0;
}
