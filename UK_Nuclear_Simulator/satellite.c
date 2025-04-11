#include "common.h"

static unsigned char satellite_key[KEY_SIZE];

void capture_imagery(int sock, unsigned char *key) {
    const char *reports[] = {
        "No unusual activity detected",
        "Possible missile silo activity",
        "Large military movement detected"
    };
    int idx = rand() % (sizeof(reports) / sizeof(reports[0]));
    SecureMessage msg = { .type = MSG_INTEL, .sender = "SATELLITE" };
    strncpy(msg.payload, reports[idx], sizeof(msg.payload) - 1);
    msg.payload[sizeof(msg.payload) - 1] = '\0';
    encrypt_message(&msg, key);
    send(sock, &msg, sizeof(msg), 0);
}

int main(void) {
    init_crypto();
    memcpy(satellite_key, "SECRET_KEY_SATELLITE_123456", KEY_SIZE);

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) handle_error("Socket creation failed", true);

    struct sockaddr_in serv_addr = { .sin_family = AF_INET, .sin_port = htons(CONTROL_PORT) };
    if (inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr) <= 0) handle_error("Invalid address", true);
    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) handle_error("Connection failed", true);

    log_message("Satellite connected to Control", true);

    SecureMessage msg = { .type = MSG_REGISTER, .sender = "SATELLITE" };
    strncpy(msg.payload, "Satellite operational", sizeof(msg.payload) - 1);
    msg.payload[sizeof(msg.payload) - 1] = '\0';
    encrypt_message(&msg, satellite_key);
    send(sock, &msg, sizeof(msg), 0);

    while (1) {
        if (rand() % 10 < 4) capture_imagery(sock, satellite_key);

        fd_set read_fds;
        FD_ZERO(&read_fds);
        FD_SET(sock, &read_fds);
        struct timeval tv = { .tv_sec = 5, .tv_usec = 0 };
        if (select(sock + 1, &read_fds, NULL, NULL, &tv) > 0 && FD_ISSET(sock, &read_fds)) {
            if (recv(sock, &msg, sizeof(msg), 0) <= 0) {
                handle_error("Connection lost", false);
                break;
            }
            if (verify_message(&msg, satellite_key) && decrypt_message(&msg, satellite_key)) {
                log_message(msg.payload, true);
            } else {
                log_message("Message verification failed", true);
            }
        }
        sleep(5);
    }

    close(sock);
    cleanup_crypto();
    return 0;
}

