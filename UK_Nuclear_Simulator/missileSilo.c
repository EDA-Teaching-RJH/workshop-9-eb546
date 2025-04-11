#include "common.h"

static uint8_t silo_key[KEY_SIZE];
static bool launch_capability = true;

void launch_missile(const char *target_info) {
    char log_msg[BUFFER_SIZE];
    snprintf(log_msg, sizeof(log_msg), "MISSILE SILO: Launching missile at %s", target_info);
    log_message(log_msg, true);
    for (int i = 5; i > 0; i--) {
        snprintf(log_msg, sizeof(log_msg), "Launch in %d...", i);
        log_message(log_msg, true);
        sleep(1);
    }
    log_message("Missile launched!", true);
}

int main(void) {
    // Use a fixed key for simplicity
    memcpy(silo_key, "SECRET_KEY_MISSILE_SILO_1234567890", KEY_SIZE);

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) handle_error("Socket creation failed", true);

    struct sockaddr_in serv_addr = { .sin_family = AF_INET, .sin_port = htons(CONTROL_PORT) };
    if (inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr) <= 0) handle_error("Invalid address", true);
    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) handle_error("Connection failed", true);

    log_message("Missile Silo connected to Control", true);

    SecureMessage msg = { .type = MSG_REGISTER, .sender = "MISSILE_SILO" };
    strncpy(msg.payload, "Ready for commands", sizeof(msg.payload) - 1);
    msg.payload[sizeof(msg.payload) - 1] = '\0';
    encrypt_message(&msg, silo_key);
    send(sock, &msg, sizeof(msg), 0);

    while (1) {
        if (recv(sock, &msg, sizeof(msg), 0) <= 0) {
            handle_error("Connection lost", false);
            break;
        }
        if (verify_message(&msg, silo_key) && decrypt_message(&msg, silo_key)) {
            switch (msg.type) {
                case MSG_LAUNCH_ORDER:
                    if (launch_capability) {
                        launch_missile(msg.payload);
                        SecureMessage response = { .type = MSG_LAUNCH_CONFIRM, .sender = "MISSILE_SILO" };
                        strncpy(response.payload, "Launch sequence completed", sizeof(response.payload) - 1);
                        response.payload[sizeof(response.payload) - 1] = '\0';
                        encrypt_message(&response, silo_key);
                        send(sock, &response, sizeof(response), 0);
                    } else {
                        log_message("Launch order received but capability offline", true);
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

    close(sock);
    return 0;
}
