#include "common.h"
#include <stdarg.h>
#include <sys/time.h>

// Function implementations...

void log_message(const char *message) {
    pthread_mutex_lock(&log_mutex);
    
    FILE *log_file = fopen(LOG_FILE, "a");
    if (log_file) {
        time_t now = time(NULL);
        char *time_str = ctime(&now);
        time_str[strlen(time_str)-1] = '\0';
        
        char log_entry[BUFFER_SIZE * 2];
        snprintf(log_entry, sizeof(log_entry), "[%s] %s", time_str, message);
        
        if (ENCRYPT_LOGS) {
            SecureMessage encrypted_log;
            strcpy(encrypted_log.sender, "LOGGER");
            strcpy(encrypted_log.payload, log_entry);
            if (encrypt_message(&encrypted_log, control_key)) {
                fwrite(&encrypted_log, sizeof(encrypted_log), 1, log_file);
            }
        } else {
            fputs(log_entry, log_file);
        }
        
        fclose(log_file);
    }
    
    printf("[LOG] %s\n", message);
    pthread_mutex_unlock(&log_mutex);
}

int verify_message(SecureMessage *msg, const unsigned char *key) {
    // Actual HMAC verification implementation
    return 1; // Placeholder for simplicity
}

