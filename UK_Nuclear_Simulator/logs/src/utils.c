#include "utils.h"
#include "common.h"
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h> // For mkdir
#include <sys/types.h> // For mkdir
#include <errno.h>
#include <stdarg.h> // For va_list, va_start, va_end
#include <stdlib.h> // For exit, EXIT_FAILURE


// --- Log Directory Handling ---
// Attempts to create the log directory. Returns true on success or if exists, false on error.
bool create_log_directory() {
    // Permissions 0755: user=rwx, group=rx, others=rx
    if (mkdir(LOG_DIR, 0755) == -1) {
        if (errno != EEXIST) {
            perror("Error creating log directory");
            fprintf(stderr, "FATAL: Could not create log directory '%s'. Exiting.\n", LOG_DIR);
            return false;
        }
        // Directory already exists, which is fine.
    }
    return true;
}


// --- Logging ---
// Logs a message to a file named <source_id>.log in the LOG_DIR
void log_message(const char *source_id, const char *format, ...) {
    // Basic check to prevent logging before directory is ensured
    // In a real app, logging might need its own initialization sequence.
    static bool log_dir_checked = false;
    if (!log_dir_checked) {
       if(!create_log_directory()) {
           fprintf(stderr, "Logging disabled due to directory creation failure.\n");
           return; // Cannot log if directory fails
       }
       log_dir_checked = true;
    }

    char filepath[256];
    char timestamp[64];
    time_t now = time(NULL);
    struct tm *t = localtime(&now);

    snprintf(filepath, sizeof(filepath), "%s/%s.log", LOG_DIR, source_id);

    FILE *logfile = fopen(filepath, "a"); // Append mode
    if (!logfile) {
        perror("Error opening log file");
        fprintf(stderr, "Failed to open log: %s\n", filepath);
        return; // Can't log if file opening fails
    }

    // Format timestamp
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", t);

    // Print timestamp and source ID
    fprintf(logfile, "[%s] [%s] ", timestamp, source_id);

    // Print the formatted message using varargs
    va_list args;
    va_start(args, format);
    vfprintf(logfile, format, args);
    va_end(args);

    fprintf(logfile, "\n"); // Add newline

    fflush(logfile); // Ensure data is written to disk immediately
    fclose(logfile);
}


// --- Simple XOR Encryption/Decryption ---
// INSECURE - FOR DEMONSTRATION ONLY
void encrypt_decrypt_xor(char *data, size_t len, const char *key) {
    size_t key_len = strlen(key);
    if (key_len == 0 || data == NULL || len == 0) return; // Basic safety checks

    for (size_t i = 0; i < len; ++i) {
        // XOR each byte of data with a byte from the key (cycling through the key)
        data[i] = data[i] ^ key[i % key_len];
    }
    // Note: Modifies data in-place. Assumes 'len' is the correct length
    // of the data segment to be encrypted/decrypted, excluding any null terminator
    // unless explicitly included in 'len'.
}

// --- Simple Checksum for Verification ---
// INSECURE - FOR DEMONSTRATION ONLY
// Combines data and key to create a basic checksum.
unsigned long simple_checksum(const char *data, const char *key) {
    unsigned long hash = 5381; // djb2 hash starting value
    int c;
    size_t i = 0;

    if (!data || !key) return 0; // Basic safety check

    // Hash the data
    while ((c = *data++) != '\0') { // Process until null terminator
        hash = ((hash << 5) + hash) + c; /* hash * 33 + c */
    }

    // Mix in the key - Start hashing the key from the beginning
    const char *key_ptr = key;
    while ((c = *key_ptr++) != '\0') {
         // Use a different mixing operation for the key
        hash = ((hash << 4) + hash) ^ c; /* hash * 17 ^ c */
    }

    return hash;
}

