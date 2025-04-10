#ifndef COMMON_H
#define COMMON_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>       // For timestamps
#include <stdbool.h>    // For bool type
#include <errno.h>      // For errno
#include <stdarg.h>     // For va_list in logging

// --- Configuration ---
#define SERVER_IP "127.0.0.1" // Loopback for local testing
#define SERVER_PORT 65001     // Choose an available port
#define MAX_CLIENTS 5
#define BUFFER_SIZE 1024
#define LOG_DIR "logs"        // Relative path for log directory

// --- Shared Secret Key (HIGHLY INSECURE - FOR DEMO ONLY) ---
#define SHARED_SECRET_KEY "TridentSuperSecretCode123!" // Replace with something complex in a real (non-demo) scenario

// --- Message Tags/Types ---
#define MSG_TYPE_SEP ':'
#define MSG_END '\n'          // Use newline as message terminator

// Client -> Server
#define TAG_IDENTIFY "IDENTIFY" // Payload: SILO | SUB | RADAR | SAT
#define TAG_INTEL "INTEL"       // Payload: <Source>:<Data>
#define TAG_STATUS "STATUS"     // Payload: <Source>:OK | READY | LAUNCHED | ERROR <details> | ON_PATROL | OPERATIONAL | NOMINAL
#define TAG_LAUNCH_ACK "LAUNCH_ACK" // Payload: <Source>:SUCCESS | FAILURE <reason>

// Server -> Client (Especially Silo/Sub)
#define TAG_COMMAND "CMD"       // Payload: <EncryptedPayload>:<Checksum>
// Inside Encrypted Payload (after decryption)
#define CMD_LAUNCH "LAUNCH"     // Data: <TargetInfo>
#define CMD_STANDDOWN "STANDDOWN" // Data: <Reason>
#define CMD_QUERY_STATUS "QUERY_STATUS" // Data: - (No specific data needed)

// Client Identifiers (used in IDENTIFY and subsequent messages)
#define ID_SILO "SILO"
#define ID_SUB "SUBMARINE"
#define ID_RADAR "RADAR"
#define ID_SAT "SATELLITE"
#define ID_CONTROL "CONTROL"    // For logging from control itself

// --- Function Prototypes (from utils.c) ---
void log_message(const char *source_id, const char *format, ...);
void encrypt_decrypt_xor(char *data, size_t len, const char *key);
unsigned long simple_checksum(const char *data, const char *key); // Simple verification checksum
bool create_log_directory();

// --- Utility Macros ---
#define UNUSED(x) (void)(x) // Suppress unused parameter warnings

#endif // COMMON_H

