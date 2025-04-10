// utils.c

// Standard library includes first
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>
#include <stdarg.h>
#include <stdlib.h> // Added for EXIT_FAILURE potentially used in error paths

// ---> ADD OR ENSURE THESE PROJECT HEADERS ARE PRESENT <---
#include "common.h" // <<< This line defines LOG_DIR
#include "utils.h"  // <<< Include its own header (good practice)
// ---> END OF ADDED LINES <---


// --- Logging ---
// Logs a message to a file named <source_id>.log in the LOG_DIR
void log_message(const char *source_id, const char *format, ...) {
    char filepath[256];
    char timestamp[64];
    time_t now = time(NULL);
    struct tm *t = localtime(&now);

    // Create log directory if it doesn't exist
    // Permissions 0755: user=rwx, group=rx, others=rx
    // ***** LOG_DIR is used here *****
    if (mkdir(LOG_DIR, 0755) == -1) {
        if (errno != EEXIST) {
            perror("Error creating log directory");
            // Continue attempt to log, might work if dir exists
        }
    }

    // ***** LOG_DIR is used here *****
    snprintf(filepath, sizeof(filepath), "%s/%s.log", LOG_DIR, source_id);

    FILE *logfile = fopen(filepath, "a"); // Append mode
    if (!logfile) {
        perror("Error opening log file");
        fprintf(stderr, "Failed to open log: %s\n", filepath);
        return;
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

    fflush(logfile); // Ensure data is written to disk
    fclose(logfile);
}


// --- Simple XOR Encryption/Decryption ---
// INSECURE - FOR DEMONSTRATION ONLY
void encrypt_decrypt_xor(char *data, size_t len, const char *key) {
    // ... (rest of the function)
}

// --- Simple Checksum for Verification ---
// INSECURE - FOR DEMONSTRATION ONLY
unsigned long simple_checksum(const char *data, const char *key) {
   // ... (rest of the function)
}