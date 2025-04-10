#include "utils.h"
#include "common.h"
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h> // For mkdir
#include <sys/types.h> // For mkdir
#include <errno.h>
#include <stdarg.h> // For va_list, va_start, va_end

// --- Logging ---
// Logs a message to a file named <source_id>.log in the LOG_DIR
void log_message(const char *source_id, const char *format, ...) {
    char filepath[256];
    char timestamp[64];
    time_t now = time(NULL);
    struct tm *t = localtime(&now);

    // Create log directory if it doesn't exist
    // Permissions 0755: user=rwx, group=rx, others=rx
    if (mkdir(LOG_DIR, 0755) == -1) {
        if (errno != EEXIST) {
            perror("Error creating log directory");
            // Continue attempt to log, might work if dir exists
        }
    }

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
    size_t key_len = strlen(key);
    if (key_len == 0) return; // Avoid division by zero

    for (size_t i = 0; i < len; ++i) {
        // XOR each byte of data with a byte from the key (cycling through the key)
        // Ensure we don't XOR the null terminator if len includes it.
        // Be careful if data contains null bytes mid-string.
        data[i] = data[i] ^ key[i % key_len];
    }
    // Note: This modifies the data in-place.
    // If the data contains null bytes, strlen won't work correctly on the result.
    // Best used on data segments where length is known.
}

// --- Simple Checksum for Verification ---
// INSECURE - FOR DEMONSTRATION ONLY
// Combines data and key to create a basic checksum.
unsigned long simple_checksum(const char *data, const char *key) {
    unsigned long hash = 5381; // djb2 hash starting value
    int c;
    size_t i = 0;

    // Hash the data
    while ((c = *data++)) {
        hash = ((hash << 5) + hash) + c; /* hash * 33 + c */
    }

    // Mix in the key
    data = key; // Reset pointer to start of key
    while ((c = *data++)) {
         // Use a different mixing operation for the key
        hash = ((hash << 4) + hash) ^ c; /* hash * 17 ^ c */
    }

    return hash;
}

