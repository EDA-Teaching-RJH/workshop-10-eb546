#ifndef UTILS_H
#define UTILS_H

#include <stddef.h> // For size_t

// Function prototypes are already in common.h to be accessible by all modules
// This file could contain declarations specific only to utils.c if needed,
// but for this project, common.h is sufficient.

#endif // UTILS_H

// common.h OR utils.h (replace the old declaration with this)

#ifndef COMMON_H // Or UTILS_H
#define COMMON_H // Or UTILS_H

// ... other includes and defines ...
#include <stdarg.h> // Often good practice when dealing with varargs prototypes

// --- Function Prototypes (from utils.c) ---
// Corrected prototype for log_message
void log_message(const char *source_id, const char *format, ...);

void encrypt_decrypt_xor(char *data, size_t len, const char *key);
unsigned long simple_checksum(const char *data, const char *key);

// ... rest of the file ...

#endif // COMMON_H or UTILS_H