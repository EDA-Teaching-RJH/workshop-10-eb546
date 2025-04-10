#ifndef COMMON_H
#define COMMON_H

#include <stddef.h>
#include <openssl/evp.h>
#include <pthread.h>

typedef struct {
    char* data;
    size_t length;
} SecureMessage;

// Message functions
SecureMessage* create_secure_message(const char* data, size_t length);
void free_secure_message(SecureMessage* msg);

// File functions
int encrypt_file(const char* input_path, const char* output_path, const unsigned char* key);

// Logging functions
void log_message(const char* message);

// System functions
void initialize_common();
void cleanup_common();

#endif