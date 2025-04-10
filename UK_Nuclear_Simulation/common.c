#include "common.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <openssl/evp.h>
#include <pthread.h>

// Constants
#define BUFFER_SIZE 1024
#define IV_SIZE 16
#define LOG_FILE "system.log"
#define ENCRYPT_LOGS 1

// Global variables
pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;
unsigned char control_key[32];

// SecureMessage structure implementation
SecureMessage* create_secure_message(const char* data, size_t length) {
    SecureMessage* msg = (SecureMessage*)malloc(sizeof(SecureMessage));
    if (!msg) return NULL;

    msg->data = (char*)malloc(length);
    if (!msg->data) {
        free(msg);
        return NULL;
    }

    memcpy(msg->data, data, length);
    msg->length = length;
    return msg;
}

void free_secure_message(SecureMessage* msg) {
    if (msg) {
        if (msg->data) free(msg->data);
        free(msg);
    }
}

// File encryption/decryption functions
int encrypt_file(const char* input_path, const char* output_path, const unsigned char* key) {
    FILE *input_file = fopen(input_path, "rb");
    FILE *output_file = fopen(output_path, "wb");
    if (!input_file || !output_file) return 0;

    unsigned char iv[IV_SIZE];
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    
    // Write IV to output file
    fwrite(iv, 1, IV_SIZE, output_file);

    unsigned char in_buf[BUFFER_SIZE], out_buf[BUFFER_SIZE + EVP_MAX_BLOCK_LENGTH];
    int bytes_read, out_len;

    while ((bytes_read = fread(in_buf, 1, BUFFER_SIZE, input_file))) {
        EVP_EncryptUpdate(ctx, out_buf, &out_len, in_buf, bytes_read);
        fwrite(out_buf, 1, out_len, output_file);
    }

    EVP_EncryptFinal_ex(ctx, out_buf, &out_len);
    fwrite(out_buf, 1, out_len, output_file);

    EVP_CIPHER_CTX_free(ctx);
    fclose(input_file);
    fclose(output_file);
    return 1;
}

// Logging functions
void log_message(const char* message) {
    pthread_mutex_lock(&log_mutex);
    
    FILE* log_file = fopen(LOG_FILE, "a");
    if (!log_file) {
        pthread_mutex_unlock(&log_mutex);
        return;
    }

    time_t now = time(NULL);
    char time_buf[26];
    ctime_r(&now, time_buf);
    time_buf[strlen(time_buf)-1] = '\0'; // Remove newline

    fprintf(log_file, "[%s] %s\n", time_buf, message);
    fclose(log_file);
    
    pthread_mutex_unlock(&log_mutex);
}

// Initialization function
void initialize_common() {
    // Initialize control key (in real use, this would be properly secured)
    memset(control_key, 0xAA, sizeof(control_key));
    
    // Initialize log file
    FILE* log_file = fopen(LOG_FILE, "w");
    if (log_file) fclose(log_file);
    
    log_message("System initialized");
}

// Cleanup function
void cleanup_common() {
    log_message("System shutting down");
    // Additional cleanup if needed
}

