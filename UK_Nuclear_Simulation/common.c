#include "common.h"
#include <stdarg.h>
#include <sys/time.h>

// Global variables (if needed)
static pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;

// Initialize OpenSSL crypto
void init_crypto() {
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
}

// Cleanup OpenSSL
void cleanup_crypto() {
    EVP_cleanup();
    ERR_free_strings();
}

// Log messages to file and stdout
void log_message(const char *message) {
    pthread_mutex_lock(&log_mutex);
    
    FILE *log_file = fopen(LOG_FILE, "a");
    if (log_file) {
        time_t now = time(NULL);
        char *time_str = ctime(&now);
        time_str[strlen(time_str)-1] = '\0'; // Remove newline
        
        fprintf(log_file, "[%s] %s\n", time_str, message);
        fclose(log_file);
    }
    
    printf("[LOG] %s\n", message);
    pthread_mutex_unlock(&log_mutex);
}

// Handle errors (print and optionally exit)
void handle_error(const char *msg, bool fatal) {
    log_message(msg);
    if (fatal) {
        exit(EXIT_FAILURE);
    }
}

// Encrypt a message using AES-256-CBC
int encrypt_message(SecureMessage *msg, const unsigned char *key) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return 0;

    // Generate random IV
    RAND_bytes(msg->iv, IV_SIZE);

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, msg->iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }

    int len;
    int ciphertext_len = 0;

    if (EVP_EncryptUpdate(ctx, (unsigned char *)msg->payload, &len, 
                         (unsigned char *)msg->payload, strlen(msg->payload)) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }
    ciphertext_len += len;

    if (EVP_EncryptFinal_ex(ctx, (unsigned char *)msg->payload + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return 1;
}

// Decrypt a message
int decrypt_message(SecureMessage *msg, const unsigned char *key) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return 0;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, msg->iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }

    int len;
    int plaintext_len = 0;

    if (EVP_DecryptUpdate(ctx, (unsigned char *)msg->payload, &len, 
                         (unsigned char *)msg->payload, strlen(msg->payload)) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }
    plaintext_len += len;

    if (EVP_DecryptFinal_ex(ctx, (unsigned char *)msg->payload + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }
    plaintext_len += len;

    msg->payload[plaintext_len] = '\0';
    EVP_CIPHER_CTX_free(ctx);
    return 1;
}

// Verify message authenticity (HMAC)
int verify_message(SecureMessage *msg, const unsigned char *key) {
    // In a real system, implement HMAC verification here
    return 1; // Placeholder
}

// Generate random key
void generate_random_key(unsigned char *key, int size) {
    RAND_bytes(key, size);
}

