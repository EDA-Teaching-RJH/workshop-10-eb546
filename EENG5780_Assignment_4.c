#ifndef COMMON_H
#define COMMON_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <time.h>

#define PORT 8080
#define BUFFER_SIZE 1024
#define ENCRYPTION_KEY "SECRET_UK_KEY" // Simple XOR key (expand for real encryption)

// Message types
enum MessageType {
    INTEL = 1,
    LAUNCH_REQUEST = 2,
    STATUS = 3
};

// Message structure
typedef struct {
    enum MessageType type;
    char payload[BUFFER_SIZE];
    char timestamp[20];
    int encrypted; // 1 if encrypted, 0 if not
} Message;

// Simple XOR encryption (for demonstration; use AES in production)
void encrypt_decrypt(char *data, const char *key);

#endif

