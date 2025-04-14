#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/aes.h>

#define SERVER_IP "127.0.0.1"
#define SERVER_PORT 8081
#define LOG_FILE "silo.log"

unsigned char aes_key[32] = "thisisaverysecretkeyforencryption!";

void log_event(const char *event) {
    FILE *fp = fopen(LOG_FILE, "a");
    if (!fp) {
        perror("Log file open failed");
        return;
    }
    time_t now = time(NULL);
    fprintf(fp, "[%s] %s\n", ctime(&now), event);
    fclose(fp);
}

int verify_message(const char *ciphertext, char *plaintext) {
    // Simplified decryption/verification
    if (strncmp(ciphertext, "ENCRYPTED:", 10) == 0) {
        strcpy(plaintext, ciphertext + 10);
        return 1;
    }
    return 0;
}

int parse_command(const char *message, char *command, char *target) {
    // Parse message like "command:launch|target:North Sea"
    char *copy = strdup(message);
    if (!copy) return 0;

    char *token = strtok(copy, "|");
    while (token) {
        char *key = strtok(token, ":");
        char *value = strtok(NULL, ":");
        if (!key || !value) {
            free(copy);
            return 0;
        }
        if (strcmp(key, "command") == 0) strncpy(command, value, 20);
        else if (strcmp(key, "target") == 0) strncpy(target, value, 50);
        token = strtok(NULL, "|");
    }
    free(copy);
    return 1;
}

int main() {
    int sock;
    struct sockaddr_in server_addr;
    char buffer[1024];
    char plaintext[1024];
    char command[20];
    char target[50];

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("Socket creation failed");
        exit(1);
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SERVER_PORT);
    inet_pton(AF_INET, SERVER_IP, &server_addr.sin_addr);

    if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Connection failed");
        close(sock);
        exit(1);
    }

    log_event("Missile Silo connected to Control");

    while (1) {
        int bytes = recv(sock, buffer, sizeof(buffer) - 1, 0);
        if (bytes <= 0) {
            log_event("Connection lost");
            break;
        }
        buffer[bytes] = '\0';

        if (verify_message(buffer, plaintext)) {
            if (parse_command(plaintext, command, target)) {
                if (strcmp(command, "launch") == 0) {
                    char log[512];
                    snprintf(log, sizeof(log), "Launch command verified, target: %s", target);
                    log_event(log);
                    // Simulate launch
                }
            } else {
                log_event("Invalid command format");
            }
        } else {
            log_event("Invalid message received");
        }
    }

    close(sock);
    return 0;
}

