#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>

#define SERVER_IP "127.0.0.1"
#define SERVER_PORT 8081
#define LOG_FILE "silo.log"

void log_event(const char *event) {
    FILE *fp = fopen(LOG_FILE, "a");
    if (fp == NULL) {
        perror("Log file open failed");
        return;
    }
    time_t now = time(NULL);
    char *time_str = ctime(&now);
    if (time_str) {
        time_str[strlen(time_str) - 1] = '\0';
        fprintf(fp, "[%s] %s\n", time_str, event);
    }
    fclose(fp);
}

int verify_message(const char *ciphertext, char *plaintext, size_t len) {
    if (strncmp(ciphertext, "ENCRYPTED:", 10) == 0) {
        strncpy(plaintext, ciphertext + 10, len - 1);
        plaintext[len - 1] = '\0';
        return 1;
    }
    return 0;
}

int parse_command(const char *message, char *command, char *target) {
    char *copy = strdup(message);
    if (!copy) {
        return 0;
    }

    command[0] = '\0';
    target[0] = '\0';
    char *token = strtok(copy, "|");
    while (token) {
        char *key = strtok(token, ":");
        char *value = strtok(NULL, ":");
        if (!key || !value) {
            free(copy);
            return 0;
        }
        if (strcmp(key, "command") == 0) {
            strncpy(command, value, 19);
            command[19] = '\0';
        } else if (strcmp(key, "target") == 0) {
            strncpy(target, value, 49);
            target[49] = '\0';
        }
        token = strtok(NULL, "|");
    }
    free(copy);
    return command[0] != '\0';
}

int main(void) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("Socket creation failed");
        return 1;
    }

    struct sockaddr_in server_addr = {0};
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SERVER_PORT);
    if (inet_pton(AF_INET, SERVER_IP, &server_addr.sin_addr) <= 0) {
        perror("Invalid address");
        close(sock);
        return 1;
    }

    if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Connection failed");
        close(sock);
        return 1;
    }

    log_event("Missile Silo connected to Control");

    char buffer[1024];
    char plaintext[1024];
    char command[20];
    char target[50];

    while (1) {
        ssize_t bytes = recv(sock, buffer, sizeof(buffer) - 1, 0);
        if (bytes <= 0) {
            log_event("Connection lost");
            break;
        }
        buffer[bytes] = '\0';

        if (verify_message(buffer, plaintext, sizeof(plaintext))) {
            if (parse_command(plaintext, command, target)) {
                if (strcmp(command, "launch") == 0) {
                    char log[512];
                    snprintf(log, sizeof(log), "Launch command verified, target: %s", target);
                    log_event(log);
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

