#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <pthread.h>
#include <ctype.h>

#define PORT_SILO 8081
#define PORT_SUB 8082
#define PORT_RADAR 8083
#define PORT_SAT 8084
#define MAX_CLIENTS 4
#define LOG_FILE "control.log"
#define CAESAR_SHIFT 3

typedef struct {
    char source[20];
    char data[256];
    double threat_level;
    char location[50];
} Intel;

void log_event(const char *event_type, const char *details) {
    FILE *fp = fopen(LOG_FILE, "a");
    if (fp == NULL) {
        perror("Log file open failed");
        return;
    }
    time_t now = time(NULL);
    char *time_str = ctime(&now);
    if (time_str) {
        time_str[strlen(time_str) - 1] = '\0'; // Remove newline
        fprintf(fp, "[%s] %-12s %s\n", time_str, event_type, details);
    }
    fclose(fp);
}

void caesar_encrypt(const char *plaintext, char *ciphertext, size_t len) {
    memset(ciphertext, 0, len);
    for (size_t i = 0; i < strlen(plaintext) && i < len - 1; i++) {
        if (isalpha((unsigned char)plaintext[i])) {
            char base = isupper((unsigned char)plaintext[i]) ? 'A' : 'a';
            ciphertext[i] = (char)((plaintext[i] - base + CAESAR_SHIFT) % 26 + base);
        } else {
            ciphertext[i] = plaintext[i];
        }
    }
}

void caesar_decrypt(const char *ciphertext, char *plaintext, size_t len) {
    memset(plaintext, 0, len);
    for (size_t i = 0; i < strlen(ciphertext) && i < len - 1; i++) {
        if (isalpha((unsigned char)ciphertext[i])) {
            char base = isupper((unsigned char)ciphertext[i]) ? 'A' : 'a';
            ciphertext[i] = (char)((ciphertext[i] - base - CAESAR_SHIFT + 26) % 26 + base);
        } else {
            plaintext[i] = ciphertext[i];
        }
    }
}

int parse_intel(const char *message, Intel *intel) {
    char *copy = strdup(message);
    if (!copy) {
        log_event("ERROR", "Memory allocation failed for parsing");
        return 0;
    }

    memset(intel, 0, sizeof(Intel));
    char *token = strtok(copy, "|");
    int valid = 1;
    while (token && valid) {
        char *key = strtok(token, ":");
        char *value = strtok(NULL, ":");
        if (!key || !value) {
            log_event("ERROR", "Malformed key-value pair in message");
            valid = 0;
            break;
        }
        if (strcmp(key, "source") == 0) {
            strncpy(intel->source, value, sizeof(intel->source) - 1);
        } else if (strcmp(key, "data") == 0) {
            strncpy(intel->data, value, sizeof(intel->data) - 1);
        } else if (strcmp(key, "threat_level") == 0) {
            char *endptr;
            intel->threat_level = strtod(value, &endptr);
            if (*endptr != '\0') valid = 0;
        } else if (strcmp(key, "location") == 0) {
            strncpy(intel->location, value, sizeof(intel->location) - 1);
        }
        token = strtok(NULL, "|");
    }
    if (!valid || !intel->source[0]) {
        log_event("ERROR", "Invalid or incomplete intelligence message");
        valid = 0;
    }
    free(copy);
    return valid;
}

void *handle_client(void *arg) {
    int client_sock = *(int *)arg;
    free(arg);
    char buffer[1024];
    char plaintext[1024];
    Intel intel;
    char client_ip[INET_ADDRSTRLEN];
    struct sockaddr_in client_addr;
    socklen_t addr_len = sizeof(client_addr);

    if (getpeername(client_sock, (struct sockaddr *)&client_addr, &addr_len) == 0) {
        inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, sizeof(client_ip));
        char log_msg[512];
        snprintf(log_msg, sizeof(log_msg), "Client connected from %s:%d", 
                 client_ip, ntohs(client_addr.sin_port));
        log_event("CONNECTION", log_msg);
    }

    while (1) {
        ssize_t bytes = recv(client_sock, buffer, sizeof(buffer) - 1, 0);
        if (bytes <= 0) {
            log_event("CONNECTION", "Client disconnected");
            break;
        }
        buffer[bytes] = '\0';

        char log_msg[1024];
        snprintf(log_msg, sizeof(log_msg), "Received encrypted: %s", buffer);
        log_event("MESSAGE", log_msg);

        caesar_decrypt(buffer, plaintext, sizeof(plaintext));
        snprintf(log_msg, sizeof(log_msg), "Decrypted to: %s", plaintext);
        log_event("MESSAGE", log_msg);

        if (parse_intel(plaintext, &intel)) {
            snprintf(log_msg, sizeof(log_msg), 
                     "Source: %s, Data: %s, Threat Level: %.2f, Location: %s",
                     intel.source, intel.data, intel.threat_level, intel.location);
            log_event("THREAT", log_msg);
        } else {
            log_event("ERROR", "Failed to parse intelligence");
        }
    }
    close(client_sock);
    return NULL;
}

void simulate_war_test(int server_sock) {
    Intel intel;
    snprintf(intel.source, sizeof(intel.source), "TEST");
    snprintf(intel.data, sizeof(intel.data), "Simulated enemy launch detected");
    intel.threat_level = (double)(rand() % 100) / 100.0;
    snprintf(intel.location, sizeof(intel.location), "North Sea");

    char log_msg[512];
    snprintf(log_msg, sizeof(log_msg), 
             "Source: %s, Data: %s, Threat Level: %.2f, Location: %s",
             intel.source, intel.data, intel.threat_level, intel.location);
    log_event("WAR_TEST", log_msg);

    if (intel.threat_level > 0.7) {
        char command[256];
        snprintf(command, sizeof(command), "command:launch|target:North Sea");
        char ciphertext[512];
        caesar_encrypt(command, ciphertext, sizeof(ciphertext));
        snprintf(log_msg, sizeof(log_msg), "Issued encrypted command: %s", ciphertext);
        log_event("COMMAND", log_msg);
        snprintf(log_msg, sizeof(log_msg), "Decrypted command: %s", command);
        log_event("COMMAND", log_msg);
    }
}

int start_server(int port) {
    int server_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (server_sock < 0) {
        perror("Socket creation failed");
        return -1;
    }

    struct sockaddr_in server_addr = {0};
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(port);

    int opt = 1;
    if (setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        perror("Setsockopt failed");
        close(server_sock);
        return -1;
    }

    if (bind(server_sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Bind failed");
        close(server_sock);
        return -1;
    }

    if (listen(server_sock, 5) < 0) {
        perror("Listen failed");
        close(server_sock);
        return -1;
    }

    return server_sock;
}

int main(int argc, char *argv[]) {
    int test_mode = 0;
    if (argc > 1 && strcmp(argv[1], "--test") == 0) {
        test_mode = 1;
        srand((unsigned int)time(NULL));
    }

    int ports[] = {PORT_SILO, PORT_SUB, PORT_RADAR, PORT_SAT};
    int server_socks[MAX_CLIENTS];
    pthread_t threads[MAX_CLIENTS];
    size_t thread_count = 0;

    for (int i = 0; i < MAX_CLIENTS; i++) {
        server_socks[i] = start_server(ports[i]);
        if (server_socks[i] < 0) {
            for (int j = 0; j < i; j++) {
                close(server_socks[j]);
            }
            return 1;
        }
        char log_msg[256];
        snprintf(log_msg, sizeof(log_msg), "Server started on port %d", ports[i]);
        log_event("STARTUP", log_msg);
    }

    if (test_mode) {
        simulate_war_test(server_socks[0]);
    }

    for (int i = 0; i < MAX_CLIENTS; i++) {
        struct sockaddr_in client_addr;
        socklen_t addr_len = sizeof(client_addr);
        int client_sock = accept(server_socks[i], (struct sockaddr *)&client_addr, &addr_len);
        if (client_sock < 0) {
            perror("Accept failed");
            continue;
        }

        int *client_sock_ptr = malloc(sizeof(int));
        if (!client_sock_ptr) {
            perror("Memory allocation failed");
            close(client_sock);
            continue;
        }
        *client_sock_ptr = client_sock;

        if (pthread_create(&threads[thread_count], NULL, handle_client, client_sock_ptr) != 0) {
            perror("Thread creation failed");
            free(client_sock_ptr);
            close(client_sock);
            continue;
        }
        thread_count++;
    }

    for (size_t i = 0; i < thread_count; i++) {
        pthread_join(threads[i], NULL);
    }

    for (int i = 0; i < MAX_CLIENTS; i++) {
        close(server_socks[i]);
    }

    log_event("SHUTDOWN", "Nuclear Control terminated");
    return 0;
}

