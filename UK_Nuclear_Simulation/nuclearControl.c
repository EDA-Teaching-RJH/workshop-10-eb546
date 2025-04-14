#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <pthread.h>

#define PORT_SILO 8081
#define PORT_SUB 8082
#define PORT_RADAR 8083
#define PORT_SAT 8084
#define MAX_CLIENTS 4
#define LOG_FILE "control.log"

typedef struct {
    char source[20];
    char data[256];
    double threat_level;
    char location[50];
} Intel;

void log_event(const char *event) {
    FILE *fp = fopen(LOG_FILE, "a");
    if (fp == NULL) {
        perror("Log file open failed");
        return;
    }
    time_t now = time(NULL);
    char *time_str = ctime(&now);
    if (time_str) {
        time_str[strlen(time_str) - 1] = '\0'; // Remove newline
        fprintf(fp, "[%s] %s\n", time_str, event);
    }
    fclose(fp);
}

void encrypt_message(const char *plaintext, char *ciphertext, size_t len) {
    snprintf(ciphertext, len, "ENCRYPTED:%s", plaintext);
}

int parse_intel(const char *message, Intel *intel) {
    char *copy = strdup(message);
    if (!copy) {
        return 0;
    }

    memset(intel, 0, sizeof(Intel));
    char *token = strtok(copy, "|");
    while (token) {
        char *key = strtok(token, ":");
        char *value = strtok(NULL, ":");
        if (!key || !value) {
            free(copy);
            return 0;
        }
        if (strcmp(key, "source") == 0) {
            strncpy(intel->source, value, sizeof(intel->source) - 1);
        } else if (strcmp(key, "data") == 0) {
            strncpy(intel->data, value, sizeof(intel->data) - 1);
        } else if (strcmp(key, "threat_level") == 0) {
            intel->threat_level = atof(value);
        } else if (strcmp(key, "location") == 0) {
            strncpy(intel->location, value, sizeof(intel->location) - 1);
        }
        token = strtok(NULL, "|");
    }
    free(copy);
    return 1;
}

void *handle_client(void *arg) {
    int client_sock = *(int *)arg;
    free(arg); // Free allocated memory immediately
    char buffer[1024];
    Intel intel;

    while (1) {
        ssize_t bytes = recv(client_sock, buffer, sizeof(buffer) - 1, 0);
        if (bytes <= 0) {
            log_event("Client disconnected");
            break;
        }
        buffer[bytes] = '\0';

        if (parse_intel(buffer, &intel)) {
            char log[512];
            snprintf(log, sizeof(log), "Received intel from %s: %s, threat: %.2f",
                     intel.source, intel.data, intel.threat_level);
            log_event(log);
        } else {
            log_event("Invalid message format");
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

    char log[512];
    snprintf(log, sizeof(log), "War test intel: %s, threat: %.2f", intel.data, intel.threat_level);
    log_event(log);

    if (intel.threat_level > 0.7) {
        char command[256];
        snprintf(command, sizeof(command), "command:launch|target:North Sea");
        char ciphertext[512];
        encrypt_message(command, ciphertext, sizeof(ciphertext));
        log_event("Launch command issued");
        // Simulate sending to clients (not implemented for simplicity)
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

    // Start servers for each client type
    for (int i = 0; i < MAX_CLIENTS; i++) {
        server_socks[i] = start_server(ports[i]);
        if (server_socks[i] < 0) {
            for (int j = 0; j < i; j++) {
                close(server_socks[j]);
            }
            return 1;
        }
    }

    log_event("Nuclear Control started");

    if (test_mode) {
        simulate_war_test(server_socks[0]);
    }

    // Accept clients
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

    // Join threads (in practice, handle dynamically)
    for (size_t i = 0; i < thread_count; i++) {
        pthread_join(threads[i], NULL);
    }

    // Close sockets
    for (int i = 0; i < MAX_CLIENTS; i++) {
        close(server_socks[i]);
    }

    return 0;
}
