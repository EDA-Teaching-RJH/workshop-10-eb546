#include "common.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <pthread.h>

#define MAX_CLIENTS 4 // missileSilo, submarine, radar, satellite

void log_message(const char *msg) {
    FILE *log = fopen("logs/control_log.txt", "a");
    if (!log) return;
    time_t now; time(&now);
    fprintf(log, "[%s] %s\n", ctime(&now), msg);
    fclose(log);
}

void *handle_client(void *client_socket) {
    int sock = *(int *)client_socket;
    free(client_socket);
    char buffer[BUFFER_SIZE];
    
    while (1) {
        int bytes = recv(sock, buffer, BUFFER_SIZE, 0);
        if (bytes <= 0) break;

        Message msg;
        memcpy(&msg, buffer, sizeof(Message));
        if (msg.encrypted) encrypt_decrypt(msg.payload, ENCRYPTION_KEY);

        log_message(msg.payload);
        printf("Received: %s\n", msg.payload);

        // War test mode decision logic
        if (strstr(msg.payload, "THREAT DETECTED") && rand() % 2) {
            Message launch = {LAUNCH_REQUEST, "LAUNCH NOW", "", 1};
            snprintf(launch.timestamp, 20, "%ld", time(NULL));
            encrypt_decrypt(launch.payload, ENCRYPTION_KEY);
            send(sock, &launch, sizeof(Message), 0);
        }
    }
    close(sock);
    return NULL;
}

int main(int argc, char *argv[]) {
    int test_mode = (argc > 1 && strcmp(argv[1], "--test") == 0);
    srand(time(NULL));

    int server_fd, client_fd;
    struct sockaddr_in address;
    int addrlen = sizeof(address);

    // Socket setup
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("Socket failed"); exit(EXIT_FAILURE);
    }

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("Bind failed"); exit(EXIT_FAILURE);
    }
    if (listen(server_fd, MAX_CLIENTS) < 0) {
        perror("Listen failed"); exit(EXIT_FAILURE);
    }

    printf("Nuclear Control Server running%s\n", test_mode ? " in test mode" : "");

    while (1) {
        if ((client_fd = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen)) < 0) {
            perror("Accept failed"); continue;
        }

        int *client_sock = malloc(sizeof(int));
        *client_sock = client_fd;
        pthread_t thread;
        pthread_create(&thread, NULL, handle_client, client_sock);
        pthread_detach(thread);
    }

    close(server_fd);
    return 0;
}

