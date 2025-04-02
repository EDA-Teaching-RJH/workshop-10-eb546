#include "common.h"
#include <sys/socket.h>

void send_intel(int sock) {
    Message intel = {INTEL, "Submarine intel: Enemy fleet spotted", "", 0};
    snprintf(intel.timestamp, 20, "%ld", time(NULL));
    send(sock, &intel, sizeof(Message), 0);
}

int main() {
    int sock;
    struct sockaddr_in server;

    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Socket failed"); exit(EXIT_FAILURE);
    }

    server.sin_family = AF_INET;
    server.sin_port = htons(PORT);
    inet_pton(AF_INET, "127.0.0.1", &server.sin_addr);

    if (connect(sock, (struct sockaddr *)&server, sizeof(server)) < 0) {
        perror("Connection failed"); exit(EXIT_FAILURE);
    }

    printf("Submarine connected to Control\n");

    while (1) {
        send_intel(sock);
        Message msg;
        int bytes = recv(sock, &msg, sizeof(Message), 0);
        if (bytes <= 0) break;

        if (msg.encrypted) encrypt_decrypt(msg.payload, ENCRYPTION_KEY);
        if (msg.type == LAUNCH_REQUEST && strcmp(msg.payload, "LAUNCH NOW") == 0) {
            printf("Launching missiles from submarine!\n");
        }
        sleep(5); // Simulate periodic updates
    }

    close(sock);
    return 0;
}

