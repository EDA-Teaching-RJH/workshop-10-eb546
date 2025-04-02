#include "common.h"
#include <sys/socket.h>

void send_message(int sock, Message *msg) {
    if (msg->encrypted) encrypt_decrypt(msg->payload, ENCRYPTION_KEY);
    send(sock, msg, sizeof(Message), 0);
}

int main() {
    int sock;
    struct sockaddr_in server;

    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Socket creation failed"); exit(EXIT_FAILURE);
    }

    server.sin_family = AF_INET;
    server.sin_port = htons(PORT);
    inet_pton(AF_INET, "127.0.0.1", &server.sin_addr);

    if (connect(sock, (struct sockaddr *)&server, sizeof(server)) < 0) {
        perror("Connection failed"); exit(EXIT_FAILURE);
    }

    printf("Missile Silo connected to Control\n");

    while (1) {
        Message msg;
        int bytes = recv(sock, &msg, sizeof(Message), 0);
        if (bytes <= 0) break;

        if (msg.encrypted) encrypt_decrypt(msg.payload, ENCRYPTION_KEY);
        printf("Received: %s\n", msg.payload);

        if (msg.type == LAUNCH_REQUEST && strcmp(msg.payload, "LAUNCH NOW") == 0) {
            printf("Launching missiles from silo!\n");
            Message status = {STATUS, "Missiles launched", "", 0};
            snprintf(status.timestamp, 20, "%ld", time(NULL));
            send_message(sock, &status);
        }
    }

    close(sock);
    return 0;
}

