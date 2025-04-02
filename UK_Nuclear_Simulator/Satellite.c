#include "common.h"
#include <sys/socket.h>

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

    printf("Satellite connected to Control\n");

    while (1) {
        Message intel = {INTEL, "Satellite intel: THREAT DETECTED", "", 0};
        snprintf(intel.timestamp, 20, "%ld", time(NULL));
        send(sock, &intel, sizeof(Message), 0);
        sleep(15); // Simulate periodic updates
    }

    close(sock);
    return 0;
}

