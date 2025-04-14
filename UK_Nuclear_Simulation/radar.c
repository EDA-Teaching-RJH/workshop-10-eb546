#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>

#define SERVER_IP "127.0.0.1"
#define SERVER_PORT 8083
#define LOG_FILE "radar.log"

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

void encrypt_message(const char *plaintext, char *ciphertext, size_t len) {
    snprintf(ciphertext, len, "ENCRYPTED:%s", plaintext);
}

void send_intel(int sock) {
    char message[512];
    snprintf(message, sizeof(message),
             "source:Radar|data:Incoming missiles|threat_level:0.8|location:Airspace");
    char ciphertext[1024];
    encrypt_message(message, ciphertext, sizeof(ciphertext));

    if (send(sock, ciphertext, strlen(ciphertext), 0) < 0) {
        log_event("Failed to send intelligence");
        return;
    }
    log_event("Radar intelligence sent");
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

    log_event("Radar connected to Control");

    while (1) {
        send_intel(sock);
        sleep(5);
    }

    close(sock);
    return 0;
}

