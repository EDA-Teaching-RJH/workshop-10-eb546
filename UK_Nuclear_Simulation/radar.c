#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <ctype.h>

#define SERVER_IP "127.0.0.1"
#define SERVER_PORT 8083
#define LOG_FILE "radar.log"
#define CAESAR_SHIFT 3

void log_event(const char *event_type, const char *details) {
    FILE *fp = fopen(LOG_FILE, "a");
    if (fp == NULL) {
        perror("Log file open failed");
        return;
    }
    time_t now = time(NULL);
    char *time_str = ctime(&now);
    if (time_str) {
        time_str[strlen(time_str) - 1] = '\0';
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

void send_intel(int sock) {
    char message[512];
    snprintf(message, sizeof(message),
             "source:Radar|data:Incoming missiles|threat_level:0.8|location:Airspace");
    char ciphertext[1024];
    caesar_encrypt(message, ciphertext, sizeof(ciphertext));

    char log_msg[1024];
    snprintf(log_msg, sizeof(log_msg), "Sending encrypted: %s", ciphertext);
    log_event("MESSAGE", log_msg);
    snprintf(log_msg, sizeof(log_msg), "Original message: %s", message);
    log_event("MESSAGE", log_msg);

    if (send(sock, ciphertext, strlen(ciphertext), 0) < 0) {
        log_event("ERROR", "Failed to send intelligence");
        return;
    }
    log_event("INTEL", "Intelligence sent: Incoming missiles, Threat Level: 0.8, Location: Airspace");
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

    log_event("CONNECTION", "Connected to Nuclear Control");

    while (1) {
        send_intel(sock);
        sleep(5);
    }

    close(sock);
    log_event("SHUTDOWN", "Radar terminated");
    return 0;
}

