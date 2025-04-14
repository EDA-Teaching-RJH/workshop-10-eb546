#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/aes.h>

#define SERVER_IP "127.0.0.1"
#define SERVER_PORT 8084
#define LOG_FILE "satellite.log"

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

void encrypt_message(const char *plaintext, char *ciphertext, int *len) {
    snprintf(ciphertext, *len, "ENCRYPTED:%s", plaintext);
}

void send_intel(int sock) {
    char message[512];
    snprintf(message, sizeof(message), 
             "source:Satellite|data:Missile launch detected|threat_level:0.7|location:Orbit");
    char ciphertext[1024];
    int len = sizeof(ciphertext);
    encrypt_message(message, ciphertext, &len);

    send(sock, ciphertext, strlen(ciphertext), 0);
    log_event("Satellite intelligence sent");
}

int main() {
    int sock;
    struct sockaddr_in server_addr;

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

    log_event("Satellite connected to Control");

    while (1) {
        send_intel(sock);
        sleep(5); // Send intel periodically
    }

    close(sock);
    return 0;
}

