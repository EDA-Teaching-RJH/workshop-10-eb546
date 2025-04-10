#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <stdbool.h>
#include <signal.h>

#include "common.h"
#include "utils.h"

#define MY_ID ID_SAT "_Skynet" // Unique ID for this satellite instance
#define INTEL_UPDATE_INTERVAL 25 // Seconds (Satellites might have specific overpass times)
#define STATUS_UPDATE_INTERVAL 120 // Seconds

volatile sig_atomic_t keep_running = 1;

void signal_handler(int signum) {
    if (signum == SIGINT || signum == SIGTERM) {
         keep_running = 0;
    }
}

// --- Generate Simulated Intel ---
void generate_intel(char *intel_buffer, size_t buffer_size) {
    // Simple random intel generation
    int type = rand() % 4;
    int region_code = rand() % 900 + 100; // Geographic region code
    const char *obs_type;

    switch (type) {
        case 0: obs_type = "Optical imaging"; break;
        case 1: obs_type = "Infrared scan"; break;
        case 2: obs_type = "Signals intelligence"; break;
        case 3: // Simulate potential threat for War Test
              if (rand() % 15 == 0) { // Lower chance than radar
                   snprintf(intel_buffer, buffer_size, "Unusual heat signature detected near hostile border, possible launch prep. Region %d", region_code);
                   return;
               } // else fall through
        default: obs_type = "Routine scan"; break;
    }
    snprintf(intel_buffer, buffer_size, "%s results for region %d: Nominal activity.", obs_type, region_code);
}


// --- Main Client Logic (Very similar structure to Radar/Submarine) ---
int main() {
    int sock_fd = -1;
    struct sockaddr_in server_addr;
    char buffer[BUFFER_SIZE];
    char intel_buffer[BUFFER_SIZE];
    time_t last_status_update = 0;
    time_t last_intel_update = 0;
    bool connected = false;

    srand(time(NULL));
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    log_message(MY_ID, "Satellite client starting...");
    printf("[%s] Satellite client starting...\n", MY_ID);

    while (keep_running) {
        if (!connected) {
            // Attempt connection
            sock_fd = socket(AF_INET, SOCK_STREAM, 0);
            if (sock_fd < 0) { perror("socket"); log_message(MY_ID,"ERROR socket: %s", strerror(errno)); sleep(5); continue; }

            memset(&server_addr, 0, sizeof(server_addr));
            server_addr.sin_family = AF_INET;
            server_addr.sin_port = htons(SERVER_PORT);
            if (inet_pton(AF_INET, SERVER_IP, &server_addr.sin_addr) <= 0) { perror("inet_pton"); log_message(MY_ID,"ERROR invalid IP: %s", SERVER_IP); close(sock_fd); sock_fd = -1; sleep(5); continue; }

            printf("[%s] Connecting to Nuclear Control %s:%d...\n", MY_ID, SERVER_IP, SERVER_PORT);
            if (connect(sock_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) { perror("connect"); log_message(MY_ID, "ERROR connect: %s", strerror(errno)); close(sock_fd); sock_fd = -1; sleep(5); continue; }

            connected = true;
            printf("[%s] Connected to Nuclear Control.\n", MY_ID);
            log_message(MY_ID, "Connected to server %s:%d.", SERVER_IP, SERVER_PORT);

            // Send IDENTIFY
            snprintf(buffer, BUFFER_SIZE, "%s:%s%c", TAG_IDENTIFY, MY_ID, MSG_END);
            if (send(sock_fd, buffer, strlen(buffer), 0) < 0) { perror("send IDENTIFY"); log_message(MY_ID, "ERROR send IDENTIFY: %s", strerror(errno)); close(sock_fd); sock_fd = -1; connected = false; continue; }
            log_message(MY_ID, "Sent IDENTIFY message.");
            last_status_update = last_intel_update = time(NULL);
        }

        // --- Main loop when connected ---
        if (connected) {
            fd_set read_fds;
            struct timeval tv;
            int retval;

            FD_ZERO(&read_fds); FD_SET(sock_fd, &read_fds);
            tv.tv_sec = 1; tv.tv_usec = 0;

            retval = select(sock_fd + 1, &read_fds, NULL, NULL, &tv);

            if (retval == -1) {
                 if (errno == EINTR) { continue; }
                perror("select"); log_message(MY_ID, "ERROR select: %s", strerror(errno)); close(sock_fd); sock_fd = -1; connected = false; continue;
            } else if (retval > 0) {
                // Data available from server
                if (FD_ISSET(sock_fd, &read_fds)) {
                    memset(buffer, 0, BUFFER_SIZE);
                    int n = recv(sock_fd, buffer, BUFFER_SIZE - 1, 0);
                    if (n <= 0) {
                        if (n == 0) log_message(MY_ID, "INFO: Server closed connection.");
                        else log_message(MY_ID, "ERROR recv: %s", strerror(errno));
                        close(sock_fd); sock_fd = -1; connected = false; continue;
                    }
                    buffer[n] = '\0';
                    log_message(MY_ID, "Received raw: %s", buffer);
                     // Basic command handling (e.g., status query)
                    char *type = strtok(buffer, ":\n");
                    char *payload = strtok(NULL, "\n");
                     if (type && strcmp(type, TAG_COMMAND) == 0 && payload) {
                         char *cmd_type = strtok(payload, ":");
                          if(cmd_type && strcmp(cmd_type, CMD_QUERY_STATUS) == 0) {
                              log_message(MY_ID, "Received Status Query. Sending status.");
                              snprintf(buffer, BUFFER_SIZE, "%s:%s:NOMINAL%c", TAG_STATUS, MY_ID, MSG_END);
                              if (send(sock_fd, buffer, strlen(buffer), 0) < 0) log_message(MY_ID, "ERROR send status: %s", strerror(errno));
                          } else {
                               log_message(MY_ID, "WARN: Received unhandled command type: %s", cmd_type ? cmd_type : "<null>");
                          }
                     } else if (type) {
                          log_message(MY_ID, "WARN: Received non-command message type: %s", type);
                     } else {
                          log_message(MY_ID, "WARN: Received malformed message from server.");
                     }
                }
            } else {
                 // select() timed out
                 time_t now = time(NULL);

                 // Send Periodic Intel
                 if (now - last_intel_update >= INTEL_UPDATE_INTERVAL) {
                     generate_intel(intel_buffer, sizeof(intel_buffer));
                     snprintf(buffer, BUFFER_SIZE, "%s:%s:%s%c", TAG_INTEL, MY_ID, intel_buffer, MSG_END);
                     log_message(MY_ID, "Sending intel: %s", intel_buffer);
                     if (send(sock_fd, buffer, strlen(buffer), 0) < 0) { perror("send intel"); log_message(MY_ID, "ERROR send intel: %s", strerror(errno)); close(sock_fd); sock_fd = -1; connected = false; continue; }
                     last_intel_update = now;
                 }

                 // Send Periodic Status
                 if (now - last_status_update >= STATUS_UPDATE_INTERVAL) {
                     snprintf(buffer, BUFFER_SIZE, "%s:%s:NOMINAL%c", TAG_STATUS, MY_ID, MSG_END);
                     log_message(MY_ID, "Sending periodic status update: NOMINAL");
                     if (send(sock_fd, buffer, strlen(buffer), 0) < 0) { perror("send status"); log_message(MY_ID, "ERROR send status: %s", strerror(errno)); close(sock_fd); sock_fd = -1; connected = false; continue; }
                     last_status_update = now;
                 }
            }
        }

        if (!connected && keep_running) { sleep(1); }
    }

    printf("\n[%s] Shutting down...\n", MY_ID);
    if (sock_fd != -1) close(sock_fd);
    log_message(MY_ID, "Satellite client stopped.");
    return 0;
}