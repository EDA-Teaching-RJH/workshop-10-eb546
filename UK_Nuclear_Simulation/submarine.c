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

#define MY_ID ID_SUB "_Vanguard" // Unique ID for this sub instance
#define INTEL_UPDATE_INTERVAL 15  // Seconds
#define STATUS_UPDATE_INTERVAL 60 // Seconds

volatile sig_atomic_t keep_running = 1; // Signal handler flag

void signal_handler(int signum) {
    if (signum == SIGINT || signum == SIGTERM) {
         keep_running = 0;
    }
}

// --- Launch Simulation ---
void simulate_launch(const char *target_info) {
    log_message(MY_ID, "VALID LAUNCH COMMAND RECEIVED. Target: %s", target_info);
    printf("[%s] *** LAUNCH SEQUENCE INITIATED (SLBM) ***\n", MY_ID);
    log_message(MY_ID, "Launch sequence initiated (SLBM).");
    // Submarines might have slightly different procedures/timings
    sleep(3); // Simulate preparation (e.g., flooding tubes)
    printf("[%s] *** SLBM LAUNCHED *** Target: %s\n", MY_ID, target_info);
    log_message(MY_ID, "SLBM LAUNCHED.");
    // State should change, report back to control
}

// --- Generate Simulated Intel ---
void generate_intel(char *intel_buffer, size_t buffer_size) {
    // Simple random intel generation for simulation
    int type = rand() % 3;
    int x = rand() % 1000;
    int y = rand() % 1000;
    const char *status;

    switch (type) {
        case 0: status = "Passive sonar contact"; break;
        case 1: status = "Active sonar ping detected"; break;
        case 2: status = "Periscope depth observation"; break;
        default: status = "Routine patrol data"; break;
    }
    snprintf(intel_buffer, buffer_size, "%s at approx %d,%d", status, x, y);
}

// --- Main Client Logic ---
int main() {
    int sock_fd = -1;
    struct sockaddr_in server_addr;
    char buffer[BUFFER_SIZE];
    char intel_buffer[BUFFER_SIZE];
    time_t last_status_update = 0;
    time_t last_intel_update = 0;
    bool connected = false;

    srand(time(NULL)); // Seed random for intel generation
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    log_message(MY_ID, "Submarine client starting...");
    printf("[%s] Submarine client starting...\n", MY_ID);


    while (keep_running) {
        if (!connected) {
            // Attempt connection (similar to missileSilo)
            sock_fd = socket(AF_INET, SOCK_STREAM, 0);
            if (sock_fd < 0) {
                perror("ERROR opening socket");
                log_message(MY_ID, "ERROR: Failed to create socket: %s", strerror(errno));
                sleep(5); continue;
            }

            memset(&server_addr, 0, sizeof(server_addr));
            server_addr.sin_family = AF_INET;
            server_addr.sin_port = htons(SERVER_PORT);
            if (inet_pton(AF_INET, SERVER_IP, &server_addr.sin_addr) <= 0) {
                perror("ERROR invalid server IP address");
                 log_message(MY_ID, "ERROR: Invalid server IP address %s", SERVER_IP);
                close(sock_fd); sock_fd = -1; sleep(5); continue;
            }

            printf("[%s] Connecting to Nuclear Control %s:%d...\n", MY_ID, SERVER_IP, SERVER_PORT);
            if (connect(sock_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
                perror("ERROR connecting");
                 log_message(MY_ID, "ERROR: Failed to connect to %s:%d: %s", SERVER_IP, SERVER_PORT, strerror(errno));
                close(sock_fd); sock_fd = -1; sleep(5); continue;
            }

            connected = true;
            printf("[%s] Connected to Nuclear Control.\n", MY_ID);
            log_message(MY_ID, "Connected to server %s:%d.", SERVER_IP, SERVER_PORT);

            // Send IDENTIFY
            snprintf(buffer, BUFFER_SIZE, "%s:%s%c", TAG_IDENTIFY, MY_ID, MSG_END);
            if (send(sock_fd, buffer, strlen(buffer), 0) < 0) {
                perror("ERROR sending IDENTIFY");
                 log_message(MY_ID, "ERROR: Failed to send IDENTIFY message: %s", strerror(errno));
                close(sock_fd); sock_fd = -1; connected = false; continue;
            }
             log_message(MY_ID, "Sent IDENTIFY message.");
            last_status_update = time(NULL);
            last_intel_update = time(NULL);
        }

        // --- Main loop when connected ---
        if (connected) {
            fd_set read_fds;
            struct timeval tv;
            int retval;

            FD_ZERO(&read_fds);
            FD_SET(sock_fd, &read_fds);
            tv.tv_sec = 1; tv.tv_usec = 0;

            retval = select(sock_fd + 1, &read_fds, NULL, NULL, &tv);

            if (retval == -1) {
                 if (errno == EINTR) { continue; } // Interrupted by signal
                perror("ERROR in select()");
                log_message(MY_ID, "ERROR: select() failed: %s", strerror(errno));
                close(sock_fd); sock_fd = -1; connected = false; continue;
            } else if (retval > 0) {
                // Data available from server
                if (FD_ISSET(sock_fd, &read_fds)) {
                    memset(buffer, 0, BUFFER_SIZE);
                    int n = recv(sock_fd, buffer, BUFFER_SIZE - 1, 0);
                    if (n <= 0) {
                        if (n == 0) log_message(MY_ID, "INFO: Server closed connection.");
                        else log_message(MY_ID, "ERROR: Failed to receive data: %s", strerror(errno));
                        close(sock_fd); sock_fd = -1; connected = false; continue;
                    }
                    buffer[n] = '\0';
                    log_message(MY_ID, "Received raw: %s", buffer);

                    // --- Parse Command (Identical logic to Missile Silo) ---
                    char *type = strtok(buffer, ":\n");
                    char *payload_encrypted = strtok(NULL, ":\n");
                    char *checksum_str = strtok(NULL, "\n");

                     if (type && strcmp(type, TAG_COMMAND) == 0 && payload_encrypted && checksum_str) {
                        char decrypted_payload[BUFFER_SIZE];
                        strncpy(decrypted_payload, payload_encrypted, BUFFER_SIZE -1);
                        decrypted_payload[BUFFER_SIZE-1] = '\0';

                        encrypt_decrypt_xor(decrypted_payload, strlen(decrypted_payload), SHARED_SECRET_KEY);
                        log_message(MY_ID, "Decrypted payload: %s", decrypted_payload);

                        unsigned long received_checksum = strtoul(checksum_str, NULL, 10);
                        unsigned long calculated_checksum = simple_checksum(decrypted_payload, SHARED_SECRET_KEY);
                         log_message(MY_ID, "Received Checksum: %lu, Calculated Checksum: %lu", received_checksum, calculated_checksum);

                        if (received_checksum == calculated_checksum) {
                             log_message(MY_ID, "Checksum VERIFIED.");
                            char *command_type = strtok(decrypted_payload, ":");
                            char *command_data = strtok(NULL, "");

                            if (command_type) {
                                if (strcmp(command_type, CMD_LAUNCH) == 0) {
                                    simulate_launch(command_data ? command_data : "UNKNOWN_TARGET");
                                    snprintf(buffer, BUFFER_SIZE, "%s:%s:SUCCESS%c", TAG_LAUNCH_ACK, MY_ID, MSG_END);
                                     if (send(sock_fd, buffer, strlen(buffer), 0) < 0) log_message(MY_ID, "ERROR: Failed to send LAUNCH ACK: %s", strerror(errno));
                                     else log_message(MY_ID, "Sent LAUNCH ACK: SUCCESS");
                                } else if (strcmp(command_type, CMD_STANDDOWN) == 0) {
                                    printf("[%s] Received STAND DOWN command. Reason: %s\n", MY_ID, command_data ? command_data : "N/A");
                                    log_message(MY_ID, "Received STAND DOWN command. Reason: %s", command_data ? command_data : "N/A");
                                } else if (strcmp(command_type, CMD_QUERY_STATUS) == 0) {
                                     log_message(MY_ID, "Received Status Query. Sending status.");
                                     snprintf(buffer, BUFFER_SIZE, "%s:%s:ON_PATROL%c", TAG_STATUS, MY_ID, MSG_END); // Example sub status
                                     if (send(sock_fd, buffer, strlen(buffer), 0) < 0) log_message(MY_ID, "ERROR: Failed to send status: %s", strerror(errno));
                                } else {
                                    log_message(MY_ID, "WARN: Received unknown command type after decryption: %s", command_type);
                                }
                            } else {
                                 log_message(MY_ID, "ERROR: Failed to parse command type from decrypted payload.");
                            }
                        } else {
                            log_message(MY_ID, "ERROR: Checksum verification FAILED! Ignoring command.");
                             snprintf(buffer, BUFFER_SIZE, "%s:%s:FAILURE Checksum_Mismatch%c", TAG_LAUNCH_ACK, MY_ID, MSG_END);
                              if (send(sock_fd, buffer, strlen(buffer), 0) < 0) log_message(MY_ID, "ERROR: Failed to send LAUNCH NACK (Checksum): %s", strerror(errno));
                              else log_message(MY_ID, "Sent LAUNCH NACK: Checksum Mismatch");
                        }
                    } else if (type) {
                        log_message(MY_ID, "WARN: Received non-command message type: %s", type);
                    } else {
                        log_message(MY_ID, "WARN: Received malformed message from server.");
                    }

                } // End if FD_ISSET
            } else {
                 // select() timed out
                 time_t now = time(NULL);

                 // Send Periodic Intel
                 if (now - last_intel_update >= INTEL_UPDATE_INTERVAL) {
                     generate_intel(intel_buffer, sizeof(intel_buffer));
                     snprintf(buffer, BUFFER_SIZE, "%s:%s:%s%c", TAG_INTEL, MY_ID, intel_buffer, MSG_END);
                     log_message(MY_ID, "Sending intel: %s", intel_buffer);
                     if (send(sock_fd, buffer, strlen(buffer), 0) < 0) {
                         perror("ERROR sending intel");
                         log_message(MY_ID, "ERROR: Failed sending intel: %s", strerror(errno));
                         close(sock_fd); sock_fd = -1; connected = false; continue;
                     }
                     last_intel_update = now;
                 }

                 // Send Periodic Status
                 if (now - last_status_update >= STATUS_UPDATE_INTERVAL) {
                     snprintf(buffer, BUFFER_SIZE, "%s:%s:ON_PATROL%c", TAG_STATUS, MY_ID, MSG_END);
                     log_message(MY_ID, "Sending periodic status update: ON_PATROL");
                     if (send(sock_fd, buffer, strlen(buffer), 0) < 0) {
                          perror("ERROR sending status update");
                          log_message(MY_ID, "ERROR: Failed sending status update: %s", strerror(errno));
                          close(sock_fd); sock_fd = -1; connected = false; continue;
                     }
                     last_status_update = now;
                 }
            } // End select handling
        } // End if (connected)

        if (!connected && keep_running) { sleep(1); }

    } // End while(keep_running)

    printf("\n[%s] Shutting down...\n", MY_ID);
    if (sock_fd != -1) close(sock_fd);
    log_message(MY_ID, "Submarine client stopped.");
    return 0;
}

