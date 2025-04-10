// missileSilo.c
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

// ---> ADD THESE LINES <---
#include <errno.h>
#include <sys/select.h>
// ---> END OF ADDED LINES <---

#include "common.h"
#include "utils.h"

// ... rest of missileSilo.c ...

#define MY_ID ID_SILO "_Alpha" // Unique ID for this silo instance
#define STATUS_UPDATE_INTERVAL 30 // Seconds

volatile sig_atomic_t keep_running = 1; // Signal handler flag

void signal_handler(int signum) {
    if (signum == SIGINT || signum == SIGTERM) {
         keep_running = 0;
    }
}

// --- Launch Simulation ---
void simulate_launch(const char *target_info) {
    log_message(MY_ID, "VALID LAUNCH COMMAND RECEIVED. Target: %s", target_info);
    printf("[%s] *** LAUNCH SEQUENCE INITIATED ***\n", MY_ID);
    log_message(MY_ID, "Launch sequence initiated.");
    sleep(2); // Simulate preparation
    printf("[%s] *** MISSILE LAUNCHED *** Target: %s\n", MY_ID, target_info);
    log_message(MY_ID, "MISSILE LAUNCHED.");
    // State should change, report back to control
}

// --- Main Client Logic ---
int main() {
    int sock_fd = -1;
    struct sockaddr_in server_addr;
    char buffer[BUFFER_SIZE];
    time_t last_status_update = 0;
    bool connected = false;

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    log_message(MY_ID, "Missile Silo client starting...");
    printf("[%s] Missile Silo client starting...\n", MY_ID);


    while (keep_running) {
        if (!connected) {
            // Attempt connection
            sock_fd = socket(AF_INET, SOCK_STREAM, 0);
            if (sock_fd < 0) {
                perror("ERROR opening socket");
                log_message(MY_ID, "ERROR: Failed to create socket: %s", strerror(errno));
                sleep(5); // Wait before retry
                continue;
            }

            memset(&server_addr, 0, sizeof(server_addr));
            server_addr.sin_family = AF_INET;
            server_addr.sin_port = htons(SERVER_PORT);
            if (inet_pton(AF_INET, SERVER_IP, &server_addr.sin_addr) <= 0) {
                perror("ERROR invalid server IP address");
                 log_message(MY_ID, "ERROR: Invalid server IP address %s", SERVER_IP);
                close(sock_fd);
                sock_fd = -1;
                sleep(5);
                continue;
            }

            printf("[%s] Connecting to Nuclear Control %s:%d...\n", MY_ID, SERVER_IP, SERVER_PORT);
            if (connect(sock_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
                perror("ERROR connecting");
                 log_message(MY_ID, "ERROR: Failed to connect to %s:%d: %s", SERVER_IP, SERVER_PORT, strerror(errno));
                close(sock_fd);
                sock_fd = -1;
                sleep(5); // Wait before retry
                continue;
            }

            // --- Connection successful ---
            connected = true;
            printf("[%s] Connected to Nuclear Control.\n", MY_ID);
            log_message(MY_ID, "Connected to server %s:%d.", SERVER_IP, SERVER_PORT);

            // 1. Send IDENTIFY message
            snprintf(buffer, BUFFER_SIZE, "%s:%s%c", TAG_IDENTIFY, MY_ID, MSG_END);
            if (send(sock_fd, buffer, strlen(buffer), 0) < 0) {
                perror("ERROR sending IDENTIFY");
                 log_message(MY_ID, "ERROR: Failed to send IDENTIFY message: %s", strerror(errno));
                close(sock_fd);
                sock_fd = -1;
                connected = false;
                continue; // Retry connection
            }
            log_message(MY_ID, "Sent IDENTIFY message.");
            last_status_update = time(NULL); // Reset timer after successful connection/identification
        } // End if (!connected)


        // --- Main loop when connected ---
        if (connected) {
            // Use select for non-blocking read and periodic tasks
            fd_set read_fds;
            struct timeval tv;
            int retval;

            FD_ZERO(&read_fds);
            FD_SET(sock_fd, &read_fds);

            // Set timeout for select (e.g., 1 second)
            tv.tv_sec = 1;
            tv.tv_usec = 0;

            retval = select(sock_fd + 1, &read_fds, NULL, NULL, &tv);

            if (retval == -1) {
                 if (errno == EINTR) { // Interrupted by signal handler
                     log_message(MY_ID, "INFO: Select interrupted by signal.");
                     continue; // Check keep_running flag
                 }
                perror("ERROR in select()");
                log_message(MY_ID, "ERROR: select() failed: %s", strerror(errno));
                close(sock_fd);
                sock_fd = -1;
                connected = false;
                continue; // Attempt reconnect
            } else if (retval > 0) {
                // Data is available to read from server
                if (FD_ISSET(sock_fd, &read_fds)) {
                    memset(buffer, 0, BUFFER_SIZE);
                    int n = recv(sock_fd, buffer, BUFFER_SIZE - 1, 0);

                    if (n <= 0) {
                        if (n == 0) {
                            printf("[%s] Server disconnected.\n", MY_ID);
                            log_message(MY_ID, "INFO: Server closed connection.");
                        } else {
                            perror("ERROR reading from socket");
                            log_message(MY_ID, "ERROR: Failed to receive data: %s", strerror(errno));
                        }
                        close(sock_fd);
                        sock_fd = -1;
                        connected = false;
                        continue; // Attempt reconnect
                    }

                    // Process received command
                    buffer[n] = '\0';
                    log_message(MY_ID, "Received raw: %s", buffer); // Log raw incoming data

                    // --- Parse Command ---
                    char *type = strtok(buffer, ":\n");
                    char *payload_encrypted = strtok(NULL, ":\n"); // Might be encrypted payload + checksum
                    char *checksum_str = strtok(NULL, "\n");       // Might be checksum

                    if (type && strcmp(type, TAG_COMMAND) == 0 && payload_encrypted && checksum_str) {
                        // Received a command potentially needing decryption/verification
                        log_message(MY_ID, "Received potential command. Payload (Encrypted?): %s, Checksum str: %s", payload_encrypted, checksum_str);

                        // 1. Decrypt the payload (in-place)
                        // IMPORTANT: Create a mutable copy for decryption if needed, or ensure buffer is large enough
                        char decrypted_payload[BUFFER_SIZE];
                        strncpy(decrypted_payload, payload_encrypted, BUFFER_SIZE -1);
                        decrypted_payload[BUFFER_SIZE-1] = '\0';

                        encrypt_decrypt_xor(decrypted_payload, strlen(decrypted_payload), SHARED_SECRET_KEY);
                         log_message(MY_ID, "Decrypted payload: %s", decrypted_payload);

                        // 2. Verify checksum
                        unsigned long received_checksum = strtoul(checksum_str, NULL, 10);
                        unsigned long calculated_checksum = simple_checksum(decrypted_payload, SHARED_SECRET_KEY);

                         log_message(MY_ID, "Received Checksum: %lu, Calculated Checksum: %lu", received_checksum, calculated_checksum);

                        if (received_checksum == calculated_checksum) {
                            log_message(MY_ID, "Checksum VERIFIED.");

                            // 3. Parse the decrypted payload (CommandType:Data)
                            char *command_type = strtok(decrypted_payload, ":");
                            char *command_data = strtok(NULL, ""); // Rest is data

                            if (command_type) {
                                if (strcmp(command_type, CMD_LAUNCH) == 0) {
                                    simulate_launch(command_data ? command_data : "UNKNOWN_TARGET");
                                    // Send ACK back to control
                                    snprintf(buffer, BUFFER_SIZE, "%s:%s:SUCCESS%c", TAG_LAUNCH_ACK, MY_ID, MSG_END);
                                    if (send(sock_fd, buffer, strlen(buffer), 0) < 0) {
                                         perror("Error sending LAUNCH ACK");
                                         log_message(MY_ID, "ERROR: Failed to send LAUNCH ACK: %s", strerror(errno));
                                         // Non-fatal for silo operation itself
                                    } else {
                                         log_message(MY_ID, "Sent LAUNCH ACK: SUCCESS");
                                    }
                                } else if (strcmp(command_type, CMD_STANDDOWN) == 0) {
                                    printf("[%s] Received STAND DOWN command. Reason: %s\n", MY_ID, command_data ? command_data : "N/A");
                                    log_message(MY_ID, "Received STAND DOWN command. Reason: %s", command_data ? command_data : "N/A");
                                    // Implement stand down logic if needed
                                } else if (strcmp(command_type, CMD_QUERY_STATUS) == 0) {
                                     log_message(MY_ID, "Received Status Query. Sending status.");
                                     // Send current status (e.g., READY)
                                     snprintf(buffer, BUFFER_SIZE, "%s:%s:READY%c", TAG_STATUS, MY_ID, MSG_END);
                                     if (send(sock_fd, buffer, strlen(buffer), 0) < 0) {
                                        perror("Error sending status");
                                         log_message(MY_ID, "ERROR: Failed to send status: %s", strerror(errno));
                                     }
                                }
                                else {
                                    log_message(MY_ID, "WARN: Received unknown command type after decryption: %s", command_type);
                                }
                            } else {
                                 log_message(MY_ID, "ERROR: Failed to parse command type from decrypted payload.");
                            }
                        } else {
                            log_message(MY_ID, "ERROR: Checksum verification FAILED! Ignoring command.");
                            // Send NACK back to control?
                            snprintf(buffer, BUFFER_SIZE, "%s:%s:FAILURE Checksum_Mismatch%c", TAG_LAUNCH_ACK, MY_ID, MSG_END);
                             if (send(sock_fd, buffer, strlen(buffer), 0) < 0) {
                                 perror("Error sending LAUNCH NACK");
                                 log_message(MY_ID, "ERROR: Failed to send LAUNCH NACK (Checksum): %s", strerror(errno));
                             } else {
                                 log_message(MY_ID, "Sent LAUNCH NACK: Checksum Mismatch");
                             }
                        }
                    } else if (type) {
                        // Handle other non-encrypted messages if needed (e.g., server pings)
                        log_message(MY_ID, "WARN: Received non-command message type: %s", type);
                    } else {
                         log_message(MY_ID, "WARN: Received malformed message from server.");
                    }

                } // End if FD_ISSET
            } else {
                 // select() timed out, no data received from server
                 // This is where we can do periodic tasks
                 time_t now = time(NULL);
                 if (now - last_status_update >= STATUS_UPDATE_INTERVAL) {
                     // Send status update
                     snprintf(buffer, BUFFER_SIZE, "%s:%s:READY%c", TAG_STATUS, MY_ID, MSG_END);
                     log_message(MY_ID, "Sending periodic status update: READY");
                     if (send(sock_fd, buffer, strlen(buffer), 0) < 0) {
                         perror("ERROR sending status update");
                         log_message(MY_ID, "ERROR: Failed sending status update: %s", strerror(errno));
                         // Connection might be broken, trigger reconnect logic
                         close(sock_fd);
                         sock_fd = -1;
                         connected = false;
                     }
                     last_status_update = now;
                 }
            } // End select handling
        } // End if (connected)

        // Small delay if not connected to prevent busy-looping on connection errors
        if (!connected && keep_running) {
             sleep(1);
        }

    } // End while(keep_running)

    // --- Cleanup ---
    printf("\n[%s] Shutting down...\n", MY_ID);
    if (sock_fd != -1) {
        close(sock_fd);
    }
    log_message(MY_ID, "Missile Silo client stopped.");
    return 0;
}

