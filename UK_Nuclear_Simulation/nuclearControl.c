#define _DEFAULT_SOURCE // For NI_MAXHOST, NI_MAXSERV with glibc >= 2.22
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h> // For signal handling
#include <time.h>   // For seeding rand()
#include <stdbool.h> // For bool type
#include <netdb.h> // For getnameinfo

#include "common.h"
#include "utils.h"

#define MAX_PENDING_CONNECTIONS 5

// Structure to hold client information
typedef struct {
    int socket_fd;
    struct sockaddr_in address;
    char client_id[50]; // Store ID like "SILO_1", "SUB_ALPHA", "RADAR_NORTH" etc.
    bool active;
    pthread_t thread_id;
} client_info_t;

client_info_t clients[MAX_CLIENTS];
pthread_mutex_t clients_mutex = PTHREAD_MUTEX_INITIALIZER;
int client_count = 0;
bool run_server = true; // Flag to control server loop
bool war_test_mode = false;
int server_socket_fd = -1;

// Function Prototypes
void *handle_client(void *arg);
void initialize_clients();
int add_client(int socket_fd, struct sockaddr_in address);
void remove_client(int client_index);
void broadcast_message(const char *message, int sender_index); // Not used currently, but useful
void send_to_client(int client_index, const char *message);
void send_secure_launch_command(const char* target_client_id_prefix, const char* target_info);
void *war_test_monitor(void *arg);
void cleanup_server();
void signal_handler(int signum);
void assess_threat_and_decide(const char* intel_source, const char* intel_data);


// --- Main Server Logic ---
int main(int argc, char *argv[]) {
    srand(time(NULL)); // Seed random number generator for war test

    // Check for command line arguments
    if (argc > 1 && strcmp(argv[1], "--test") == 0) {
        war_test_mode = true;
        printf("INFO: War test mode enabled.\n");
        log_message(ID_CONTROL, "War test mode enabled.");
    }

    // Setup signal handling for graceful shutdown
    signal(SIGINT, signal_handler); // Handle Ctrl+C
    signal(SIGTERM, signal_handler); // Handle termination signal

    initialize_clients();
    log_message(ID_CONTROL, "Nuclear Control Server starting...");

    struct sockaddr_in server_addr;

    // 1. Create socket
    server_socket_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket_fd < 0) {
        perror("ERROR opening socket");
        log_message(ID_CONTROL, "FATAL: Failed to create server socket: %s", strerror(errno));
        exit(EXIT_FAILURE);
    }
    log_message(ID_CONTROL, "Server socket created (fd: %d).", server_socket_fd);

    // Set SO_REUSEADDR to allow immediate reuse of the port after server stops
    int optval = 1;
    if (setsockopt(server_socket_fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) < 0) {
        perror("setsockopt(SO_REUSEADDR) failed");
        // Non-fatal, but log it
        log_message(ID_CONTROL, "WARN: setsockopt(SO_REUSEADDR) failed: %s", strerror(errno));
    }


    // 2. Bind socket
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr(SERVER_IP); // Or INADDR_ANY for all interfaces
    server_addr.sin_port = htons(SERVER_PORT);

    if (bind(server_socket_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("ERROR on binding");
        log_message(ID_CONTROL, "FATAL: Failed to bind server socket to %s:%d: %s", SERVER_IP, SERVER_PORT, strerror(errno));
        close(server_socket_fd);
        exit(EXIT_FAILURE);
    }
    log_message(ID_CONTROL, "Server socket bound to %s:%d.", SERVER_IP, SERVER_PORT);

    // 3. Listen for connections
    if (listen(server_socket_fd, MAX_PENDING_CONNECTIONS) < 0) {
        perror("ERROR on listen");
        log_message(ID_CONTROL, "FATAL: Failed to listen on server socket: %s", strerror(errno));
        close(server_socket_fd);
        exit(EXIT_FAILURE);
    }
    printf("Nuclear Control Server listening on %s:%d...\n", SERVER_IP, SERVER_PORT);
    log_message(ID_CONTROL, "Server listening...");


    // Start War Test Monitor thread if enabled
    pthread_t war_test_thread_id;
    if (war_test_mode) {
        if (pthread_create(&war_test_thread_id, NULL, war_test_monitor, NULL) != 0) {
            perror("Failed to create war test monitor thread");
            log_message(ID_CONTROL, "ERROR: Failed to start war test monitor thread.");
            // Continue without war test? Or exit? Let's continue but log error.
        } else {
             log_message(ID_CONTROL, "War test monitor thread started.");
        }
    }


    // 4. Accept connections in a loop
    while (run_server) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        int newsockfd = accept(server_socket_fd, (struct sockaddr *)&client_addr, &client_len);

        if (!run_server) break; // Check flag again after potentially blocking accept

        if (newsockfd < 0) {
            // Don't exit on accept error unless it's critical or we are shutting down
            if (errno == EINTR && !run_server) {
                 log_message(ID_CONTROL, "INFO: Accept interrupted during shutdown.");
                 break; // Normal shutdown
            }
            perror("ERROR on accept");
            log_message(ID_CONTROL, "WARN: Error accepting new connection: %s", strerror(errno));
            continue; // Try to accept the next connection
        }

        // Add client to our list and start a handler thread
        int client_index = add_client(newsockfd, client_addr);
        if (client_index != -1) {
             if (pthread_create(&clients[client_index].thread_id, NULL, handle_client, (void *)(intptr_t)client_index) != 0) {
                 perror("ERROR creating client handler thread");
                 log_message(ID_CONTROL, "ERROR: Failed to create thread for client %d.", newsockfd);
                 close(newsockfd);
                 remove_client(client_index); // Clean up partially added client
             } else {
                 // Thread created successfully, detaching so we don't need to join it
                 // The thread will clean itself up via remove_client on exit/error
                 pthread_detach(clients[client_index].thread_id);
             }
        } else {
            // Failed to add client (e.g., max clients reached)
            log_message(ID_CONTROL, "WARN: Rejected connection from fd %d: too many clients.", newsockfd);
            const char *reject_msg = "ERROR: Server busy. Too many clients.\n";
            send(newsockfd, reject_msg, strlen(reject_msg), 0);
            close(newsockfd);
        }
    }

    // --- Cleanup ---
    cleanup_server();
    printf("Nuclear Control Server shut down.\n");
    log_message(ID_CONTROL, "Server shut down gracefully.");
    return 0;
}

// --- Client Handling Thread ---
void *handle_client(void *arg) {
    int client_index = (intptr_t)arg;
    int sock_fd;
    char buffer[BUFFER_SIZE];
    int n;
    char client_ip[NI_MAXHOST];
    char client_port[NI_MAXSERV];
    bool client_identified = false;

    // Safely get socket descriptor
    pthread_mutex_lock(&clients_mutex);
    if (client_index < 0 || client_index >= MAX_CLIENTS || !clients[client_index].active) {
         pthread_mutex_unlock(&clients_mutex);
         log_message(ID_CONTROL, "ERROR: Invalid client index %d in handle_client.", client_index);
         return NULL;
    }
    sock_fd = clients[client_index].socket_fd;
    struct sockaddr_in addr = clients[client_index].address;
    pthread_mutex_unlock(&clients_mutex);

    // Get client address string for logging
    if (getnameinfo((struct sockaddr*)&addr, sizeof(addr), client_ip, sizeof(client_ip),
                    client_port, sizeof(client_port), NI_NUMERICHOST | NI_NUMERICSERV) == 0) {
        log_message(ID_CONTROL, "INFO: Handling client %d from %s:%s.", sock_fd, client_ip, client_port);
    } else {
        log_message(ID_CONTROL, "INFO: Handling client %d (address lookup failed).", sock_fd);
        strncpy(client_ip, "?.?.?.?", sizeof(client_ip)-1); // Default if lookup fails
        client_ip[sizeof(client_ip)-1] = '\0';
    }


    // Client interaction loop
    while (run_server) {
        memset(buffer, 0, BUFFER_SIZE);
        n = recv(sock_fd, buffer, BUFFER_SIZE - 1, 0);

        if (n <= 0) {
            if (n == 0) {
                // Connection closed by client
                log_message(ID_CONTROL, "INFO: Client %s (%s:%s, fd %d) disconnected.", clients[client_index].client_id, client_ip, client_port, sock_fd);
            } else {
                // Error receiving data
                perror("ERROR reading from socket");
                log_message(ID_CONTROL, "ERROR: Failed to receive from client %s (%s:%s, fd %d): %s.", clients[client_index].client_id, client_ip, client_port, sock_fd, strerror(errno));
            }
            break; // Exit loop on error or disconnect
        }

        // Null-terminate received data (important!)
        buffer[n] = '\0';

        // Process received message (simple parsing based on TAG:)
        char *type = strtok(buffer, ":\n"); // Use : and \n as delimiters
        char *payload = strtok(NULL, "\n"); // Get the rest of the line

        if (type == NULL) {
            log_message(ID_CONTROL, "WARN: Received empty or malformed message from fd %d.", sock_fd);
            continue;
        }

        // --- Message Handling Logic ---
        if (!client_identified) {
            // First message must be IDENTIFY
            if (strcmp(type, TAG_IDENTIFY) == 0 && payload != NULL) {
                pthread_mutex_lock(&clients_mutex);
                if (clients[client_index].active) { // Check again inside lock
                    strncpy(clients[client_index].client_id, payload, sizeof(clients[client_index].client_id) - 1);
                    clients[client_index].client_id[sizeof(clients[client_index].client_id) - 1] = '\0'; // Ensure null termination
                    client_identified = true;
                     log_message(ID_CONTROL, "INFO: Client fd %d identified as %s.", sock_fd, clients[client_index].client_id);
                }
                 pthread_mutex_unlock(&clients_mutex);

                 if(!client_identified) break; // Client removed while identifying?

                 // Optional: Send acknowledgement or initial command
                 // send_to_client(client_index, "ACK:IDENTIFY:OK\n");

            } else {
                log_message(ID_CONTROL, "WARN: Client fd %d sent invalid first message (expected IDENTIFY): %s", sock_fd, type);
                 // Consider sending an error and closing connection
                 // const char *errMsg = "ERROR:Invalid identification\n";
                 // send(sock_fd, errMsg, strlen(errMsg), 0);
                 break; // Disconnect unidentified client sending wrong message
            }
        } else {
             // Handle subsequent messages from identified client
            log_message(clients[client_index].client_id, "Received raw: %s:%s", type, payload ? payload : "<NULL>"); // Log from client's perspective

            if (strcmp(type, TAG_INTEL) == 0 && payload != NULL) {
                char *intel_source = strtok(payload, ":");
                char *intel_data = strtok(NULL, ""); // Get rest of payload
                if (intel_source && intel_data) {
                    log_message(ID_CONTROL, "INTEL received from %s: %s", intel_source, intel_data);
                    // Potentially trigger threat assessment based on intel
                    assess_threat_and_decide(intel_source, intel_data);
                } else {
                    log_message(ID_CONTROL, "WARN: Malformed INTEL message from %s.", clients[client_index].client_id);
                }
            } else if (strcmp(type, TAG_STATUS) == 0 && payload != NULL) {
                log_message(ID_CONTROL, "STATUS update from %s: %s", clients[client_index].client_id, payload);
                // Update internal state if necessary (e.g., track readiness)
            } else if (strcmp(type, TAG_LAUNCH_ACK) == 0 && payload != NULL) {
                log_message(ID_CONTROL, "LAUNCH ACK from %s: %s", clients[client_index].client_id, payload);
                // Handle launch confirmation/failure
            }
             else if (strcmp(type, TAG_IDENTIFY) == 0) {
                 log_message(ID_CONTROL, "WARN: Client %s sent IDENTIFY message again.", clients[client_index].client_id);
                 // Ignore or handle as error? Ignore for now.
             }
            else {
                log_message(ID_CONTROL, "WARN: Received unknown message type '%s' from %s.", type, clients[client_index].client_id);
            }
        }
    } // End while(run_server)

    // --- Client Disconnected or Error ---
    log_message(ID_CONTROL, "INFO: Closing connection for client %s (fd %d).", clients[client_index].client_id[0] ? clients[client_index].client_id : "unknown", sock_fd);
    close(sock_fd);
    remove_client(client_index); // Remove from the active list

    return NULL;
}

// --- War Test Monitor Thread ---
// Only runs if --test is specified
void *war_test_monitor(void *arg) {
    UNUSED(arg);
    log_message(ID_CONTROL, "War Test Monitor active.");
    const char* potential_threats[] = {
        "RADAR:Possible incoming ballistic missile detected.",
        "SATELLITE:Unusual heat signature detected near hostile border.",
        "SUBMARINE:Hostile submarine detected in patrol zone.",
        "RADAR:Multiple unidentified aircraft approaching airspace.",
        "SATELLITE:Large scale troop movement observed.",
    };
    int num_threats = sizeof(potential_threats) / sizeof(potential_threats[0]);

    while (run_server) {
        // Wait for a random interval (e.g., 15-60 seconds)
        int delay = 15 + rand() % 46; // Delay between 15 and 60 seconds
        sleep(delay);

        if (!run_server) break; // Check after sleep

        // Simulate receiving a random threat intel report
        int threat_index = rand() % num_threats;
        char simulated_intel[BUFFER_SIZE];
        snprintf(simulated_intel, BUFFER_SIZE, "%s", potential_threats[threat_index]);

        char *source = strtok(simulated_intel, ":");
        char *data = strtok(NULL, "");

        if (source && data) {
             log_message(ID_CONTROL, "[WAR TEST] Simulated Intel Received from %s: %s", source, data);
             // Assess the simulated threat
             assess_threat_and_decide(source, data);
        }
    }
    log_message(ID_CONTROL, "War Test Monitor stopping.");
    return NULL;
}

// --- Threat Assessment & Decision Logic ---
// Basic example: Launch if specific keywords are detected
void assess_threat_and_decide(const char* intel_source, const char* intel_data) {
    log_message(ID_CONTROL, "Assessing threat from %s: '%s'", intel_source, intel_data);

    bool launch_condition_met = false;
    const char* target_info = "DefaultTargetCoordinates"; // Example target

    // Simple keyword-based assessment (can be much more complex)
    if (strstr(intel_data, "ballistic missile detected") != NULL) {
        log_message(ID_CONTROL, "CRITICAL THREAT DETECTED: Potential incoming missile!");
        launch_condition_met = true;
        target_info = "CounterforceTarget_A";
    } else if (strstr(intel_data, "hostile border") != NULL && strstr(intel_data, "heat signature") != NULL) {
         log_message(ID_CONTROL, "HIGH ALERT: Potential enemy launch preparation detected.");
         // Maybe increase readiness but don't launch yet?
         // For the test, let's make this a launch condition too.
         launch_condition_met = true;
         target_info = "PreemptiveTarget_B";
    } else if (strstr(intel_data, "Hostile submarine") != NULL && strstr(intel_data, "patrol zone") != NULL) {
        log_message(ID_CONTROL, "ALERT: Hostile submarine detected.");
        // Decide if this warrants launch - maybe target the sub's presumed location?
        // Let's make this a launch condition for the test.
        launch_condition_met = true;
        target_info = "AntiSubmarineTarget_C";
    }
     else {
        log_message(ID_CONTROL, "Assessment: Threat level not critical for immediate launch based on current intel.");
        return; // No launch decision
    }


    if (launch_condition_met && war_test_mode) { // Only launch in test mode for this simulation
        log_message(ID_CONTROL, "[WAR TEST] LAUNCH CONDITION MET. Initiating launch sequence...");

        // Decide which asset to use (simple example: prefer Silo if available)
        bool silo_launched = false;
        pthread_mutex_lock(&clients_mutex);
        for(int i=0; i<MAX_CLIENTS; ++i) {
            if(clients[i].active && strncmp(clients[i].client_id, ID_SILO, strlen(ID_SILO)) == 0) {
                 log_message(ID_CONTROL, "[WAR TEST] Selecting Missile Silo (%s) for launch.", clients[i].client_id);
                 send_secure_launch_command(ID_SILO, target_info);
                 silo_launched = true;
                 break; // Launch from one silo for now
            }
        }
        pthread_mutex_unlock(&clients_mutex);


        // If no silo available or preference is Submarine, try submarine
        if (!silo_launched) {
             pthread_mutex_lock(&clients_mutex);
             for(int i=0; i<MAX_CLIENTS; ++i) {
                 if(clients[i].active && strncmp(clients[i].client_id, ID_SUB, strlen(ID_SUB)) == 0) {
                    log_message(ID_CONTROL, "[WAR TEST] No Silo available/chosen. Selecting Submarine (%s) for launch.", clients[i].client_id);
                    send_secure_launch_command(ID_SUB, target_info);
                    break; // Launch from one sub for now
                 }
             }
             pthread_mutex_unlock(&clients_mutex);
        }


    } else if (launch_condition_met && !war_test_mode) {
         log_message(ID_CONTROL, "WARN: Launch condition met, but War Test Mode is OFF. No launch initiated.");
    }
}


// --- Send Secure Launch Command ---
// Sends an encrypted and checksummed launch command to the first available client matching the ID prefix
void send_secure_launch_command(const char* target_client_id_prefix, const char* target_info) {
    char command_payload[BUFFER_SIZE];
    char message_to_send[BUFFER_SIZE];
    unsigned long checksum;
    int target_client_index = -1;

    // Find the target client (first match)
    pthread_mutex_lock(&clients_mutex);
    for (int i = 0; i < MAX_CLIENTS; ++i) {
        if (clients[i].active && strncmp(clients[i].client_id, target_client_id_prefix, strlen(target_client_id_prefix)) == 0) {
            target_client_index = i;
            break;
        }
    }
    pthread_mutex_unlock(&clients_mutex);

    if (target_client_index == -1) {
        log_message(ID_CONTROL, "ERROR: Cannot send launch command. No active client found with prefix: %s", target_client_id_prefix);
        return;
    }

    // 1. Format the command payload (CommandType:Data)
    snprintf(command_payload, sizeof(command_payload), "%s:%s", CMD_LAUNCH, target_info);

    // 2. Calculate checksum based on payload and secret key
    checksum = simple_checksum(command_payload, SHARED_SECRET_KEY);

    // 3. Format the full message (TAG_COMMAND:Payload:Checksum\n)
    snprintf(message_to_send, sizeof(message_to_send), "%s:%s:%lu%c", TAG_COMMAND, command_payload, checksum, MSG_END);

    // 4. Encrypt the payload part (between the first ':' and the last ':')
    // Find the start and end of the payload within message_to_send
    char *payload_start = strchr(message_to_send, MSG_TYPE_SEP);
    char *checksum_start = strrchr(message_to_send, MSG_TYPE_SEP);

    if (payload_start && checksum_start && checksum_start > payload_start) {
        payload_start++; // Move past the first ':'
        size_t payload_len = checksum_start - payload_start;

        log_message(ID_CONTROL, "DEBUG: Encrypting payload part: '%.*s' (len %zu)", (int)payload_len, payload_start, payload_len);
        encrypt_decrypt_xor(payload_start, payload_len, SHARED_SECRET_KEY);
         log_message(ID_CONTROL, "DEBUG: Encrypted message part looks like: '%.*s'", (int)payload_len, payload_start);

         // Reconstruct the final message (optional, as encryption was in-place)
         // snprintf(final_message, sizeof(final_message), "%.*s%s", (int)(payload_start - message_to_send), message_to_send, checksum_start);

    } else {
         log_message(ID_CONTROL, "ERROR: Could not find payload markers for encryption in '%s'. Sending unencrypted.", message_to_send);
         // Fallback: Just send the unencrypted message (or handle error better)
    }

    // 5. Send the (potentially encrypted) message
    log_message(ID_CONTROL, "Sending LAUNCH command to %s (Index %d). Target: %s", clients[target_client_index].client_id, target_client_index, target_info);
    // log_message(ID_CONTROL, "DEBUG: Final message: %s", message_to_send); // Careful logging encrypted data

    send_to_client(target_client_index, message_to_send);
}


// --- Utility Functions ---

// Initialize the clients array
void initialize_clients() {
    pthread_mutex_lock(&clients_mutex);
    for (int i = 0; i < MAX_CLIENTS; ++i) {
        clients[i].socket_fd = -1;
        clients[i].active = false;
        clients[i].client_id[0] = '\0';
         clients[i].thread_id = 0; // Or some invalid thread ID constant if available
    }
    client_count = 0;
    pthread_mutex_unlock(&clients_mutex);
}

// Add a new client connection
int add_client(int socket_fd, struct sockaddr_in address) {
    pthread_mutex_lock(&clients_mutex);
    int client_index = -1;
    if (client_count >= MAX_CLIENTS) {
        log_message(ID_CONTROL, "WARN: Cannot add client fd %d. Maximum client limit (%d) reached.", socket_fd, MAX_CLIENTS);
        pthread_mutex_unlock(&clients_mutex);
        return -1; // Indicate failure
    }

    // Find an empty slot
    for (int i = 0; i < MAX_CLIENTS; ++i) {
        if (!clients[i].active) {
            clients[i].socket_fd = socket_fd;
            clients[i].address = address;
            clients[i].active = true;
            clients[i].client_id[0] = '\0'; // Clear ID until identified
            client_index = i;
            client_count++;
            log_message(ID_CONTROL, "INFO: Client fd %d added at index %d. Total clients: %d.", socket_fd, i, client_count);
            break;
        }
    }
     pthread_mutex_unlock(&clients_mutex);

     if (client_index == -1) {
          // This shouldn't happen if client_count was checked correctly, but defensively:
         log_message(ID_CONTROL, "ERROR: Failed to find empty slot for client fd %d despite count check.", socket_fd);
     }

    return client_index;
}

// Remove a client (e.g., on disconnect)
void remove_client(int client_index) {
    pthread_mutex_lock(&clients_mutex);
    if (client_index >= 0 && client_index < MAX_CLIENTS && clients[client_index].active) {
        log_message(ID_CONTROL, "INFO: Removing client %s (Index %d, fd %d).", clients[client_index].client_id[0] ? clients[client_index].client_id : "unknown", client_index, clients[client_index].socket_fd);
        clients[client_index].active = false;
        clients[client_index].socket_fd = -1; // Mark socket as invalid
        clients[client_index].client_id[0] = '\0';
        clients[client_index].thread_id = 0; // Reset thread ID
        client_count--;
        log_message(ID_CONTROL, "INFO: Total clients: %d.", client_count);
    } else {
         log_message(ID_CONTROL, "WARN: Attempted to remove inactive or invalid client index %d.", client_index);
    }
    pthread_mutex_unlock(&clients_mutex);
}

// Send a message to a specific client
void send_to_client(int client_index, const char *message) {
    int sock_fd = -1;
    pthread_mutex_lock(&clients_mutex);
    if (client_index >= 0 && client_index < MAX_CLIENTS && clients[client_index].active) {
        sock_fd = clients[client_index].socket_fd;
    }
    pthread_mutex_unlock(&clients_mutex);

    if (sock_fd != -1) {
        if (send(sock_fd, message, strlen(message), 0) < 0) {
            // Don't log error here directly, handle_client will detect disconnection
            // perror("ERROR writing to socket"); // Avoid noisy logs if client just disconnected
             log_message(ID_CONTROL,"WARN: Failed to send to client index %d (fd %d), might be disconnected.", client_index, sock_fd);
        }
    } else {
         log_message(ID_CONTROL, "WARN: Attempted to send to inactive client index %d.", client_index);
    }
}

// Signal handler for graceful shutdown
void signal_handler(int signum) {
    if (signum == SIGINT || signum == SIGTERM) {
        printf("\nReceived signal %d. Shutting down server...\n", signum);
        log_message(ID_CONTROL, "INFO: Received signal %d. Initiating shutdown...", signum);
        run_server = false; // Signal loops to stop

        // Close the listening socket to prevent new connections
        if (server_socket_fd != -1) {
            close(server_socket_fd);
            server_socket_fd = -1; // Mark as closed
        }

        // Optionally: Send shutdown command to clients? (May not receive if server closing)

        // Optionally: Try to join threads? (Difficult with detached threads, rely on them exiting)
        // For detached threads, they will eventually notice run_server is false or error on recv/send.
    }
}

// Cleanup resources before exiting
void cleanup_server() {
    printf("Cleaning up server resources...\n");

    // Close listening socket if not already closed by signal handler
    if (server_socket_fd != -1) {
        close(server_socket_fd);
        server_socket_fd = -1;
    }

    // Close all active client sockets
    pthread_mutex_lock(&clients_mutex);
    for (int i = 0; i < MAX_CLIENTS; ++i) {
        if (clients[i].active && clients[i].socket_fd != -1) {
            log_message(ID_CONTROL, "INFO: Closing connection to client %s (fd %d) during cleanup.", clients[i].client_id, clients[i].socket_fd);
            close(clients[i].socket_fd);
            clients[i].socket_fd = -1; // Mark as closed
            clients[i].active = false; // Mark as inactive
            // Note: We don't explicitly cancel/join detached threads here.
            // They should exit naturally when their socket operations fail or they check run_server.
        }
    }
    client_count = 0; // Reset count
    pthread_mutex_unlock(&clients_mutex);

    // Destroy mutex (optional, as process is exiting anyway)
    // pthread_mutex_destroy(&clients_mutex);

    log_message(ID_CONTROL, "Server cleanup complete.");
}


