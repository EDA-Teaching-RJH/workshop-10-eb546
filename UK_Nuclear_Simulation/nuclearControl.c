#include "common.h"

// Global variables
static unsigned char control_key[KEY_SIZE];
static Target targets[MAX_TARGETS];
static int target_count = 0;
static bool test_mode = false;
static pthread_mutex_t target_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;

// Function to load targets from file
void load_targets() {
    FILE *file = fopen("targets.dat", "rb");
    if (file) {
        pthread_mutex_lock(&target_mutex);
        target_count = fread(targets, sizeof(Target), MAX_TARGETS, file);
        pthread_mutex_unlock(&target_mutex);
        fclose(file);
        log_message("Loaded targets from file");
    } else {
        log_message("No targets file found, starting with empty target list");
    }
}

// Function to save targets to file
void save_targets() {
    FILE *file = fopen("targets.dat", "wb");
    if (file) {
        pthread_mutex_lock(&target_mutex);
        fwrite(targets, sizeof(Target), target_count, file);
        pthread_mutex_unlock(&target_mutex);
        fclose(file);
        log_message("Saved targets to file");
    } else {
        handle_error("Failed to save targets", false);
    }
}

// Function to process incoming messages
void process_message(int client_socket, SecureMessage *msg) {
    char log_msg[BUFFER_SIZE * 2];
    
    switch(msg->type) {
        case MSG_REGISTER:
            snprintf(log_msg, sizeof(log_msg), "%s registered with control", msg->sender);
            log_message(log_msg);
            
            // Send acknowledgement
            SecureMessage response;
            response.type = MSG_STATUS;
            strcpy(response.sender, "CONTROL");
            strcpy(response.payload, "Registered successfully");
            encrypt_message(&response, control_key);
            send(client_socket, &response, sizeof(response), 0);
            break;
            
        case MSG_INTEL:
            snprintf(log_msg, sizeof(log_msg), "Intel received from %s: %s", msg->sender, msg->payload);
            log_message(log_msg);
            
            // In test mode, randomly decide if this is a threat
            if (test_mode && rand() % 100 < 30) { // 30% chance of threat in test mode
                log_message("TEST MODE: Simulated threat detected!");
                
                // Select a random target
                pthread_mutex_lock(&target_mutex);
                int target_idx = rand() % target_count;
                Target target = targets[target_idx];
                pthread_mutex_unlock(&target_mutex);
                
                // Decide launch platform based on target location
                const char *platform = (target.longitude < -30) ? "SUBMARINE" : "MISSILE_SILO";
                
                snprintf(log_msg, sizeof(log_msg), 
                        "TEST MODE: Launching nuclear strike on %s via %s", 
                        target.name, platform);
                log_message(log_msg);
                
                // Prepare launch order
                SecureMessage launch_order;
                launch_order.type = MSG_LAUNCH_ORDER;
                strcpy(launch_order.sender, "CONTROL");
                snprintf(launch_order.payload, sizeof(launch_order.payload),
                        "TARGET:%s,LAT:%f,LON:%f", target.name, target.latitude, target.longitude);
                
                encrypt_message(&launch_order, control_key);
                send(client_socket, &launch_order, sizeof(launch_order), 0);
            }
            break;
            
        case MSG_LAUNCH_CONFIRM:
            snprintf(log_msg, sizeof(log_msg), "Launch confirmed by %s: %s", msg->sender, msg->payload);
            log_message(log_msg);
            break;
            
        default:
            snprintf(log_msg, sizeof(log_msg), "Unknown message type from %s", msg->sender);
            log_message(log_msg);
            break;
    }
}

// Thread function to handle client connections
void *handle_client(void *arg) {
    int client_socket = *((int *)arg);
    free(arg);
    
    SecureMessage msg;
    int bytes_received;
    
    while ((bytes_received = recv(client_socket, &msg, sizeof(msg), 0)) > 0) {
        if (bytes_received != sizeof(msg)) {
            log_message("Received incomplete message");
            continue;
        }
        
        if (verify_message(&msg, control_key)) {
            decrypt_message(&msg, control_key);
            process_message(client_socket, &msg);
        } else {
            log_message("Message verification failed - possible security breach!");
        }
    }
    
    close(client_socket);
    return NULL;
}

int main(int argc, char *argv[]) {
    // Check for test mode
    if (argc > 1 && strcmp(argv[1], "--test") == 0) {
        test_mode = true;
        log_message("TEST MODE ACTIVATED - Simulated war scenario");
    }
    
    // Initialize crypto
    init_crypto();
    generate_random_key(control_key, KEY_SIZE);
    
    // Load targets
    load_targets();
    
    // Create server socket
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        handle_error("Socket creation failed", true);
    }
    
    // Set socket options
    int opt = 1;
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
        handle_error("Setsockopt failed", true);
    }
    
    // Bind socket
    struct sockaddr_in address;
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(CONTROL_PORT);
    
    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        handle_error("Bind failed", true);
    }
    
    // Listen for connections
    if (listen(server_fd, MAX_CLIENTS) < 0) {
        handle_error("Listen failed", true);
    }
    
    log_message("Nuclear Control Center operational and listening for connections");
    
    // Main server loop
    while (1) {
        int new_socket;
        int addrlen = sizeof(address);
        
        if ((new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen)) < 0) {
            handle_error("Accept failed", false);
            continue;
        }
        
        // Log new connection
        char ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &address.sin_addr, ip_str, INET_ADDRSTRLEN);
        char log_msg[100];
        snprintf(log_msg, sizeof(log_msg), "New connection from %s", ip_str);
        log_message(log_msg);
        
        // Create thread for client
        pthread_t thread_id;
        int *client_socket = malloc(sizeof(int));
        *client_socket = new_socket;
        
        if (pthread_create(&thread_id, NULL, handle_client, (void*)client_socket) < 0) {
            handle_error("Thread creation failed", false);
            free(client_socket);
            close(new_socket);
        }
        
        // Detach thread so resources are automatically freed on exit
        pthread_detach(thread_id);
    }
    
    // Cleanup (though we never get here in this simple example)
    close(server_fd);
    cleanup_crypto();
    save_targets();
    return 0;
}

void process_and_decrypt_message(int client_socket, SecureMessage *msg, unsigned char *key) {
    char log_msg[BUFFER_SIZE * 2];
    
    if (!verify_message(msg, key)) {
        log_message("Message verification failed - possible security breach!");
        return;
    }
    
    if (!decrypt_message(msg, key)) {
        log_message("Failed to decrypt message");
        return;
    }
    
    snprintf(log_msg, sizeof(log_msg), "Decrypted message from %s: %s", 
             msg->sender, msg->payload);
    log_message(log_msg);
    
    // Rest of your processing logic...
    process_message(client_socket, msg);
}

