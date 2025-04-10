#include "common.h"

static unsigned char silo_key[KEY_SIZE];
static bool launch_capability = true;

// Function to simulate missile launch
void launch_missile(const char *target_info) {
    char log_msg[BUFFER_SIZE];
    snprintf(log_msg, sizeof(log_msg), "MISSILE SILO: Launching missile at %s", target_info);
    log_message(log_msg);
    
    // Simulate launch sequence
    for (int i = 5; i > 0; i--) {
        snprintf(log_msg, sizeof(log_msg), "Launch in %d...", i);
        log_message(log_msg);
        sleep(1);
    }
    
    log_message("Missile launched!");
}

int main() {
    // Initialize crypto
    init_crypto();
    
    // In a real system, this would be pre-shared or exchanged via secure channel
    memcpy(silo_key, "SECRET_KEY_MISSILE_SILO_1234567890", KEY_SIZE);
    
    // Create socket
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        handle_error("Socket creation failed", true);
    }
    
    // Configure server address
    struct sockaddr_in serv_addr;
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(CONTROL_PORT);
    
    if (inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr) <= 0) {
        handle_error("Invalid address", true);
    }
    
    // Connect to control
    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        handle_error("Connection failed", true);
    }
    
    log_message("Missile Silo connected to Control");
    
    // Register with control
    SecureMessage msg;
    msg.type = MSG_REGISTER;
    strcpy(msg.sender, "MISSILE_SILO");
    strcpy(msg.payload, "Ready for commands");
    
    encrypt_message(&msg, silo_key);
    send(sock, &msg, sizeof(msg), 0);
    
    // Main loop
    while (1) {
        int bytes_received = recv(sock, &msg, sizeof(msg), 0);
        if (bytes_received <= 0) {
            handle_error("Connection lost", false);
            break;
        }
        
        if (verify_message(&msg, silo_key)) {
            decrypt_message(&msg, silo_key);
            
            switch(msg.type) {
                case MSG_LAUNCH_ORDER:
                    if (launch_capability) {
                        launch_missile(msg.payload);
                        
                        // Send confirmation
                        SecureMessage response;
                        response.type = MSG_LAUNCH_CONFIRM;
                        strcpy(response.sender, "MISSILE_SILO");
                        strcpy(response.payload, "Launch sequence completed");
                        encrypt_message(&response, silo_key);
                        send(sock, &response, sizeof(response), 0);
                    } else {
                        log_message("Launch order received but capability offline");
                    }
                    break;
                    
                case MSG_STATUS:
                    log_message(msg.payload);
                    break;
                    
                default:
                    log_message("Received unknown message type");
                    break;
            }
        } else {
            log_message("Message verification failed - possible security breach!");
        }
    }
    
    close(sock);
    cleanup_crypto();
    return 0;
}

