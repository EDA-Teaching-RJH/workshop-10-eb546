#include "common.h"

static unsigned char satellite_key[KEY_SIZE];

// Function to simulate satellite imagery
void capture_imagery(int sock, unsigned char *key) {
    const char *satellite_reports[] = {
        "No unusual activity detected",
        "Possible missile silo activity at coordinates 45.678, -123.456",
        "Large military movement detected",
        "Infrared signature detected in restricted area",
        "All quiet on surveillance sectors",
        "Detected possible launch preparation"
    };
    
    int report_idx = rand() % (sizeof(satellite_reports) / sizeof(satellite_reports[0]));
    
    SecureMessage msg;
    msg.type = MSG_INTEL;
    strcpy(msg.sender, "SATELLITE");
    strcpy(msg.payload, satellite_reports[report_idx]);
    
    encrypt_message(&msg, key);
    send(sock, &msg, sizeof(msg), 0);
}

int main() {
    // Initialize crypto
    init_crypto();
    
    // In a real system, this would be pre-shared or exchanged via secure channel
    memcpy(satellite_key, "SECRET_KEY_SATELLITE_123456", KEY_SIZE);
    
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
    
    log_message("Surveillance satellite connected to Control");
    
    // Register with control
    SecureMessage msg;
    msg.type = MSG_REGISTER;
    strcpy(msg.sender, "SATELLITE");
    strcpy(msg.payload, "Satellite operational");
    
    encrypt_message(&msg, satellite_key);
    send(sock, &msg, sizeof(msg), 0);
    
    // Main loop
    while (1) {
        // Capture imagery at random intervals
        if (rand() % 10 < 4) { // 40% chance each iteration
            capture_imagery(sock, satellite_key);
        }
        
        // Check for messages from control (though satellite typically doesn't receive commands)
        fd_set read_fds;
        FD_ZERO(&read_fds);
        FD_SET(sock, &read_fds);
        
        struct timeval tv;
        tv.tv_sec = 5;
        tv.tv_usec = 0;
        
        if (select(sock + 1, &read_fds, NULL, NULL, &tv) > 0) {
            if (FD_ISSET(sock, &read_fds)) {
                int bytes_received = recv(sock, &msg, sizeof(msg), 0);
                if (bytes_received <= 0) {
                    handle_error("Connection lost", false);
                    break;
                }
                
                if (verify_message(&msg, satellite_key)) {
                    decrypt_message(&msg, satellite_key);
                    
                    if (msg.type == MSG_STATUS) {
                        log_message(msg.payload);
                    } else {
                        log_message("Received unexpected message type");
                    }
                } else {
                    log_message("Message verification failed - possible security breach!");
                }
            }
        }
        
        sleep(5); // Prevent busy waiting
    }
    
    close(sock);
    cleanup_crypto();
    return 0;
}

