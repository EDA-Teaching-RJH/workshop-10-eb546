#include "common.h"

static unsigned char radar_key[KEY_SIZE];

// Function to simulate radar sweep
void perform_radar_sweep(int sock, unsigned char *key) {
    const char *radar_reports[] = {
        "Airspace clear",
        "Detected commercial aircraft at 30,000ft",
        "Unidentified contact at 45,000ft bearing 245",
        "Weather front detected moving east",
        "Multiple fast-moving contacts at low altitude",
        "No contacts detected"
    };
    
    int report_idx = rand() % (sizeof(radar_reports) / sizeof(radar_reports[0]));
    
    SecureMessage msg;
    msg.type = MSG_INTEL;
    strcpy(msg.sender, "RADAR");
    strcpy(msg.payload, radar_reports[report_idx]);
    
    encrypt_message(&msg, key);
    send(sock, &msg, sizeof(msg), 0);
}

int main() {
    // Initialize crypto
    init_crypto();
    
    // In a real system, this would be pre-shared or exchanged via secure channel
    memcpy(radar_key, "SECRET_KEY_RADAR_1234567890", KEY_SIZE);
    
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
    
    log_message("Radar station connected to Control");
    
    // Register with control
    SecureMessage msg;
    msg.type = MSG_REGISTER;
    strcpy(msg.sender, "RADAR");
    strcpy(msg.payload, "Radar operational");
    
    encrypt_message(&msg, radar_key);
    send(sock, &msg, sizeof(msg), 0);
    
    // Main loop
    while (1) {
        // Perform regular radar sweeps
        perform_radar_sweep(sock, radar_key);
        
        // Check for messages from control (though radar typically doesn't receive commands)
        fd_set read_fds;
        FD_ZERO(&read_fds);
        FD_SET(sock, &read_fds);
        
        struct timeval tv;
        tv.tv_sec = 10; // Sweep every 10 seconds
        tv.tv_usec = 0;
        
        if (select(sock + 1, &read_fds, NULL, NULL, &tv) > 0) {
            if (FD_ISSET(sock, &read_fds)) {
                int bytes_received = recv(sock, &msg, sizeof(msg), 0);
                if (bytes_received <= 0) {
                    handle_error("Connection lost", false);
                    break;
                }
                
                if (verify_message(&msg, radar_key)) {
                    decrypt_message(&msg, radar_key);
                    
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
    }
    
    close(sock);
    cleanup_crypto();
    return 0;
}