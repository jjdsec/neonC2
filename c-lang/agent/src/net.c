/**
 * net.c
 * this file contains the implementation of the network communication feature for the agent.
 * it includes functions to establish a connection, send and receive data, and handle network errors.
 * this feature is managed by the main.c file, which acts as the central hub for the agent's features.
 * the network communication feature is designed to be flexible and extensible, allowing for future enhancements.
 * 
 * Author: JJDSEC
 * Date: 2025-08-31
 */

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <pthread.h> // Include the pthread library
#include "net.h"
#include <errno.h>

#define AUTH_CODE "NEONC2" // Authentication code for the agent
#define NETIN_HEADERSIZE sizeof(AUTH_CODE) // Size of the header for incoming data
#define PORT 8080
#define MAX_PENDING_CONNECTIONS 3
static net_client_handler_t g_client_handler = NULL;
void *handle_client_thread(void *socket_desc_ptr); // Forward declaration

bool test_net_feature() {

        int sock_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (sock_fd < 0) {
        perror("socket");
        return 1;
    }

    struct sockaddr_in address;
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    // Attempt to bind to the port
    if (bind(sock_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        // Check if the specific error is "Address already in use"
        if (errno == EADDRINUSE) {
            printf("❌ Port %d is already in use.\n", PORT);
        } else {
            // Some other error occurred
            perror("❌ bind failed");
        }
        close(sock_fd);
        return false;
    }

    printf("✅ Port %d is available and has been successfully bound.\n", PORT);
    close(sock_fd);
    return true;
}

bool net_init(net_client_handler_t callback) {
    
    printf("[NET] Initializing connection handler...\n");
    // register the callback function
    if (callback == NULL) {
        fprintf(stderr, "[NET] Callback function cannot be NULL.\n");
        return false;
    }
    g_client_handler = callback;


    // setup and start server
    printf("[NET] Initializing network server...\n");
    int server_socket;
    struct sockaddr_in address;
    int opt = 1;

    // 1. Create the socket file descriptor
    if ((server_socket = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    // 2. Set socket options to allow reusing the port
    if (setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    // 3. Bind the socket
    if (bind(server_socket, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }

    // 4. Listen for incoming connections
    if (listen(server_socket, MAX_PENDING_CONNECTIONS) < 0) {
        perror("listen");
        exit(EXIT_FAILURE);
    }
    printf("Server listening on port %d\n", PORT);

    // 5. handle connections
    while (1) {
        int new_socket;
        int addrlen = sizeof(address);
        if ((new_socket = accept(server_socket, (struct sockaddr *)&address, (socklen_t*)&addrlen)) < 0) {
            perror("accept");
            continue;
        }
        
        pthread_t thread_id;
        int *new_sock_ptr = malloc(sizeof(int));
        *new_sock_ptr = new_socket;

        if (pthread_create(&thread_id, NULL, handle_client_thread, (void*) new_sock_ptr) < 0) {
            perror("could not create thread");
            free(new_sock_ptr);
        }
        pthread_detach(thread_id);
    }
}

void *handle_client_thread(void *socket_desc_ptr) {
    int sock = *(int*)socket_desc_ptr;
    free(socket_desc_ptr);
    char auth_buf[NETIN_HEADERSIZE] = {0};

    ssize_t bytes_read_h = read(sock, auth_buf, NETIN_HEADERSIZE);

    if (bytes_read_h < 0) {
        perror("read failed");
        close(sock);
        return NULL;
    } else if (bytes_read_h == 0) {
        printf("Client disconnected.\n");
        close(sock);
        return NULL;
    } else {
        printf("Received auth header: %s\n", auth_buf);
        if (strncmp(auth_buf, AUTH_CODE, NETIN_HEADERSIZE) != 0) {
            printf("Invalid authentication code. Closing connection.\n");
            close(sock);
            return NULL;
        } else {
            // hand off socket to the handler
            g_client_handler(sock);
        }
    }
    close(sock);
    return NULL;
}
