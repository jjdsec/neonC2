// client_interactive.c

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/select.h> // Required for select()

#define STDIN 0 // File descriptor for standard input

int main(int argc, char *argv[]) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <server_ip> <port>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    char *server_ip = argv[1];
    int port = atoi(argv[2]);
    int sock = 0;
    struct sockaddr_in serv_addr;

    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("socket"); exit(EXIT_FAILURE);
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(port);

    if (inet_pton(AF_INET, server_ip, &serv_addr.sin_addr) <= 0) {
        perror("inet_pton"); exit(EXIT_FAILURE);
    }

    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("connect"); exit(EXIT_FAILURE);
    }

    printf("# Connected to server. You can start typing.\nType 'exit' to quit.\n");

    while (1) {
        fd_set read_fds; // Set of file descriptors to monitor for reading
        FD_ZERO(&read_fds); // Clear the set
        FD_SET(STDIN, &read_fds); // Add standard input (keyboard) to the set
        FD_SET(sock, &read_fds); // Add the client socket to the set

        // select() is a blocking call, it will wait until one of the fds is ready
        if (select(sock + 1, &read_fds, NULL, NULL, NULL) < 0) {
            perror("select");
            exit(EXIT_FAILURE);
        }

        // Check if standard input is ready
        if (FD_ISSET(STDIN, &read_fds)) {
            char send_buffer[1024];
            if (fgets(send_buffer, sizeof(send_buffer), stdin) != NULL) {
                // Remove newline character from fgets
                send_buffer[strcspn(send_buffer, "\n")] = 0;
                
                send(sock, send_buffer, strlen(send_buffer), 0);
                
                if (strncmp(send_buffer, "exit", 4) == 0) {
                    printf("# Disconnecting...\n");
                    break;
                }
            }
        }
        
        // Check if the socket is ready
        if (FD_ISSET(sock, &read_fds)) {
            char recv_buffer[1024] = {0};
            ssize_t bytes_read = read(sock, recv_buffer, sizeof(recv_buffer) - 1);
            if (bytes_read > 0) {
                printf("Server: %s\n", recv_buffer);
            } else {
                // If read returns 0, the server has closed the connection
                printf("# Server disconnected.\n");
                break;
            }
        }
    }

    close(sock);
    return 0;
}