/**
 * cmd.c
 * this file contains the implementation of the command execution feature for the agent.
 * it includes functions to execute commands, handle command output, and manage command history.
 * this feature is managed by the main.c file, which acts as the central hub for the agent's features.
 * the command execution feature is designed to be flexible and extensible, allowing for future enhancements.
 * 
 * Author: JJDSEC
 * Date: 2025-08-31
 */

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include "cmd.h"

#define BUFFER_SIZE 1024


// 1. Define the signature for our command handler functions.
typedef int (*command_handler_t)(int argc, char *argv[]);

// 2. Define the structure that represents a command.
typedef struct {
    const char *name;          // The command name
    command_handler_t handler; // Pointer to the handler function
    const char *help_text;     // A short description
} command_t;

// --- Forward declare our handler functions ---
int handle_help(int argc, char *argv[]);
int handle_exit(int argc, char *argv[]);
int handle_status(int argc, char *argv[]);
int handle_echo(int argc, char *argv[]);
int cmd_execute(const char* command);


// 3. Build the command table (our list of known commands).
static const command_t commands[] = {
    {"help",   handle_help,   "Displays this help message."},
    {"status", handle_status, "Shows the current application status."},
    {"echo",   handle_echo,   "Prints back the arguments given to it."},
    {"exit",   handle_exit,   "Exits the application."},
    // The last entry must be NULL to act as a sentinel.
    {NULL, NULL, NULL}
};


bool test_cmd_feature() {
    // This function is a placeholder for testing the command feature.
    // It can be expanded to include actual command execution tests.
    if (cmd_execute("echo test") == 0) {
        return true; // Indicate that the test passed
    }
    return false; // Indicate that the test failed
}

void cmd_shell(int client_socket) {
    printf("Opening shell for client on socket %d...\n", client_socket);
    // Here you would implement the logic to open a shell for the client

    char input_buffer[256];
    char *args[20]; // Max 20 arguments
    int argc;

    while (1) {
        // Prompt for input
        printf("shell> ");
        if (fgets(input_buffer, sizeof(input_buffer), stdin) == NULL) {
            printf("Error reading input or EOF reached. Exiting shell.\n");
            break;
        }

        // Remove newline character from input
        input_buffer[strcspn(input_buffer, "\n")] = 0;

        // Tokenize input into arguments
        argc = 0;
        char *token = strtok(input_buffer, " ");
        while (token != NULL && argc < 20) {
            args[argc++] = token;
            token = strtok(NULL, " ");
        }
        args[argc] = NULL; // Null-terminate the argument list

        // Check for exit command
        if (argc > 0 && strcmp(args[0], "exit") == 0) {
            printf("Exiting shell.\n");
            break;
        }

        // Execute the command
        if (argc > 0) {
            cmd_execute(input_buffer);
        }
    }
}

int cmd_execute(const char* command) {
    printf("[CMD] Executing command: %s\n", command);
    char buffer[BUFFER_SIZE];


    // The "r" means we are opening the process for reading its output.
    // Use "w" if you want to write to the process's standard input.
    FILE *pipe = popen(command, "r");
    
    if (pipe == NULL) {
        perror("popen");
        exit(EXIT_FAILURE);
    }
    
    printf("--- Output of '%s' ---\n", command);
    
    // Read the output from the command line by line
    while (fgets(buffer, sizeof(buffer), pipe) != NULL) {
        printf("%s", buffer);
    }
    
    printf("--- End of output ---\n");

    // **Crucially, you must close the pipe with pclose()**
    // This waits for the command to terminate.
    int status = pclose(pipe);
    printf("pclose() returned status: %d\n", status);

    if (WIFEXITED(status)) {
        int exit_code = WEXITSTATUS(status);
        printf("✅ Command exited normally with exit code: %d\n", exit_code);
        return exit_code;
    } else {
        printf("❌ Command terminated abnormally.\n");
    }
    return status;
}


// --- Implementations of the handler functions ---

int handle_help(int argc, char *argv[]) {
    printf("Available commands:\n");
    // Iterate through the command table until the NULL sentinel is found
    for (int i = 0; commands[i].name != NULL; i++) {
        printf("  %-10s - %s\n", commands[i].name, commands[i].help_text);
    }
    return 0; // Success
}

int handle_exit(int argc, char *argv[]) {
    printf("Exiting...\n");
    return 1; // Return a special value to signal the main loop to exit
}

int handle_status(int argc, char *argv[]) {
    printf("Application status: OK\n");
    printf("Uptime: 42 seconds\n");
    return 0; // Success
}

int handle_echo(int argc, char *argv[]) {
    // Start from 1 to skip the command name itself
    for (int i = 1; i < argc; i++) {
        printf("%s ", argv[i]);
    }
    printf("\n");
    return 0; // Success
}


// build functions according to signatures