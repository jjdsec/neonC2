#!/bin/bash

# Build script for cross-compiling NeonC2 client for multiple platforms
# Usage: ./build.sh [server_url]
# Example: ./build.sh http://192.168.1.100:8080

set -e

VERSION="1.0.0"
BUILD_DIR="build"
MAIN_FILE="main.go"
SERVER_URL="${1:-}"

# Create build directory
mkdir -p $BUILD_DIR

# Build flags
LDFLAGS="-s -w"
if [ -n "$SERVER_URL" ]; then
    LDFLAGS="$LDFLAGS -X main.buildServerURL=$SERVER_URL"
    echo "Building with embedded server URL: $SERVER_URL"
else
    echo "Building without embedded server URL (will use default or -server flag)"
fi

echo "Building NeonC2 Client for multiple platforms..."

# Linux builds
echo "Building for Linux..."
GOOS=linux GOARCH=amd64 go build -ldflags="$LDFLAGS" -o $BUILD_DIR/neonc2-client-linux-amd64 $MAIN_FILE
GOOS=linux GOARCH=arm64 go build -ldflags="$LDFLAGS" -o $BUILD_DIR/neonc2-client-linux-arm64 $MAIN_FILE
GOOS=linux GOARCH=386 go build -ldflags="$LDFLAGS" -o $BUILD_DIR/neonc2-client-linux-386 $MAIN_FILE

# Windows builds
echo "Building for Windows..."
GOOS=windows GOARCH=amd64 go build -ldflags="$LDFLAGS" -o $BUILD_DIR/neonc2-client-windows-amd64.exe $MAIN_FILE
GOOS=windows GOARCH=386 go build -ldflags="$LDFLAGS" -o $BUILD_DIR/neonc2-client-windows-386.exe $MAIN_FILE

# macOS builds
echo "Building for macOS..."
GOOS=darwin GOARCH=amd64 go build -ldflags="$LDFLAGS" -o $BUILD_DIR/neonc2-client-darwin-amd64 $MAIN_FILE
GOOS=darwin GOARCH=arm64 go build -ldflags="$LDFLAGS" -o $BUILD_DIR/neonc2-client-darwin-arm64 $MAIN_FILE

echo "Build complete! Binaries are in the $BUILD_DIR directory:"
ls -lh $BUILD_DIR/
