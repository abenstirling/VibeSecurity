#!/bin/bash
# Build script for Go scanner - supports multiple architectures

echo "Building Go scanner for multiple platforms..."

# Clean previous builds
rm -f goscan goscan-*

# Build for Linux (most common server deployment)
echo "Building for Linux amd64..."
GOOS=linux GOARCH=amd64 go build -o goscan-linux-amd64 main.go

# Build for macOS (local development)
echo "Building for macOS amd64..."
GOOS=darwin GOARCH=amd64 go build -o goscan-darwin-amd64 main.go

# Build for macOS Apple Silicon (local development)
echo "Building for macOS arm64..."
GOOS=darwin GOARCH=arm64 go build -o goscan-darwin-arm64 main.go

# Create a symlink for the current platform
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    ln -sf goscan-linux-amd64 goscan
    echo "Created symlink for Linux"
elif [[ "$OSTYPE" == "darwin"* ]]; then
    if [[ $(uname -m) == "arm64" ]]; then
        ln -sf goscan-darwin-arm64 goscan
        echo "Created symlink for macOS ARM64"
    else
        ln -sf goscan-darwin-amd64 goscan
        echo "Created symlink for macOS AMD64"
    fi
else
    echo "Unknown platform, using Linux binary as default"
    ln -sf goscan-linux-amd64 goscan
fi

echo "Build complete!"
ls -la goscan*