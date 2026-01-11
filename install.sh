#!/bin/bash
# Sentinel Installation Script

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${GREEN}Installing Sentinel...${NC}"

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Please run as root (sudo ./install.sh)${NC}"
    exit 1
fi

# Determine script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Check if binary exists
if [ ! -f "$SCRIPT_DIR/target/release/sentinel" ]; then
    echo -e "${YELLOW}Binary not found. Building...${NC}"
    cd "$SCRIPT_DIR"
    cargo build --release
fi

# Create directories
echo "Creating directories..."
mkdir -p /etc/sentinel
mkdir -p /var/lib/sentinel
mkdir -p /var/log

# Install binary
echo "Installing binary..."
cp "$SCRIPT_DIR/target/release/sentinel" /usr/local/bin/sentinel
chmod 755 /usr/local/bin/sentinel

# Install config if not exists
if [ ! -f /etc/sentinel/config.yaml ]; then
    echo "Installing default configuration..."
    cp "$SCRIPT_DIR/configs/default.yaml" /etc/sentinel/config.yaml
else
    echo -e "${YELLOW}Config exists, skipping...${NC}"
fi

# Install systemd service
echo "Installing systemd service..."
cp "$SCRIPT_DIR/sentinel.service" /etc/systemd/system/sentinel.service
systemctl daemon-reload

# Enable service
echo "Enabling service..."
systemctl enable sentinel.service

echo ""
echo -e "${GREEN}Installation complete!${NC}"
echo ""
echo "Commands:"
echo "  sudo systemctl start sentinel    # Start service"
echo "  sudo systemctl stop sentinel     # Stop service"
echo "  sudo systemctl status sentinel   # Check status"
echo "  sudo journalctl -u sentinel -f   # View logs"
echo ""
echo "Configuration: /etc/sentinel/config.yaml"
echo ""
echo -e "${YELLOW}Note: Edit /etc/sentinel/config.yaml before starting${NC}"
