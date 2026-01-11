#!/bin/bash
# Sentinel Uninstallation Script

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${YELLOW}Uninstalling Sentinel...${NC}"

if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Please run as root (sudo ./uninstall.sh)${NC}"
    exit 1
fi

# Stop and disable service
if systemctl is-active --quiet sentinel 2>/dev/null; then
    echo "Stopping service..."
    systemctl stop sentinel
fi

if systemctl is-enabled --quiet sentinel 2>/dev/null; then
    echo "Disabling service..."
    systemctl disable sentinel
fi

# Remove files
echo "Removing files..."
rm -f /usr/local/bin/sentinel
rm -f /etc/systemd/system/sentinel.service
systemctl daemon-reload

echo ""
read -p "Remove configuration and data? (y/N) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    rm -rf /etc/sentinel
    rm -rf /var/lib/sentinel
    echo "Configuration and data removed."
else
    echo -e "${YELLOW}Keeping /etc/sentinel and /var/lib/sentinel${NC}"
fi

echo ""
echo -e "${GREEN}Uninstallation complete!${NC}"
