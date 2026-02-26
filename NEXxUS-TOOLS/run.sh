#!/bin/bash
#
# NetVision Launcher Script
# Activates the virtual environment and runs the tool with sudo
#

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="$SCRIPT_DIR/venv"
PYTHON="$VENV_DIR/bin/python3"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${CYAN}"
echo "  ╔══════════════════════════════════════╗"
echo "  ║   🛰️  NetVision Launcher             ║"
echo "  ║   WiFi Network Intelligence Tool     ║"
echo "  ╚══════════════════════════════════════╝"
echo -e "${NC}"

# Check virtual environment
if [ ! -f "$PYTHON" ]; then
    echo -e "${YELLOW}⟐ Setting up virtual environment...${NC}"
    python3 -m venv "$VENV_DIR"
    "$VENV_DIR/bin/pip" install -r "$SCRIPT_DIR/requirements.txt"
    echo -e "${GREEN}✓ Environment ready!${NC}"
fi

# Check for root
if [ "$EUID" -ne 0 ]; then
    echo -e "${YELLOW}⚠ Root privileges recommended for full functionality.${NC}"
    echo -e "${CYAN}  Relaunching with sudo...${NC}"
    echo ""
    sudo "$PYTHON" "$SCRIPT_DIR/netvision.py" "$@"
else
    "$PYTHON" "$SCRIPT_DIR/netvision.py" "$@"
fi
