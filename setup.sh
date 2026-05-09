#!/bin/bash
# ============================================================
# setup.sh — Automated Linux Setup Script
# AI-Powered Linux Network Threat Analyzer
#
# Run this once to set up everything:
#   chmod +x setup.sh
#   ./setup.sh
# ============================================================

set -e  # Stop script if any command fails

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No color

echo -e "${CYAN}"
echo "======================================================"
echo "  AI Network Threat Analyzer — Setup Script"
echo "======================================================"
echo -e "${NC}"

# ---- Check Python version ----
echo -e "${YELLOW}[1/6] Checking Python version...${NC}"
PYTHON_VERSION=$(python3 --version 2>&1 | awk '{print $2}')
MAJOR=$(echo $PYTHON_VERSION | cut -d. -f1)
MINOR=$(echo $PYTHON_VERSION | cut -d. -f2)

if [ "$MAJOR" -lt 3 ] || ([ "$MAJOR" -eq 3 ] && [ "$MINOR" -lt 8 ]); then
    echo -e "${RED}ERROR: Python 3.8+ required. Found: $PYTHON_VERSION${NC}"
    exit 1
fi
echo -e "${GREEN}✓ Python $PYTHON_VERSION found${NC}"

# ---- Install system packages ----
echo -e "${YELLOW}[2/6] Installing system dependencies...${NC}"
if command -v apt &> /dev/null; then
    sudo apt update -q
    sudo apt install -y python3-pip python3-venv libpcap-dev tcpdump -q
    echo -e "${GREEN}✓ System packages installed (apt)${NC}"
elif command -v dnf &> /dev/null; then
    sudo dnf install -y python3-pip libpcap-devel -q
    echo -e "${GREEN}✓ System packages installed (dnf)${NC}"
elif command -v pacman &> /dev/null; then
    sudo pacman -S --noconfirm python-pip libpcap
    echo -e "${GREEN}✓ System packages installed (pacman)${NC}"
else
    echo -e "${YELLOW}⚠ Unknown package manager. Install libpcap manually.${NC}"
fi

# ---- Create virtual environment ----
echo -e "${YELLOW}[3/6] Creating Python virtual environment...${NC}"
if [ ! -d "venv" ]; then
    python3 -m venv venv
    echo -e "${GREEN}✓ Virtual environment created${NC}"
else
    echo -e "${GREEN}✓ Virtual environment already exists${NC}"
fi

# Activate venv
source venv/bin/activate

# ---- Install Python packages ----
echo -e "${YELLOW}[4/6] Installing Python packages...${NC}"
pip install --quiet --upgrade pip
pip install --quiet -r requirements.txt
echo -e "${GREEN}✓ Python packages installed${NC}"

# ---- Create .env file ----
echo -e "${YELLOW}[5/6] Setting up environment file...${NC}"
if [ ! -f ".env" ]; then
    cp .env.example .env
    # Generate a random secret key
    SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")
    sed -i "s/your_random_secret_key_here/$SECRET_KEY/" .env
    echo -e "${GREEN}✓ .env file created with random secret key${NC}"
    echo -e "${YELLOW}  → Edit .env to add your AbuseIPDB API key (optional)${NC}"
else
    echo -e "${GREEN}✓ .env file already exists${NC}"
fi

# ---- Create required directories ----
echo -e "${YELLOW}[6/6] Creating directories...${NC}"
mkdir -p logs reports/csv reports/pdf database ai_engine/models
echo -e "${GREEN}✓ Directories created${NC}"

# ---- Done! ----
echo ""
echo -e "${GREEN}======================================================"
echo "  Setup Complete!"
echo "======================================================"
echo -e "${NC}"
echo "Next steps:"
echo ""
echo "  1. Review settings:"
echo "     nano config/config.ini"
echo ""
echo "  2. Run the analyzer (requires sudo for packet capture):"
echo "     source venv/bin/activate"
echo "     sudo venv/bin/python3 main.py"
echo ""
echo "  3. Open dashboard in browser:"
echo "     http://127.0.0.1:5000"
echo ""
echo "  4. (Optional) Add AbuseIPDB API key to .env"
echo "     nano .env"
echo ""
