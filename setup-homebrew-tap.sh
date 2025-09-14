# File: setup-homebrew-tap.sh
# Copy to: dcert repository root
# Make executable: chmod +x setup-homebrew-tap.sh

#!/bin/bash
# setup-homebrew-tap.sh - Script to set up dcert Homebrew tap

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}Setting up dcert Homebrew tap...${NC}"

# Check if we're on Linux
if [[ "$OSTYPE" != "linux-gnu"* ]]; then
    echo -e "${RED}Error: This script is for Linux only. dcert Homebrew tap supports Linux.${NC}"
    exit 1
fi

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Check if Homebrew is installed
if ! command_exists brew; then
    echo -e "${YELLOW}Homebrew not found. Installing Homebrew for Linux...${NC}"
    /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
    
    # Add Homebrew to PATH
    echo -e "${YELLOW}Adding Homebrew to PATH...${NC}"
    echo 'eval "$(/home/linuxbrew/.linuxbrew/bin/brew shellenv)"' >> ~/.bashrc
    echo 'eval "$(/home/linuxbrew/.linuxbrew/bin/brew shellenv)"' >> ~/.profile
    
    # Source the new PATH
    eval "$(/home/linuxbrew/.linuxbrew/bin/brew shellenv)"
    
    echo -e "${GREEN}Homebrew installed successfully!${NC}"
else
    echo -e "${GREEN}Homebrew is already installed.${NC}"
fi

# Verify Homebrew is working
if ! command_exists brew; then
    echo -e "${RED}Error: Homebrew installation failed or not in PATH.${NC}"
    echo -e "${YELLOW}Please restart your terminal and run: eval \"\$(/home/linuxbrew/.linuxbrew/bin/brew shellenv)\"${NC}"
    exit 1
fi

# Add the dcert tap
echo -e "${BLUE}Adding dcert tap...${NC}"
USERNAME="${1:-SCGIS-Wales}"  # Allow username as first argument

if brew tap | grep -q "${USERNAME}/tap"; then
    echo -e "${YELLOW}Tap ${USERNAME}/tap is already added.${NC}"
else
    brew tap "${USERNAME}/tap"
    echo -e "${GREEN}Successfully added ${USERNAME}/tap!${NC}"
fi

# Install dcert
echo -e "${BLUE}Installing dcert...${NC}"
if brew list | grep -q "^dcert$"; then
    echo -e "${YELLOW}dcert is already installed. Upgrading...${NC}"
    brew upgrade "${USERNAME}/tap/dcert"
else
    brew install "${USERNAME}/tap/dcert"
fi

# Verify installation
echo -e "${BLUE}Verifying installation...${NC}"
if command_exists dcert; then
    VERSION=$(dcert --version)
    echo -e "${GREEN}✓ dcert installed successfully!${NC}"
    echo -e "${GREEN}✓ Version: ${VERSION}${NC}"
    
    # Show usage example
    echo -e "\n${BLUE}Usage example:${NC}"
    echo -e "${YELLOW}dcert --file /path/to/certificate.pem${NC}"
    echo -e "${YELLOW}dcert --file cert.pem --format json${NC}"
    echo -e "${YELLOW}dcert --help${NC}"
    
else
    echo -e "${RED}✗ Installation verification failed.${NC}"
    exit 1
fi

echo -e "\n${GREEN}🎉 Setup complete! dcert is ready to use.${NC}"