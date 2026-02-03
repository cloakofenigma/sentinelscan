#!/bin/bash
# SentinelScan Installation Script
# Installs SentinelScan and optionally sets up git hooks

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Paths
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_DIR="${HOME}/.sentinelscan"
BIN_DIR="${HOME}/.local/bin"

echo -e "${BLUE}"
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║              SentinelScan Installation Script                 ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Check Python version
echo -e "${YELLOW}Checking Python version...${NC}"
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}Error: Python 3 is required but not installed.${NC}"
    exit 1
fi

PYTHON_VERSION=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
REQUIRED_VERSION="3.8"

if [ "$(printf '%s\n' "$REQUIRED_VERSION" "$PYTHON_VERSION" | sort -V | head -n1)" != "$REQUIRED_VERSION" ]; then
    echo -e "${RED}Error: Python $REQUIRED_VERSION or higher is required (found $PYTHON_VERSION)${NC}"
    exit 1
fi
echo -e "${GREEN}✓ Python $PYTHON_VERSION found${NC}"

# Check pip
echo -e "${YELLOW}Checking pip...${NC}"
if ! command -v pip3 &> /dev/null; then
    echo -e "${RED}Error: pip3 is required but not installed.${NC}"
    exit 1
fi
echo -e "${GREEN}✓ pip3 found${NC}"

# Create installation directory
echo -e "${YELLOW}Creating installation directory...${NC}"
mkdir -p "$INSTALL_DIR"
mkdir -p "$BIN_DIR"
echo -e "${GREEN}✓ Created $INSTALL_DIR${NC}"

# Create virtual environment
echo -e "${YELLOW}Creating virtual environment...${NC}"
python3 -m venv "$INSTALL_DIR/venv"
source "$INSTALL_DIR/venv/bin/activate"
echo -e "${GREEN}✓ Virtual environment created${NC}"

# Upgrade pip
echo -e "${YELLOW}Upgrading pip...${NC}"
pip install --upgrade pip > /dev/null 2>&1
echo -e "${GREEN}✓ pip upgraded${NC}"

# Install dependencies
echo -e "${YELLOW}Installing dependencies...${NC}"
pip install pyyaml > /dev/null 2>&1

# Install tree-sitter dependencies
echo -e "${YELLOW}Installing tree-sitter parsers...${NC}"
pip install tree-sitter > /dev/null 2>&1
pip install tree-sitter-java tree-sitter-python tree-sitter-javascript 2>/dev/null || true
echo -e "${GREEN}✓ Dependencies installed${NC}"

# Copy source files
echo -e "${YELLOW}Installing SentinelScan...${NC}"
if [ -d "$SCRIPT_DIR/scanengine" ]; then
    cp -r "$SCRIPT_DIR/scanengine" "$INSTALL_DIR/"
    echo -e "${GREEN}✓ Source files copied${NC}"
else
    echo -e "${RED}Error: scanengine directory not found${NC}"
    exit 1
fi

# Copy rules
echo -e "${YELLOW}Installing security rules...${NC}"
if [ -d "$SCRIPT_DIR/rules" ]; then
    cp -r "$SCRIPT_DIR/rules" "$INSTALL_DIR/"
    echo -e "${GREEN}✓ Rules installed ($(find "$INSTALL_DIR/rules" -name "*.yaml" | wc -l) rule files)${NC}"
fi

# Create CLI wrapper
echo -e "${YELLOW}Creating CLI wrapper...${NC}"
cat > "$BIN_DIR/sentinelscan" << 'WRAPPER'
#!/bin/bash
# SentinelScan CLI Wrapper

INSTALL_DIR="${HOME}/.sentinelscan"
source "$INSTALL_DIR/venv/bin/activate"

# Default rules directory
export SECURITY_RULES_DIR="${SECURITY_RULES_DIR:-$INSTALL_DIR/rules}"

python -m scanengine.cli "$@"
WRAPPER
chmod +x "$BIN_DIR/sentinelscan"
echo -e "${GREEN}✓ CLI wrapper created${NC}"

# Create hooks installer wrapper
cat > "$BIN_DIR/sentinelscan-hooks" << 'WRAPPER'
#!/bin/bash
# SentinelScan Hooks Installer

INSTALL_DIR="${HOME}/.sentinelscan"
source "$INSTALL_DIR/venv/bin/activate"

python -m scanengine.hooks.installer "$@"
WRAPPER
chmod +x "$BIN_DIR/sentinelscan-hooks"

# Check if bin directory is in PATH
if [[ ":$PATH:" != *":$BIN_DIR:"* ]]; then
    echo -e "${YELLOW}Adding $BIN_DIR to PATH...${NC}"

    # Detect shell
    SHELL_RC=""
    if [ -n "$ZSH_VERSION" ] || [ -f "$HOME/.zshrc" ]; then
        SHELL_RC="$HOME/.zshrc"
    elif [ -f "$HOME/.bashrc" ]; then
        SHELL_RC="$HOME/.bashrc"
    fi

    if [ -n "$SHELL_RC" ]; then
        echo "" >> "$SHELL_RC"
        echo "# SentinelScan" >> "$SHELL_RC"
        echo "export PATH=\"\$PATH:$BIN_DIR\"" >> "$SHELL_RC"
        echo -e "${GREEN}✓ Added to $SHELL_RC${NC}"
        echo -e "${YELLOW}  Note: Run 'source $SHELL_RC' or restart your terminal${NC}"
    fi
fi

# Installation summary
echo ""
echo -e "${BLUE}╔══════════════════════════════════════════════════════════════╗"
echo -e "║                   Installation Complete!                       ║"
echo -e "╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${GREEN}Installation directory:${NC} $INSTALL_DIR"
echo -e "${GREEN}CLI command:${NC} sentinelscan"
echo ""
echo -e "${YELLOW}Quick Start:${NC}"
echo "  # Scan a directory"
echo "  sentinelscan /path/to/code"
echo ""
echo "  # Scan with specific severity threshold"
echo "  sentinelscan . -s high"
echo ""
echo "  # Generate SARIF report"
echo "  sentinelscan . -f sarif -o report.sarif"
echo ""
echo "  # Install git hooks"
echo "  sentinelscan-hooks install"
echo ""

# Offer to install git hooks
if [ -d ".git" ]; then
    echo -e "${YELLOW}Git repository detected. Would you like to install security hooks?${NC}"
    read -p "Install git hooks? [y/N] " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        "$BIN_DIR/sentinelscan-hooks" install
    fi
fi

echo -e "${GREEN}Done! Happy scanning!${NC}"
