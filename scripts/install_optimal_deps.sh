#!/bin/bash
# SecureWipe India - Optimal Erase Dependencies Installation
# File: scripts/install_optimal_deps.sh

set -e

echo "🚀 SecureWipe India - Installing Optimal Erase Dependencies"
echo "=========================================================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Detect OS
typename="$(uname -s)"
if [[ "$typename" == "Linux" ]]; then
    OS="linux"
elif [[ "$typename" == "Darwin" ]]; then
    OS="macos"
elif [[ "$typename" =~ ^CYGWIN|MINGW|MSYS ]]; then
    OS="windows"
else
    OS="unknown"
fi

echo -e "${BLUE}Detected OS: $OS${NC}"

# Check privileges (Linux)
if [[ "$OS" == "linux" ]]; then
    if [[ $EUID -eq 0 ]]; then
        echo -e "${YELLOW}Running as root - system-wide installation${NC}"
        INSTALL_MODE="system"
    else
        echo -e "${BLUE}Running as user - some tools require sudo${NC}"
        INSTALL_MODE="user"
    fi
fi

install_linux_deps() {
    echo -e "${BLUE}Updating package lists...${NC}"
    sudo apt-get update

    echo -e "${BLUE}Installing required packages...${NC}"
    sudo apt-get install -y \
        hdparm \
        smartmontools \
        nvme-cli \
        sg3-utils \
        cryptsetup-bin \
        util-linux \
        secure-delete \
        wipefs

    echo -e "${GREEN}✅ Linux dependencies installed successfully${NC}"
}

install_macos_deps() {
    echo -e "${BLUE}Installing macOS dependencies...${NC}"
    if command -v brew &> /dev/null; then
        brew update
        brew install smartmontools nvme-cli
        echo -e "${GREEN}✅ macOS dependencies installed via Homebrew${NC}"
        echo -e "${YELLOW}⚠️  Note: Some hardware tools may have limited functionality on macOS${NC}"
    else
        echo -e "${YELLOW}Homebrew not found. Please install Homebrew first:${NC}"
        echo "  /bin/bash -c \"\$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)\""
        echo "  brew install smartmontools nvme-cli"
    fi
}

install_windows_deps() {
    echo -e "${BLUE}Windows detected. Ensure these built-in tools are available:${NC}"
    echo "  - diskpart.exe"
    echo "  - manage-bde.exe (BitLocker)"
    echo "  - cipher.exe"
    echo ""
    echo "Optional vendor utilities:"
    echo "  - Samsung Magician, Intel SSD Toolbox, Crucial Storage Executive, SanDisk Dashboard"
    echo "Third-party tool:"
    echo "  - SysInternals SDelete (https://docs.microsoft.com/sysinternals/downloads/sdelete)"
    echo -e "${GREEN}✅ Windows prerequisites listed${NC}"
}

verify_installation() {
    echo -e "${BLUE}Verifying tool availability...${NC}"
    if [[ "$OS" == "linux" ]]; then
        tools=(hdparm smartctl nvme sg_sanitize blkdiscard cryptsetup wipefs)
    elif [[ "$OS" == "macos" ]]; then
        tools=(smartctl nvme)
    elif [[ "$OS" == "windows" ]]; then
        tools=(diskpart manage-bde cipher)
    fi

    for tool in "${tools[@]}"; do
        if command -v "$tool" &> /dev/null; then
            echo -e "   ✅ $tool available"
        else
            echo -e "   ❌ $tool missing"
        fi
    done

    if [[ "$OS" == "linux" ]]; then
        echo -e "\n${BLUE}Checking device access permissions...${NC}"
        if [[ -r /dev/sda ]] 2>/dev/null || [[ $EUID -eq 0 ]]; then
            echo -e "   ✅ Device access: OK"
        else
            echo -e "   ⚠️  Device access: Limited"
            echo -e "   💡 Add user to disk group: sudo usermod -a -G disk \$USER"
            echo -e "   💡 Then log out and back in"
        fi
    fi
}

print_usage_examples() {
    echo -e "\n${BLUE}Optimal Erase Usage Examples:${NC}"
    echo "CLI:"
    echo "  securewipe optimal-methods"
    echo "  securewipe optimal-wipe --device /dev/sdb"
    echo "  securewipe optimal-wipe --device /dev/sdb --force"
    echo ""
    echo "GUI:"
    echo "  securewipe-gui  # Then click '🚀 Optimal Fast Wipe'"
    echo ""
    echo "⚠️ NEVER run optimal erase on system drives!"
    echo "   ALWAYS test in VMs first!"
    echo "   BACKUP important data before wiping!"
}

# Main installation
main() {
    echo -e "${BLUE}Starting optimal erase dependencies installation...${NC}\n"
    case $OS in
        linux)   install_linux_deps ;;
        macos)   install_macos_deps ;;
        windows) install_windows_deps ;;
        *)       echo -e "${RED}Unsupported OS: $OS${NC}"; exit 1 ;;
    esac

    echo ""
    verify_installation
    print_usage_examples

    echo -e "\n${GREEN}🎉 Installation complete!${NC}"
    echo -e "${GREEN}Next Steps: copy optimal_erase.py to src/core/, update main_gui.py and cli.py, test in VM${NC}"
}

main "$@"
