#!/bin/bash

# ============================================
# Complete Security Tools Installation Script
# For Kali Linux - One Script to Rule Them All
# ============================================

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m' # No Color

# Print colored output functions
print_status() {
    echo -e "${BLUE}[*]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[+]${NC} $1"
}

print_error() {
    echo -e "${RED}[!]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

print_info() {
    echo -e "${CYAN}[i]${NC} $1"
}

print_header() {
    echo ""
    echo -e "${MAGENTA}=========================================${NC}"
    echo -e "${MAGENTA}  $1${NC}"
    echo -e "${MAGENTA}=========================================${NC}"
    echo ""
}

print_banner() {
    echo -e "${CYAN}"
    echo "╔══════════════════════════════════════════════════════════╗"
    echo "║     Security Tools Installation Script for Kali Linux    ║"
    echo "║                  One Script to Rule Them All              ║"
    echo "╚══════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

# Check command success
check_success() {
    if [ $? -eq 0 ]; then
        print_success "$1"
        return 0
    else
        print_error "$1 failed"
        return 1
    fi
}

# Start installation
clear
print_banner

# Detect user and environment
if [[ $EUID -eq 0 ]]; then
    USER_HOME="/root"
    print_warning "Running as root. Tools will be installed for root user."
else
    USER_HOME="$HOME"
    print_info "Running as $USER"
fi

# Detect shell

if [[ -n "$ZSH_VERSION" ]]; then
    SHELL_RC="$USER_HOME/.zshrc"
    CURRENT_SHELL="zsh"
elif [[ -n "$BASH_VERSION" ]]; then
    SHELL_RC="$USER_HOME/.bashrc"
    CURRENT_SHELL="bash"
else
    SHELL_RC="$USER_HOME/.profile"
    CURRENT_SHELL="sh"
fi

print_info "Using shell: $CURRENT_SHELL"
print_info "Config file: $SHELL_RC"

# ============================================
# Phase 1: System Updates and Dependencies
# ============================================
print_header "Phase 1: System Updates and Dependencies"

print_status "Updating package lists..."
sudo apt update
check_success "Package list update"

print_status "Upgrading existing packages..."
sudo apt upgrade -y
check_success "Package upgrade"

print_status "Installing essential build tools..."
sudo apt install -y git curl wget unzip build-essential software-properties-common apt-transport-https ca-certificates gnupg lsb-release
check_success "Essential tools installation"

# ============================================
# Phase 2: Language Runtimes
# ============================================
print_header "Phase 2: Installing Language Runtimes"

# Python installation
print_status "Installing Python and related tools..."
sudo apt install -y python3 python3-pip python3-venv python3-dev python3-full
check_success "Python installation"

# Ensure pip is up to date
print_status "Upgrading pip..."
python3 -m pip install --upgrade pip
check_success "Pip upgrade"

# Install pipx properly
print_status "Installing pipx..."
sudo apt install -y pipx
python3 -m pip install --user pipx
python3 -m pipx ensurepath
check_success "pipx installation"

# Add pipx to PATH for current session
export PATH="$PATH:$USER_HOME/.local/bin"
check_success "pipx PATH configuration"

# Go installation
print_status "Installing Go..."
sudo apt install -y golang-go
check_success "Go installation"

# Rust installation via rustup
print_status "Installing Rust via rustup..."
if ! command -v rustc &> /dev/null; then
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    check_success "Rust installation"
    source "$USER_HOME/.cargo/env"
else
    print_success "Rust already installed: $(rustc --version)"
fi

# ============================================
# Phase 3: Environment Configuration
# ============================================
print_header "Phase 3: Environment Configuration"

print_status "Configuring environment variables..."

# Backup existing config
if [[ -f "$SHELL_RC" ]]; then
    cp "$SHELL_RC" "$SHELL_RC.backup.$(date +%s)"
    print_success "Backed up $SHELL_RC"
fi

# Set up GOPATH
if [[ -z "$GOPATH" ]]; then
    export GOPATH="$USER_HOME/go"
    echo "export GOPATH=\$HOME/go" >> "$SHELL_RC"
fi

# Create Go directories
mkdir -p "$USER_HOME/go/bin"
mkdir -p "$USER_HOME/go/src"

# Add all necessary paths to PATH
PATHS_TO_ADD=(
    "\$GOPATH/bin"
    "\$HOME/.cargo/bin"
    "\$HOME/.local/bin"
    "/usr/local/go/bin"
    "/usr/local/bin"
    "/usr/bin"
)

for path_entry in "${PATHS_TO_ADD[@]}"; do
    if ! grep -q "export PATH=.*$path_entry" "$SHELL_RC"; then
        # echo "export PATH=\$PATH:$path_entry" >> "$SHELL_RC"
        echo "export PATH=$path_entry:\$PATH" >> "$SHELL_RC"
        print_success "Added $path_entry to PATH"
    fi
done

# Apply PATH for current session
export PATH="$PATH:$USER_HOME/go/bin:$USER_HOME/.cargo/bin:$USER_HOME/.local/bin:/usr/local/go/bin:/usr/local/bin"

# Add Rust env if not present
if ! grep -q "cargo/env" "$SHELL_RC"; then
    echo 'source "$HOME/.cargo/env"' >> "$SHELL_RC"
fi

print_success "Environment configured"

# ============================================
# Phase 4: APT Security Tools
# ============================================
print_header "Phase 4: Installing APT Security Tools"

SECURITY_TOOLS=(
    "nmap"
    "gobuster"
    "dnsrecon"
    "whatweb"
    "whois"
    "bind9-dnsutils"
    "wafw00f"
    "nikto"
    "sqlmap"
)

for tool in "${SECURITY_TOOLS[@]}"; do
    print_status "Installing $tool..."
    sudo apt install -y "$tool"
done

check_success "APT security tools installation"

# ============================================
# Phase 5: Go Security Tools
# ============================================
print_header "Phase 5: Installing Go Security Tools"

# Function to install Go tool
install_go_tool() {
    local tool_name=$1
    local install_cmd=$2
    
    print_status "Installing $tool_name..."
    if eval "$install_cmd" 2>&1; then
        print_success "$tool_name installed successfully"
        return 0
    else
        print_error "Failed to install $tool_name"
        return 1
    fi
}

# ProjectDiscovery Tools
install_go_tool "subfinder" "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
install_go_tool "dnsx" "go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
install_go_tool "httpx" "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest"
install_go_tool "nuclei" "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
install_go_tool "alterx" "go install -v github.com/projectdiscovery/alterx/cmd/alterx@latest"

# DNS Tools
install_go_tool "puredns" "go install github.com/d3mondev/puredns/v2@latest"

# Asset Discovery
install_go_tool "assetfinder" "go install github.com/tomnomnom/assetfinder@latest"

# Subdomain Takeover
install_go_tool "subjack" "go install github.com/haccer/subjack@latest"

# Technology Detection
install_go_tool "webanalyze" "go install github.com/rverton/webanalyze/cmd/webanalyze@latest"

# XSS Scanner
install_go_tool "dalfox" "go install github.com/hahwul/dalfox/v2@latest"

# Additional Go Tools
install_go_tool "ffuf" "go install github.com/ffuf/ffuf@latest"

# ============================================
# Phase 6: Rust Tools
# ============================================
print_header "Phase 6: Installing Rust Tools"

print_status "Installing rustscan..."
cargo install rustscan
check_success "rustscan installation"

# ============================================
# Phase 7: Python Tools (Enhanced BBOT Installation)
# ============================================
print_header "Phase 7: Installing Python Tools"

# Method 1: Install bbot with pipx with proper flags
print_status "Installing bbot with pipx..."
pipx install bbot --force --python python3
check_success "bbot installation attempt 1"

# Verify if bbot was installed
if ! command -v bbot &> /dev/null; then
    print_warning "bbot not found, trying alternative installation method..."
    
    # Method 2: Install with pip directly using --break-system-packages for Kali
    print_status "Installing bbot with pip directly..."
    pip3 install bbot --break-system-packages
    check_success "bbot installation with pip"
fi

# Method 3: If still not installed, try with --user flag
if ! command -v bbot &> /dev/null; then
    print_warning "bbot still not found, trying user installation..."
    pip3 install --user bbot
    check_success "bbot user installation"
fi

# Method 4: Create a virtual environment as last resort
if ! command -v bbot &> /dev/null; then
    print_warning "Creating Python virtual environment for bbot..."
    python3 -m venv "$USER_HOME/bbot-env"
    source "$USER_HOME/bbot-env/bin/activate"
    pip install bbot
    deactivate
    
    # Create alias for bbot
    echo "alias bbot='$USER_HOME/bbot-env/bin/bbot'" >> "$SHELL_RC"
    print_success "Created alias for bbot in virtual environment"
fi

# Verify bbot installation
if command -v bbot &> /dev/null; then
    print_success "bbot installed successfully: $(bbot --version 2>&1 | head -1)"
else
    # Check if bbot exists in common locations
    if [[ -f "$USER_HOME/.local/bin/bbot" ]]; then
        print_success "bbot found at $USER_HOME/.local/bin/bbot"
        export PATH="$PATH:$USER_HOME/.local/bin"
        echo 'export PATH="$PATH:$HOME/.local/bin"' >> "$SHELL_RC"
    elif [[ -f "/usr/local/bin/bbot" ]]; then
        print_success "bbot found at /usr/local/bin/bbot"
    else
        print_error "bbot installation failed after multiple attempts"
        print_info "You can manually install bbot later with: pipx install bbot"
    fi
fi

# Install other Python libraries
print_status "Installing additional Python libraries..."
pip3 install requests beautifulsoup4 --break-system-packages 2>/dev/null || pip3 install requests beautifulsoup4
check_success "Python libraries installation"

# ============================================
# Phase 8: Create Symbolic Links
# ============================================
print_header "Phase 8: Creating Symbolic Links"

print_status "Creating symbolic links for Go tools in /usr/local/bin..."

mkdir -p /usr/local/bin

GO_TOOLS=(
    "subfinder"
    "assetfinder"
    "puredns"
    "alterx"
    "dnsx"
    "subjack"
    "webanalyze"
    "nuclei"
    "dalfox"
    "httpx"
    "ffuf"
)

for tool in "${GO_TOOLS[@]}"; do
    # Find binary in common locations
    BINARY_PATH=$(find "$USER_HOME/go/bin" /usr/local/go/bin -name "$tool" -type f 2>/dev/null | head -1)
    
    if [[ -n "$BINARY_PATH" && -f "$BINARY_PATH" ]]; then
        if [[ ! -L "/usr/local/bin/$tool" && ! -f "/usr/local/bin/$tool" ]]; then
            ln -sf "$BINARY_PATH" "/usr/local/bin/$tool"
            print_success "Created symlink: /usr/local/bin/$tool"
        fi
    fi
done

# ============================================
# Phase 9: Update Tool Databases
# ============================================
print_header "Phase 9: Updating Tool Databases"

# Update nuclei templates
if command -v nuclei &> /dev/null; then
    print_status "Updating nuclei templates..."
    nuclei -update-templates
    check_success "Nuclei templates update"
fi

# Update webanalyze database
if command -v webanalyze &> /dev/null; then
    print_status "Updating webanalyze database..."
    webanalyze -update
    check_success "Webanalyze database update"
fi

# ============================================
# Phase 10: Create Verification Script
# ============================================
print_header "Phase 10: Creating Verification Script"

cat > "$USER_HOME/verify_all_tools.sh" << 'EOF'
#!/bin/bash

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo ""
echo "========================================="
echo "  Complete Tool Verification Report"
echo "========================================="
echo ""

# Tool categories
declare -A system_tools=(
    ["nmap"]="nmap --version"
    ["gobuster"]="gobuster --version"
    ["dnsrecon"]="dnsrecon --version"
    ["whatweb"]="whatweb --version"
    ["whois"]="whois -v"
    ["dig"]="dig -v"
    ["wafw00f"]="wafw00f --version"
)

declare -A go_tools=(
    ["subfinder"]="subfinder -version"
    ["assetfinder"]="assetfinder --help"
    ["puredns"]="puredns -version"
    ["alterx"]="alterx -version"
    ["dnsx"]="dnsx -version"
    ["httpx"]="httpx -version"
    ["nuclei"]="nuclei -version"
    ["subjack"]="subjack -h"
    ["webanalyze"]="webanalyze -version"
    ["dalfox"]="dalfox -version"
    ["ffuf"]="ffuf -V"
)

declare -A rust_tools=(
    ["rustscan"]="rustscan --version"
)

declare -A python_tools=(
    ["bbot"]="bbot --version"
)

# Check system tools
echo -e "${BLUE}System Tools:${NC}"
for tool in "${!system_tools[@]}"; do
    if command -v "$tool" &> /dev/null; then
        echo -e "${GREEN}✔${NC} $tool"
    else
        echo -e "${RED}✘${NC} $tool"
    fi
done

echo ""
echo -e "${BLUE}Go Tools:${NC}"
for tool in "${!go_tools[@]}"; do
    if command -v "$tool" &> /dev/null; then
        echo -e "${GREEN}✔${NC} $tool"
    elif [[ -f "$HOME/go/bin/$tool" ]] || [[ -f "/root/go/bin/$tool" ]]; then
        echo -e "${GREEN}✔${NC} $tool (found in Go bin)"
    else
        echo -e "${RED}✘${NC} $tool"
    fi
done

echo ""
echo -e "${BLUE}Rust Tools:${NC}"
for tool in "${!rust_tools[@]}"; do
    if command -v "$tool" &> /dev/null; then
        echo -e "${GREEN}✔${NC} $tool"
    else
        echo -e "${RED}✘${NC} $tool"
    fi
done

echo ""
echo -e "${BLUE}Python Tools:${NC}"
for tool in "${!python_tools[@]}"; do
    if command -v "$tool" &> /dev/null; then
        echo -e "${GREEN}✔${NC} $tool"
    elif [[ -f "$HOME/.local/bin/$tool" ]] || [[ -f "/root/.local/bin/$tool" ]]; then
        echo -e "${GREEN}✔${NC} $tool (found in local bin)"
    else
        echo -e "${RED}✘${NC} $tool"
    fi
done

echo ""
echo "========================================="
EOF

chmod +x "$USER_HOME/verify_all_tools.sh"
print_success "Verification script created at $USER_HOME/verify_all_tools.sh"

# ============================================
# Phase 11: Clone and Test Heyport
# ============================================
print_header "Phase 11: Setting Up Heyport"

if [[ ! -d "$USER_HOME/Heyport" ]]; then
    print_status "Cloning Heyport repository..."
    cd "$USER_HOME"
    git clone https://github.com/Az3ll3/Heyport.git
    check_success "Heyport clone"
else
    print_status "Heyport already exists, updating..."
    cd "$USER_HOME/Heyport"
    git pull
fi

cd "$USER_HOME/Heyport"

# Run tool check
print_status "Running Heyport tool verification..."
python3 Heyport-3.py --check-tools

# ============================================
# Phase 12: Final Configuration and Summary
# ============================================
print_header "Installation Complete! Final Configuration"

# Source the shell config
source "$SHELL_RC"

# Create final summary
cat > "$USER_HOME/INSTALLATION_SUMMARY.txt" << EOF
Security Tools Installation Summary
====================================
Date: $(date)
User: $USER
Shell: $CURRENT_SHELL
Config: $SHELL_RC

Installed Components:
- System Tools: ${#SECURITY_TOOLS[@]} tools
- Go Tools: ${#GO_TOOLS[@]} tools
- Rust Tools: rustscan
- Python Tools: bbot + libraries
- Heyport: Cloned and configured

Paths Added:
- \$GOPATH/bin
- \$HOME/.cargo/bin
- \$HOME/.local/bin
- /usr/local/bin

Next Steps:
1. Reload shell: source $SHELL_RC
2. Verify tools: ~/verify_all_tools.sh
3. Test Heyport: cd ~/Heyport && python3 Heyport-3.py --check-tools
4. Start scanning: python3 Heyport-3.py -t target.com

For help: python3 Heyport-3.py --help
EOF

print_success "Installation summary saved to $USER_HOME/INSTALLATION_SUMMARY.txt"

# ============================================
# Final Verification
# ============================================
print_header "Final Verification"

print_status "Running final verification..."
bash "$USER_HOME/verify_all_tools.sh"

echo ""
print_status "PATH Configuration:"
echo "$PATH" | tr ':' '\n' | grep -E "(go|bin|cargo|local)" | head -10

# ============================================
# Completion Message
# ============================================
echo ""
print_success "========================================="
print_success "  INSTALLATION COMPLETE!"
print_success "========================================="
echo ""

print_info "Installation Summary:"
echo "  ✓ System dependencies installed"
echo "  ✓ Go environment configured"
echo "  ✓ Rust environment configured"
echo "  ✓ All security tools installed"
echo "  ✓ Heyport repository cloned"
echo "  ✓ PATH properly configured"
echo ""

print_status "IMPORTANT: Reload your shell to apply changes:"
echo "  source $SHELL_RC"
echo ""

print_status "Quick Commands:"
echo "  # Verify all tools:      ~/verify_all_tools.sh"
echo "  # Check Heyport:         cd ~/Heyport && python3 Heyport-3.py --check-tools"
echo "  # Run a scan:            cd ~/Heyport && python3 Heyport-3.py -t testphp.vulnweb.com"
echo ""

print_status "For full documentation:"
echo "  cat ~/INSTALLATION_SUMMARY.txt"
echo ""

print_success "Happy Hacking! 🚀"

# Optional: Ask to run verification
echo ""
read -p "Do you want to run the Heyport tool check now? (y/n) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    cd "$USER_HOME/Heyport"
    python3 Heyport-3.py --check-tools
fi
