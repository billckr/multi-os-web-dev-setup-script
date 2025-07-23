#!/bin/bash

# Multi-OS Web Stack Builder
# Version: 1.0
# Description: Bulletproof installation script for web development stack
# Supports: RHEL-based, Debian-based, SUSE-based, and Arch-based distributions

set -euo pipefail

# Capture SSH environment variables early (before sudo context changes)
if [[ -z "${ORIGINAL_SSH_CLIENT:-}" && -n "${SSH_CLIENT:-}" ]]; then
    export ORIGINAL_SSH_CLIENT="$SSH_CLIENT"
fi
if [[ -z "${ORIGINAL_SSH_CONNECTION:-}" && -n "${SSH_CONNECTION:-}" ]]; then
    export ORIGINAL_SSH_CONNECTION="$SSH_CONNECTION"
fi

# Global variables
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_FILE=""
INSTALLED_PACKAGES=()
INSTALLED_SERVICES=()
USER_IP=""
DOMAIN_NAME=""
SELECTED_WEBSERVER=""
SELECTED_DATABASES=()
INSTALLED_DATABASES=()  # Track which databases were actually installed
SELECTED_PHP_VERSIONS=()
CREATE_USER=false
USERNAME=""
VERBOSE_LOGGING=false
AUTO_PRESET=false
PRESET_MODE=false
SKIP_CONFIRMATION=false
NON_INTERACTIVE=false
DEFAULT_PHP_VERSION=""
DETECTED_SSH_CLIENT_IP=""

# Colors for output
RED='\033[1;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[1;34m'
ORANGE='\033[0;33m'
WHITE='\033[1;37m'
LIGHT_GREY='\033[0;37m'
PURPLE='\033[1;35m'
NC='\033[0m' # No Color

# Logging function
log() {
    local level="$1"
    shift
    local message="$*"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    # Always log to file for debugging purposes
    if [[ -n "$LOG_FILE" ]]; then
        echo "[$timestamp] [$level] $message" >> "$LOG_FILE"
    fi
    
    # Only show certain levels in console based on verbosity
    case "$level" in
        "ERROR"|"WARNING")
            # Always show errors and warnings
            ;;
        "SUCCESS"|"COMPLETION")
            # Always show success and completion messages
            ;;
        "INFO"|"DEBUG")
            # Only show info/debug if verbose logging is enabled
            ;;
    esac
}

# Print functions
print_info() {
    echo -e "${LIGHT_GREY}[INFO]${NC} $1"
    if [[ "$VERBOSE_LOGGING" == true ]]; then
        log "INFO" "$1"
    fi
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
    log "SUCCESS" "$1"
}

print_warning() {
    echo -e "   ${YELLOW}[WARNING]${NC} $1"
    log "WARNING" "$1"
}

print_tip() {
    echo -e "   ${PURPLE}[TIP]${NC} $1"
    if [[ "$VERBOSE_LOGGING" == true ]]; then
        log "INFO" "TIP: $1"
    fi
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
    log "ERROR" "$1"
}

# Error handler
error_exit() {
    local line_number="$1"
    local error_message="$2"
    print_error "Error on line $line_number: $error_message"
    print_error "Installation failed. Check $LOG_FILE for details."
    exit 1
}

# Cleanup function for Ctrl+C
cleanup_on_interrupt() {
    # Clean up install log file silently when user presses Ctrl+C
    if [[ -n "$LOG_FILE" && -f "$LOG_FILE" ]]; then
        rm -f "$LOG_FILE" 2>/dev/null || true
    fi
    exit 0
}

# Set up error trap and interrupt handler
trap 'error_exit ${LINENO} "$BASH_COMMAND"' ERR
trap 'cleanup_on_interrupt' INT

# Security validation functions
validate_domain_name() {
    local domain="$1"
    # RFC 1035 compliant domain validation
    if [[ "$domain" =~ ^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$ ]] && [[ ${#domain} -le 253 ]]; then
        return 0
    else
        return 1
    fi
}

validate_username() {
    local username="$1"
    # Strict username validation: lowercase letters, numbers, underscore, dash
    # Must start with letter or underscore, 3-32 characters
    if [[ "$username" =~ ^[a-z_]([a-z0-9_-]{1,30})$ ]]; then
        # Check if user already exists (any user, system or regular)
        if id "$username" >/dev/null 2>&1; then
            return 1  # User already exists, reject to avoid conflicts
        fi
        return 0
    else
        return 1
    fi
}

validate_ip_address() {
    local ip="$1"
    # IPv4 validation
    if [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
        local IFS='.'
        local -a octets=($ip)
        for octet in "${octets[@]}"; do
            if [[ $octet -gt 255 ]]; then
                return 1
            fi
        done
        return 0
    fi
    # IPv6 basic validation (simplified)
    if [[ "$ip" =~ ^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$ ]]; then
        return 0
    fi
    return 1
}

sanitize_input() {
    local input="$1"
    # Remove dangerous characters and shell metacharacters
    input=$(printf '%s' "$input" | tr -d '`$(){}[]|&;<>*?~')
    printf '%s' "$input"
}

secure_random_password() {
    # Generate cryptographically secure random password
    openssl rand -base64 32 | tr -d "=+/" | cut -c1-25
}

create_secure_file() {
    local filepath="$1"
    local content="$2"
    local permissions="${3:-600}"
    
    # Create file with secure permissions from the start
    (
        umask 077
        printf '%s' "$content" > "$filepath"
    )
    chmod "$permissions" "$filepath"
}

validate_file_path() {
    local filepath="$1"
    # Prevent path traversal attacks
    if [[ "$filepath" =~ \.\./|^/\.\./ ]]; then
        return 1
    fi
    # Ensure path is absolute for security
    if [[ ! "$filepath" =~ ^/ ]]; then
        return 1
    fi
    return 0
}

# Spinner functions for long-running operations
show_spinner() {
    local pid=$1
    local message="${2:-Processing}"
    local spinstr='|/-\'
    local temp
    
    # Hide cursor
    tput civis
    
    while kill -0 "$pid" 2>/dev/null; do
        temp=${spinstr#?}
        printf "\r${BLUE}[%c]${NC} %s..." "$spinstr" "$message"
        spinstr=$temp${spinstr%"$temp"}
        sleep 0.1
    done
    
    # Show cursor and clear spinner line
    tput cnorm
    printf "\r"
}

run_with_spinner() {
    local message="$1"
    shift
    local command=("$@")
    
    # Run command in background
    "${command[@]}" &
    local pid=$!
    
    # Show spinner while command runs
    show_spinner "$pid" "$message"
    
    # Wait for command to complete and get exit code
    wait "$pid"
    local exit_code=$?
    
    # Clear the spinner line completely
    printf "\r\033[K"
    
    return $exit_code
}

# Welcome and description
welcome_user() {
    clear
    echo -e "${BLUE}===========================================================================${NC}"
    echo -e "${WHITE}                        Multi-OS Web Stack Builder${NC}"
    echo -e "${BLUE}===========================================================================${NC}"
    echo ""
    echo "   This script will install and configure a complete web development stack"
    echo "   including web server, PHP, database, and security tools."
    echo ""
    echo -e "   ${BLUE}Supported Components:${NC}"
    echo "     • Web Servers: Apache or Nginx"
    echo "     • PHP: Versions 8.2, 8.3, 8.4 (one or more)"
    echo "     • Databases: MySQL, MariaDB, PostgreSQL, SQLite3, MongoDB, Redis"
    echo "     • Security: Fail2ban with automatic IP whitelisting"
    echo ""
    echo -e "   ${BLUE}Features:${NC}"
    echo "     • Multi-OS support (RHEL, Debian, SUSE, Arch families)"
    echo "     • Automatic OS detection and package manager selection"
    echo "     • Concise logging (errors/warnings only by default)"
    echo ""
    echo -e "   ${BLUE}Automatically installed tools:${NC}"
    echo "     • curl - Data transfer with URLs"
    echo "     • wget - File downloading from web servers"
    echo "     • net-tools - (netstat, ifconfig, etc.)"
    echo "     • netcat - Network connection utility"
    echo "     • atop - Advanced system and process monitor"
    echo ""
    echo -e "   ${BLUE}Usage:${NC}"
    echo "     sudo $0              # Normal installation"
    echo "     sudo $0 --verbose    # Verbose logging"
    echo "     sudo $0 --remove     # Remove installation"
    echo ""
    
    log "COMPLETION" "Installation script started"
    log "INFO" "Script version: 1.0"
    log "INFO" "Log file: $LOG_FILE"
    if [[ "$VERBOSE_LOGGING" == true ]]; then
        print_info "Verbose logging enabled"
    else
        echo -e "   ${BLUE}System Settings:${NC}"
        echo -e "     Install log: ${BLUE}$LOG_FILE${NC}"
    fi
}

# Check if running as root
check_root() {
    if [[ $EUID -eq 0 ]]; then
        echo -e "     Running as ${BLUE}root${NC}"
        log "INFO" "Script running as root user"
    else
        # Script not running as root - check if we can auto-detect SSH IP and re-exec with sudo
        local ssh_client_ip=""
        
        # Try to detect SSH client IP before losing environment
        if [[ -n "${SSH_CLIENT:-}" ]]; then
            ssh_client_ip=$(echo "$SSH_CLIENT" | awk '{print $1}')
        elif [[ -n "${SSH_CONNECTION:-}" ]]; then
            ssh_client_ip=$(echo "$SSH_CONNECTION" | awk '{print $1}')
        fi
        
        # Re-execute with sudo, preserving the SSH client IP
        if [[ -n "$ssh_client_ip" ]]; then
            print_info "Auto-executing with sudo and preserving SSH client IP: $ssh_client_ip"
            exec sudo "$0" "$@" --ssh-client-ip="$ssh_client_ip"
        else
            print_error "This script must be run as root or with sudo"
            print_error "Usage: sudo $0"
            exit 1
        fi
    fi
}

# Detect operating system for preset mode (no confirmation prompts)
detect_os_preset() {
    local os_name=""
    local os_version=""
    local package_manager=""
    
    if [[ -f /etc/os-release ]]; then
        source /etc/os-release
        os_name="$NAME"
        os_version="$VERSION_ID"
    else
        print_error "Cannot detect operating system"
        exit 1
    fi
    
    # Determine package manager
    if command -v dnf >/dev/null 2>&1; then
        package_manager="dnf"
    elif command -v yum >/dev/null 2>&1; then
        package_manager="yum"
    elif command -v apt >/dev/null 2>&1; then
        package_manager="apt"
    elif command -v zypper >/dev/null 2>&1; then
        package_manager="zypper"
    elif command -v pacman >/dev/null 2>&1; then
        package_manager="pacman"
    else
        print_error "Unsupported package manager"
        exit 1
    fi
    
    log "INFO" "Detected OS: $os_name $os_version"
    log "INFO" "Package manager: $package_manager"
    
    # Store in global variables for later use
    export OS_NAME="$os_name"
    export OS_VERSION="$os_version"
    export PACKAGE_MANAGER="$package_manager"
    
    # No confirmation prompt in preset mode
}

# Get user IP for preset mode (simplified, no prompts)
get_user_ip_preset() {
    # Robust IP detection that works with or without sudo
    local detected_ip=""
    
    # Priority 1: SSH client IP passed as parameter (from non-sudo re-execution)
    if [[ -n "${DETECTED_SSH_CLIENT_IP:-}" ]]; then
        detected_ip="$DETECTED_SSH_CLIENT_IP"
        log "INFO" "IP detected from command parameter: '$detected_ip'"
        
    # Priority 2: Try SSH environment variables (work in fresh sudo sessions)
    elif [[ -n "${SSH_CLIENT:-}" ]]; then
        detected_ip=$(echo "$SSH_CLIENT" | awk '{print $1}')
        log "INFO" "IP detected from SSH_CLIENT: '$SSH_CLIENT' -> '$detected_ip'"
    elif [[ -n "${SSH_CONNECTION:-}" ]]; then
        detected_ip=$(echo "$SSH_CONNECTION" | awk '{print $1}')
        log "INFO" "IP detected from SSH_CONNECTION: '$SSH_CONNECTION' -> '$detected_ip'"
        
    # Priority 3: Parse active SSH connections (fresh server assumption)
    elif command -v netstat >/dev/null 2>&1; then
        # Get SSH connections to port 22, exclude local connections
        local ssh_connections=$(netstat -tn 2>/dev/null | awk '/ESTABLISHED/ && /:22 / {print $5}' | cut -d: -f1 | grep -v '^127\.' | grep -v '^::1' | head -1)
        if [[ -n "$ssh_connections" && "$ssh_connections" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
            detected_ip="$ssh_connections"
            log "INFO" "IP detected from netstat SSH connections: '$detected_ip'"
        fi
        
    # Priority 4: Try 'ss' command as fallback
    elif command -v ss >/dev/null 2>&1; then
        local ssh_connections=$(ss -tn 2>/dev/null | awk '/ESTAB/ && /:22/ {print $4}' | cut -d: -f1 | grep -v '^127\.' | grep -v '^::1' | head -1)
        if [[ -n "$ssh_connections" && "$ssh_connections" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
            detected_ip="$ssh_connections"
            log "INFO" "IP detected from ss SSH connections: '$detected_ip'"
        fi
    fi
    
    # Log final detection result
    if [[ -z "$detected_ip" ]]; then
        log "WARNING" "All IP detection methods failed - fresh server SSH detection unsuccessful"
    fi
    
    # Validate IPv4 format and set USER_IP
    if [[ -n "$detected_ip" ]] && [[ "$detected_ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
        # Validate octet ranges (0-255)
        local IFS='.'
        local -a octets=($detected_ip)
        local valid_ipv4=true
        for octet in "${octets[@]}"; do
            if [[ $octet -gt 255 ]]; then
                valid_ipv4=false
                break
            fi
        done
        
        if [[ "$valid_ipv4" == "true" && "$detected_ip" != "127.0.0.1" ]]; then
            USER_IP="$detected_ip"
            log "INFO" "Valid IPv4 client IP confirmed: $USER_IP"
        else
            USER_IP="$detected_ip (invalid)"
            log "WARNING" "Invalid or localhost IP detected: $detected_ip"
        fi
    else
        USER_IP="not detected"  
        log "WARNING" "No SSH client IP found - SSH_CLIENT and SSH_CONNECTION empty"
    fi
    
    log "INFO" "IP for fail2ban whitelist: $USER_IP"
}

# Detect operating system
detect_os() {
    local os_name=""
    local os_version=""
    local package_manager=""
    
    if [[ -f /etc/os-release ]]; then
        source /etc/os-release
        os_name="$NAME"
        os_version="$VERSION_ID"
    else
        print_error "Cannot detect operating system"
        exit 1
    fi
    
    # Determine package manager
    if command -v dnf >/dev/null 2>&1; then
        package_manager="dnf"
    elif command -v yum >/dev/null 2>&1; then
        package_manager="yum"
    elif command -v apt >/dev/null 2>&1; then
        package_manager="apt"
    elif command -v zypper >/dev/null 2>&1; then
        package_manager="zypper"
    elif command -v pacman >/dev/null 2>&1; then
        package_manager="pacman"
    else
        print_error "Unsupported package manager"
        exit 1
    fi
    
    echo -e "     Detected OS: ${BLUE}$os_name $os_version${NC}"
    echo -e "     Package Manager: ${BLUE}$package_manager${NC}"
    
    echo ""
    echo -e "${BLUE}===========================================================================${NC}"
    echo ""
    
    log "INFO" "Detected OS: $os_name $os_version"
    log "INFO" "Package manager: $package_manager"
    
    # Store in global variables for later use
    export OS_NAME="$os_name"
    export OS_VERSION="$os_version"
    export PACKAGE_MANAGER="$package_manager"
    
    # Confirm with user (skip in non-interactive mode)
    if [[ "$SKIP_CONFIRMATION" != "true" ]]; then
        echo ""
        while true; do
            echo -e "Continue installation on ${BLUE}$os_name $os_version${NC} (y/N): \c"
            read -r
            case $REPLY in
                [Yy]*)
                    break
                    ;;
                [Nn]*|"")
                    # Clean up install log file since installation was cancelled
                    if [[ -n "$LOG_FILE" && -f "$LOG_FILE" ]]; then
                        rm -f "$LOG_FILE" 2>/dev/null || true
                    fi
                    exit 0
                    ;;
                *)
                    echo -e "${YELLOW}[WARNING]${NC} Invalid response. y/N required."
                    ;;
            esac
        done
    else
        echo ""
        print_info "Proceeding with installation on $os_name $os_version (non-interactive mode)"
        log "INFO" "Proceeding with installation on $os_name $os_version (non-interactive mode)"
    fi
    print_info "Install OS ${BLUE}$os_name $os_version${NC}"
}

# Check VPN status
check_vpn() {
    echo ""
    echo -e "   ${BLUE}VPN Options:${NC}"
    echo -e "   ${BLUE}-----------${NC}"
    
    while true; do
        echo -e "Are you currently using a VPN? (y/N): \c"
        read -r
        
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            print_info "Connection changes during install could lock you out of the server."
            log "WARNING" "User confirmed VPN usage"
            
            read -p "Continue anyway? (y/N): " -r
            if [[ ! $REPLY =~ ^[Yy]$ ]]; then
                exit 0
            fi
            break
        elif [[ $REPLY =~ ^[Nn]$ ]] || [[ -z "$REPLY" ]]; then
            print_info "No VPN"
            log "INFO" "User confirmed no VPN usage"
            break
        else
            print_warning "Invalid response. y/N required."
        fi
    done
}

# Get user's SSH IP for firewall whitelist
get_user_ip() {
    local ssh_connection=""
    local current_ip=""
    
    # Try to get IPv4 IP from SSH_CLIENT environment variable
    if [[ -n "${SSH_CLIENT:-}" ]]; then
        local ssh_ip=$(echo "$SSH_CLIENT" | awk '{print $1}')
        # Only use if it's a valid IPv4 address
        if [[ "$ssh_ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
            current_ip="$ssh_ip"
        fi
    # Try to get IPv4 IP from SSH_CONNECTION environment variable
    elif [[ -n "${SSH_CONNECTION:-}" ]]; then
        local ssh_ip=$(echo "$SSH_CONNECTION" | awk '{print $1}')
        # Only use if it's a valid IPv4 address
        if [[ "$ssh_ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
            current_ip="$ssh_ip"
        fi
    # Try to get IP from WHO command (less reliable)
    elif command -v who >/dev/null 2>&1; then
        local who_ip=$(who am i | awk '{print $5}' | sed 's/[()]//g')
        # Only use if it's a valid IPv4 address
        if [[ "$who_ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
            current_ip="$who_ip"
        fi
    fi
    
    if [[ -n "$current_ip" && "$current_ip" != "127.0.0.1" ]] && validate_ip_address "$current_ip"; then
        echo ""
        echo -e "${BLUE}IP Address:${NC}"
        echo -e "${BLUE}----------${NC}"
        echo -e "Detected SSH connection from IP: ${BLUE}$current_ip${NC}"
        USER_IP="$current_ip"
        log "INFO" "User SSH IP detected: $current_ip"
        
        read -p "Is this your local IP? (y/N): " -r
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            while true; do
                read -p "Enter your IP address manually: " -r USER_IP
                if [[ -z "$USER_IP" ]]; then
                    print_warning "No IP provided. Firewall may block your access!"
                    log "WARNING" "No user IP provided for firewall whitelist"
                    break
                fi
                # Sanitize and validate IP input
                USER_IP=$(sanitize_input "$USER_IP")
                if validate_ip_address "$USER_IP"; then
                    break
                else
                    print_error "Invalid IP address format. Please enter a valid IPv4 or IPv6 address."
                    USER_IP=""
                fi
            done
        fi
    else
        print_warning "Could not detect your IP address automatically"
        while true; do
            read -p "Enter your IP address for firewall whitelist (optional): " -r USER_IP
            if [[ -z "$USER_IP" ]]; then
                print_warning "No IP provided. Firewall may block your access!"
                log "WARNING" "No user IP provided for firewall whitelist"
                break
            fi
            # Sanitize and validate IP input
            USER_IP=$(sanitize_input "$USER_IP")
            if validate_ip_address "$USER_IP"; then
                break
            else
                print_error "Invalid IP address format. Please enter a valid IPv4 or IPv6 address."
                USER_IP=""
            fi
        done
    fi
    
    if [[ -n "$USER_IP" ]]; then
        print_info "$USER_IP will be whitelisted"
        log "INFO" "User IP for firewall whitelist: $USER_IP"
    fi
}

# Ask about domain setup
ask_domain_setup() {
    echo ""
    read -p "Will you be setting up a domain? (y/N): " -r
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        while true; do
            read -p "Enter your domain name (e.g., example.com): " -r DOMAIN_NAME
            # Sanitize input to prevent injection
            DOMAIN_NAME=$(sanitize_input "$DOMAIN_NAME")
            if [[ -n "$DOMAIN_NAME" ]] && validate_domain_name "$DOMAIN_NAME"; then
                print_success "Domain set to: $DOMAIN_NAME"
                log "INFO" "Domain name set: $DOMAIN_NAME"
                
                # Ask for username
                while true; do
                    read -p "Enter username for the domain user: " -r USERNAME
                    # Sanitize input to prevent injection
                    USERNAME=$(sanitize_input "$USERNAME")
                    if [[ -n "$USERNAME" ]] && validate_username "$USERNAME"; then
                        CREATE_USER=true
                        print_success "User '$USERNAME' will be created with home directory"
                        log "INFO" "Username set: $USERNAME"
                        break
                    else
                        print_error "Invalid username. Must start with letter/underscore, contain only lowercase letters, numbers, underscore, and dash (3-32 chars). Cannot be an existing user."
                    fi
                done
                break
            else
                print_error "Invalid domain name format. Must be a valid RFC 1035 compliant domain name."
            fi
        done
    else
        print_info "Skipping domain"
        log "INFO" "User skipped domain setup"
    fi
}

# Show resource usage for selected components in installation summary
show_resource_usage_for_selection() {
    # Get system information
    local total_ram_kb=$(grep MemTotal /proc/meminfo | awk '{print $2}')
    local total_ram_gb=$((total_ram_kb / 1024 / 1024))
    local available_disk_gb=$(df / | tail -1 | awk '{print int($4/1024/1024)}')
    local cpu_cores=$(nproc)
    
    echo ""
    echo -e "   ${BLUE}System Resources:${NC}"
    echo "     • CPU Cores: $cpu_cores"
    echo "     • Total RAM: ${total_ram_gb}GB"
    echo "     • Available Disk Space: ${available_disk_gb}GB"
    
    echo ""
    echo -e "   ${BLUE}Recommended Resources (Based on Selected):${NC}"
    echo "     • 1 CPU core"
    echo "     • 1GB RAM"
    echo "     • 5GB disk space"
    echo "     • Components: Web server + 1 database + PHP"
    
    echo ""
    echo ""
    
    log "INFO" "Resource check: ${cpu_cores} cores, ${total_ram_gb}GB RAM, ${available_disk_gb}GB disk"
}

# Choose web server
choose_webserver() {
    echo ""
    echo -e "${BLUE}Web Server Selection:${NC}"
    echo -e "${BLUE}--------------------${NC}"
    echo "1. Apache (httpd)"
    echo "2. Nginx"
    echo "3. None"
    
    while true; do
        read -p "Choose web server (1-3): " -r choice
        case $choice in
            1)
                SELECTED_WEBSERVER="apache"
                print_info "Apache selected"
                log "INFO" "Web server selected: Apache"
                break
                ;;
            2)
                SELECTED_WEBSERVER="nginx"
                print_info "Nginx selected"
                log "INFO" "Web server selected: Nginx"
                break
                ;;
            3)
                SELECTED_WEBSERVER="none"
                print_info "No web server selected - skipping web server installation"
                log "INFO" "Web server selected: None"
                break
                ;;
            *)
                print_warning "Invalid response. 1-3 required."
                ;;
        esac
    done
}

# Choose database
choose_database() {
    echo ""
    echo -e "${BLUE}Database Selection ${WHITE}(multiple allowed)${BLUE}:${NC}"
    echo -e "${BLUE}--------------------------------------${NC}"
    echo "1. MySQL"
    echo "2. MariaDB"
    echo "3. PostgreSQL"
    echo "4. SQLite3"
    echo "5. None"
    echo "For multiple use spaces (1 2 3):"
    echo -e "${PURPLE}[TIP]${NC} ${WHITE}MySQL and MariaDB cannot be installed together${NC}"
    
    SELECTED_DATABASES=()
    
    while true; do
        read -p "Choose databases or '5' for none: " -r choice
        
        # Reset array for new selection
        SELECTED_DATABASES=()
        
        # Handle "none" or "5" choice
        if [[ "$choice" == "5" || "$choice" == "none" ]]; then
            SELECTED_DATABASES=("none")
            print_info "No databases selected - skipping database installation"
            log "INFO" "Databases: None selected"
            break
        fi
        
        # Parse space-separated choices
        valid_selection=true
        
        for c in $choice; do
            case "$c" in
                1)
                    if [[ ! " ${SELECTED_DATABASES[*]} " =~ " mysql " ]]; then
                        SELECTED_DATABASES+=("mysql")
                    fi
                    ;;
                2)
                    if [[ ! " ${SELECTED_DATABASES[*]} " =~ " mariadb " ]]; then
                        SELECTED_DATABASES+=("mariadb")
                    fi
                    ;;
                3)
                    if [[ ! " ${SELECTED_DATABASES[*]} " =~ " postgresql " ]]; then
                        SELECTED_DATABASES+=("postgresql")
                    fi
                    ;;
                4)
                    if [[ ! " ${SELECTED_DATABASES[*]} " =~ " sqlite " ]]; then
                        SELECTED_DATABASES+=("sqlite")
                    fi
                    ;;
                *)
                    print_warning "Choose databases or '5' for none:"
                    valid_selection=false
                    break
                    ;;
            esac
        done
        
        if [[ "$valid_selection" == true && ${#SELECTED_DATABASES[@]} -gt 0 ]]; then
            # Check for conflicting database selections
            if [[ " ${SELECTED_DATABASES[*]} " =~ " mysql " && " ${SELECTED_DATABASES[*]} " =~ " mariadb " ]]; then
                print_error "MySQL and MariaDB cannot be installed together (port 3306 conflict)"
                print_info "Please choose either MySQL OR MariaDB, not both"
                continue
            fi
            
            if [[ "${SELECTED_DATABASES[0]}" == "none" ]]; then
                print_success "Databases: None"
            else
                print_info "Selected databases: ${SELECTED_DATABASES[*]}"
                log "INFO" "Databases selected: ${SELECTED_DATABASES[*]}"
            fi
            break
        fi
    done
}

# Choose PHP versions
choose_php_versions() {
    echo ""
    echo -e "${BLUE}PHP Selection ${WHITE}8.2, 8.3, 8.4${BLUE}:${NC}"
    echo -e "${BLUE}---------------------------${NC}"
    echo "1. 8.2"
    echo "2. 8.3"
    echo "3. 8.4"
    echo "4. None"
    echo "For multiple use spaces (1 2 3):"
    
    while true; do
        read -p "Choose PHP version(s) or '4' for none: " -r php_input
        if [[ -z "$php_input" ]]; then
            print_warning "Invalid response. 1-4 required."
            continue
        fi
        
        # Check for 'none' option (4 or 'none')
        if [[ "$php_input" == "none" || "$php_input" == "4" ]]; then
            SELECTED_PHP_VERSIONS=("none")
            print_info "PHP installation will be skipped"
            log "INFO" "PHP installation skipped by user choice"
            break
        fi
        
        # Parse input for PHP versions (convert numbers to versions)
        valid_versions=true
        SELECTED_PHP_VERSIONS=()
        
        for selection in $php_input; do
            case $selection in
                1)
                    SELECTED_PHP_VERSIONS+=("8.2")
                    ;;
                2)
                    SELECTED_PHP_VERSIONS+=("8.3")
                    ;;
                3)
                    SELECTED_PHP_VERSIONS+=("8.4")
                    ;;
                8.2)
                    SELECTED_PHP_VERSIONS+=("8.2")
                    ;;
                8.3)
                    SELECTED_PHP_VERSIONS+=("8.3")
                    ;;
                8.4)
                    SELECTED_PHP_VERSIONS+=("8.4")
                    ;;
                *)
                    print_warning "Invalid response. 1-4 required."
                    valid_versions=false
                    break
                    ;;
            esac
        done
        
        if [[ "$valid_versions" == true ]]; then
            print_info "Selected PHP versions: ${SELECTED_PHP_VERSIONS[*]}"
            log "INFO" "PHP versions selected: ${SELECTED_PHP_VERSIONS[*]}"
            
            # If multiple PHP versions selected, ask for default
            if [[ ${#SELECTED_PHP_VERSIONS[@]} -gt 1 ]]; then
                echo ""
                echo -e "${BLUE}Default PHP Version Selection:${NC}"
                echo -e "${BLUE}------------------------------${NC}"
                echo "Multiple PHP versions selected. Which should be the default?"
                for i in "${!SELECTED_PHP_VERSIONS[@]}"; do
                    echo "  $((i+1)). PHP ${SELECTED_PHP_VERSIONS[i]}"
                done
                echo ""
                
                while true; do
                    read -p "Select default PHP version (1-${#SELECTED_PHP_VERSIONS[@]}): " default_choice
                    
                    if [[ "$default_choice" =~ ^[1-9][0-9]*$ ]] && [[ "$default_choice" -ge 1 ]] && [[ "$default_choice" -le "${#SELECTED_PHP_VERSIONS[@]}" ]]; then
                        local selected_index=$((default_choice - 1))
                        DEFAULT_PHP_VERSION="${SELECTED_PHP_VERSIONS[selected_index]}"
                        
                        print_info "PHP $DEFAULT_PHP_VERSION selected as default"
                        log "INFO" "User selected PHP $DEFAULT_PHP_VERSION as default version during selection"
                        break
                    else
                        print_warning "Invalid response. 1-${#SELECTED_PHP_VERSIONS[@]} required."
                    fi
                done
            else
                # Single version, set it as default
                DEFAULT_PHP_VERSION="${SELECTED_PHP_VERSIONS[0]}"
            fi
            
            break
        fi
    done
}

# Choose package managers
choose_package_managers() {
    echo ""
    echo -e "${BLUE}Package Manager Selection ${WHITE}(multiple allowed)${BLUE}:${NC}"
    echo -e "${BLUE}--------------------------------------------${NC}"
    echo "1. Composer (PHP package manager)"
    echo "2. Node.js + npm (JavaScript package manager)"
    echo "3. None (Skip package manager installation)"
    echo "For multiple use spaces (1 2):"
    
    SELECTED_PACKAGE_MANAGERS=()
    
    while true; do
        read -p "Choose package managers or '3' for none: " -r choice
        
        # Reset array for new selection
        SELECTED_PACKAGE_MANAGERS=()
        
        # Handle "none" or "3" choice
        if [[ "$choice" == "3" || "$choice" == "none" ]]; then
            SELECTED_PACKAGE_MANAGERS=("none")
            print_info "No package managers selected - skipping installation"
            log "INFO" "Package managers: None selected"
            break
        fi
        
        # Parse space-separated choices
        valid_selection=true
        
        for c in $choice; do
            case "$c" in
                1)
                    if [[ ! " ${SELECTED_PACKAGE_MANAGERS[*]} " =~ " composer " ]]; then
                        # Check if PHP is required for Composer
                        if [[ "${SELECTED_PHP_VERSIONS[0]}" == "none" ]]; then
                            echo ""
                            print_warning "Composer requires PHP to function!"
                            print_info "You previously selected 'none' for PHP versions."
                            echo ""
                            read -p "Would you like to select PHP versions now? (Y/n): " -r
                            if [[ ! $REPLY =~ ^[Nn]$ ]]; then
                                echo ""
                                print_info "Please select at least one PHP version for Composer:"
                                choose_php_versions
                                echo ""
                                print_success "PHP versions updated. Continuing with package manager selection..."
                            else
                                print_info "Skipping Composer (PHP not selected)"
                                continue
                            fi
                        fi
                        SELECTED_PACKAGE_MANAGERS+=("composer")
                    fi
                    ;;
                2)
                    if [[ ! " ${SELECTED_PACKAGE_MANAGERS[*]} " =~ " nodejs " ]]; then
                        SELECTED_PACKAGE_MANAGERS+=("nodejs")
                    fi
                    ;;
                *)
                    print_warning "Choose package managers or '3' for none:"
                    valid_selection=false
                    break
                    ;;
            esac
        done
        
        if [[ "$valid_selection" == true && ${#SELECTED_PACKAGE_MANAGERS[@]} -gt 0 ]]; then
            if [[ "${SELECTED_PACKAGE_MANAGERS[0]}" == "none" ]]; then
                print_success "Package managers: None"
            else
                print_info "Selected package managers: ${SELECTED_PACKAGE_MANAGERS[*]}"
                log "INFO" "Package managers selected: ${SELECTED_PACKAGE_MANAGERS[*]}"
            fi
            break
        fi
    done
}

# Choose development tools
choose_development_tools() {
    echo ""
    echo -e "${BLUE}Development Tools Selection ${WHITE}(multiple allowed)${BLUE}:${NC}"
    echo -e "${BLUE}----------------------------------------------${NC}"
    echo "1. Git (version control system)"
    echo "2. GitHub CLI (gh command)"
    echo "3. Claude AI Code (AI-powered coding assistant) *requires Node.js"
    echo "4. None (Skip development tools installation)"
    echo "For multiple use spaces (1 2 3):"
    
    SELECTED_DEVELOPMENT_TOOLS=()
    
    while true; do
        read -p "Choose development tools or '4' for none: " -r choice
        
        # Reset array for new selection
        SELECTED_DEVELOPMENT_TOOLS=()
        
        # Handle "none" or "4" choice
        if [[ "$choice" == "4" || "$choice" == "none" ]]; then
            SELECTED_DEVELOPMENT_TOOLS=("none")
            print_info "No development tools selected - skipping installation"
            log "INFO" "Development tools: None selected"
            break
        fi
        
        # Parse space-separated choices
        valid_selection=true
        
        for c in $choice; do
            
            case "$c" in
                1)
                    if [[ ! " ${SELECTED_DEVELOPMENT_TOOLS[*]} " =~ " git " ]]; then
                        SELECTED_DEVELOPMENT_TOOLS+=("git")
                    fi
                    ;;
                2)
                    if [[ ! " ${SELECTED_DEVELOPMENT_TOOLS[*]} " =~ " github-cli " ]]; then
                        SELECTED_DEVELOPMENT_TOOLS+=("github-cli")
                    fi
                    ;;
                3)
                    if [[ ! " ${SELECTED_DEVELOPMENT_TOOLS[*]} " =~ " claude-ai " ]]; then
                        # Claude AI Code requires Node.js - auto-add if not selected
                        if [[ ! " ${SELECTED_PACKAGE_MANAGERS[*]} " =~ " nodejs " ]] && [[ "${SELECTED_PACKAGE_MANAGERS[0]}" != "none" ]]; then
                            print_info "Note: Claude AI Code requires Node.js. Node.js will be automatically installed."
                            log "INFO" "Claude Code dependency: Node.js will be auto-installed"
                        fi
                        SELECTED_DEVELOPMENT_TOOLS+=("claude-ai")
                    fi
                    ;;
                *)
                    print_warning "Choose development tools or '4' for none:"
                    valid_selection=false
                    break
                    ;;
            esac
        done
        
        if [[ "$valid_selection" == true && ${#SELECTED_DEVELOPMENT_TOOLS[@]} -gt 0 ]]; then
            if [[ "${SELECTED_DEVELOPMENT_TOOLS[0]}" == "none" ]]; then
                print_success "Development tools: None"
            else
                print_info "Selected development tools: ${SELECTED_DEVELOPMENT_TOOLS[*]}"
                log "INFO" "Development tools selected: ${SELECTED_DEVELOPMENT_TOOLS[*]}"
                
                # Check for Claude Code dependency
                if [[ " ${SELECTED_DEVELOPMENT_TOOLS[*]} " =~ " claude-ai " ]]; then
                    if [[ ! " ${SELECTED_PACKAGE_MANAGERS[*]} " =~ " nodejs " ]] && [[ "${SELECTED_PACKAGE_MANAGERS[0]}" != "none" ]]; then
                        echo ""
                        print_info "Note: Claude AI Code requires Node.js. Node.js will be automatically installed."
                        log "INFO" "Claude Code dependency: Node.js will be auto-installed"
                    fi
                fi
            fi
            break
        fi
    done
}

# Installation summary for preset configurations
show_preset_installation_summary() {
    local preset_name="$1"
    
    echo ""
    echo -e "${BLUE}===========================================================================${NC}"
    echo -e "${WHITE}                           INSTALLATION SUMMARY${NC}"
    echo -e "${BLUE}===========================================================================${NC}"
    echo ""
    echo "   Preset: $preset_name"
    echo ""
    echo -e "   ${BLUE}Setup Options:${NC}"
    echo "     • Operating System: $OS_NAME $OS_VERSION"
    echo "     • Package Manager: $PACKAGE_MANAGER"
    echo "     • Web Server: $SELECTED_WEBSERVER"
    if [[ "${SELECTED_DATABASES[0]}" != "none" ]]; then
        echo "     • Databases: ${SELECTED_DATABASES[*]}"
    fi
    if [[ "${SELECTED_PHP_VERSIONS[0]}" != "none" ]]; then
        echo "     • PHP Versions: ${SELECTED_PHP_VERSIONS[*]}"
    fi
    if [[ "${SELECTED_PACKAGE_MANAGERS[0]}" != "none" ]]; then
        echo "     • Package Managers: ${SELECTED_PACKAGE_MANAGERS[*]}"
    fi
    if [[ "${SELECTED_DEVELOPMENT_TOOLS[0]}" != "none" ]]; then
        echo "     • Development Tools: ${SELECTED_DEVELOPMENT_TOOLS[*]}"
    fi
    if [[ -n "$USER_IP" ]]; then
        echo "     • Firewall Whitelist IP: $USER_IP"
    fi
    
    echo ""
    echo -e "   ${BLUE}Components to install:${NC}"
    # Display webserver name with proper capitalization
    local webserver_display="$SELECTED_WEBSERVER"
    [[ "$SELECTED_WEBSERVER" == "apache" ]] && webserver_display="Apache"
    [[ "$SELECTED_WEBSERVER" == "nginx" ]] && webserver_display="Nginx"
    [[ "$SELECTED_WEBSERVER" == "none" ]] && webserver_display=""
    [[ -n "$webserver_display" ]] && echo "     • $webserver_display web server"
    
    if [[ "${SELECTED_PHP_VERSIONS[0]}" != "none" ]]; then
        echo "     • PHP ${SELECTED_PHP_VERSIONS[*]} with extensions"
    fi
    # Display database name with proper capitalization
    if [[ "${SELECTED_DATABASES[0]}" != "none" ]]; then
        local database_list=""
        for db in "${SELECTED_DATABASES[@]}"; do
            local db_display="$db"
            [[ "$db" == "sqlite" ]] && db_display="SQLite"
            [[ "$db" == "mysql" ]] && db_display="MySQL"
            [[ "$db" == "mariadb" ]] && db_display="MariaDB"
            [[ "$db" == "postgresql" ]] && db_display="PostgreSQL"
            database_list="$database_list$db_display, "
        done
        database_list="${database_list%, }"  # Remove trailing comma
        echo "     • ${database_list} database(s)"
    fi
    echo "     • Fail2ban security service"
    echo "     • Firewall configuration"
    
    # Show system resources concisely
    local total_ram_kb=$(grep MemTotal /proc/meminfo | awk '{print $2}')
    local total_ram_gb=$((total_ram_kb / 1024 / 1024))
    local available_disk_gb=$(df / | tail -1 | awk '{print int($4/1024/1024)}')
    local cpu_cores=$(nproc)
    
    echo ""
    echo -e "   ${BLUE}System Resources:${NC}"
    echo "     • CPU Cores: $cpu_cores"
    echo "     • Total RAM: ${total_ram_gb}GB"
    echo "     • Available Disk Space: ${available_disk_gb}GB"
    
    echo ""
    echo ""
    echo -e "${BLUE}===========================================================================${NC}"
    echo ""
    
    if [[ "$AUTO_PRESET" != "true" ]]; then
        read -p "Proceed with installation? (y/N): " -r
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            print_info "Installation cancelled by user"
            log "INFO" "Installation cancelled by user at summary"
            exit 0
        fi
    fi
    
    log "INFO" "User confirmed installation (preset: $preset_name)"
}

# Installation summary
show_installation_summary() {
    echo ""
    echo -e "${BLUE}===========================================================================${NC}"
    echo -e "${WHITE}                           INSTALLATION SUMMARY${NC}"
    echo -e "${BLUE}===========================================================================${NC}"
    echo ""
    echo -e "   ${BLUE}Setup Options:${NC}"
    echo "     • Operating System: $OS_NAME $OS_VERSION"
    echo "     • Package Manager: $PACKAGE_MANAGER"
    echo "     • Web Server: $SELECTED_WEBSERVER"
    if [[ "${SELECTED_DATABASES[0]}" != "none" ]]; then
        echo "     • Databases: ${SELECTED_DATABASES[*]}"
    else
        echo "     • Database: none"
    fi
    if [[ "${SELECTED_PHP_VERSIONS[0]}" != "none" ]]; then
        echo "     • PHP Versions: ${SELECTED_PHP_VERSIONS[*]}"
    else
        echo "     • PHP Versions: None (skipped)"
    fi
    if [[ "${SELECTED_PACKAGE_MANAGERS[0]}" != "none" ]]; then
        echo "     • Package Managers: ${SELECTED_PACKAGE_MANAGERS[*]}"
    else
        echo "     • Package Managers: None (skipped)"
    fi
    if [[ "${SELECTED_DEVELOPMENT_TOOLS[0]}" != "none" ]]; then
        echo "     • Development Tools: ${SELECTED_DEVELOPMENT_TOOLS[*]}"
    else
        echo "     • Development Tools: None (skipped)"
    fi
    
    if [[ "$CREATE_USER" == true ]]; then
        echo "     Domain: $DOMAIN_NAME"
        echo "     Username: $USERNAME"
        echo "     Home Directory: /home/$USERNAME"
        if [[ "${SELECTED_PHP_VERSIONS[0]}" != "none" ]]; then
            echo "     Test Page: Hello World! PHP page will be created"
        else
            echo "     Test Page: Basic HTML page will be created"
        fi
    fi
    
    if [[ -n "$USER_IP" ]]; then
        echo "     • Firewall Whitelist IP: $USER_IP"
    fi
    
    echo ""
    echo -e "   ${BLUE}Components to install:${NC}"
    # Display webserver name with proper capitalization
    local webserver_display="$SELECTED_WEBSERVER"
    [[ "$SELECTED_WEBSERVER" == "apache" ]] && webserver_display="Apache"
    [[ "$SELECTED_WEBSERVER" == "nginx" ]] && webserver_display="Nginx"
    echo "     • $webserver_display web server"
    if [[ "${SELECTED_PHP_VERSIONS[0]}" != "none" ]]; then
        echo "     • PHP ${SELECTED_PHP_VERSIONS[*]} with extensions"
    else
        echo "     • PHP: None (skipped)"
    fi
    # Display database name with proper capitalization
    if [[ "${SELECTED_DATABASES[0]}" != "none" ]]; then
        local database_list=""
        for db in "${SELECTED_DATABASES[@]}"; do
            local db_display="$db"
            [[ "$db" == "sqlite" ]] && db_display="SQLite"
            [[ "$db" == "mysql" ]] && db_display="MySQL"
            [[ "$db" == "mariadb" ]] && db_display="MariaDB"
            [[ "$db" == "postgresql" ]] && db_display="PostgreSQL"
            database_list="$database_list$db_display, "
        done
        database_list="${database_list%, }"  # Remove trailing comma
        echo "     • ${database_list} database(s)"
    fi
    echo "     • Fail2ban security service"
    echo "     • Firewall configuration"
    
    if [[ "$CREATE_USER" == true ]]; then
        echo "     • User account: $USERNAME"
        echo "     • Virtual host for: $DOMAIN_NAME"
    fi
    
    
    # Add resource usage section
    show_resource_usage_for_selection
    
    echo -e "${BLUE}===========================================================================${NC}"
    echo ""
    
    read -p "Proceed with installation? (y/N): " -r
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        print_info "Installation cancelled by user"
        log "INFO" "Installation cancelled by user at summary"
        exit 0
    fi
    
    log "INFO" "User confirmed installation"
}

# Package installation helper
install_package() {
    local package="$1"
    local description="${2:-$package}"
    
    if [[ "$VERBOSE_LOGGING" == true ]]; then
        print_info "Installing $description..."
    fi
    log "INFO" "Installing package: $package"
    
    case "$PACKAGE_MANAGER" in
        dnf|yum)
            if ! run_with_spinner "Installing $description" $PACKAGE_MANAGER install -y "$package" >/dev/null 2>&1; then
                print_error "Failed to install $description"
                log "ERROR" "Package installation failed: $package"
                return 1
            fi
            ;;
        apt)
            if ! run_with_spinner "Installing $description" apt-get install -y "$package" >/dev/null 2>&1; then
                print_error "Failed to install $description"
                log "ERROR" "Package installation failed: $package"
                return 1
            fi
            ;;
        zypper)
            if ! run_with_spinner "Installing $description" zypper install -y "$package" >/dev/null 2>&1; then
                print_error "Failed to install $description"
                log "ERROR" "Package installation failed: $package"
                return 1
            fi
            ;;
        pacman)
            if ! run_with_spinner "Installing $description" pacman -S --noconfirm "$package" >/dev/null 2>&1; then
                print_error "Failed to install $description"
                log "ERROR" "Package installation failed: $package"
                return 1
            fi
            ;;
    esac
    
    INSTALLED_PACKAGES+=("$package")
    if [[ "$VERBOSE_LOGGING" == true ]]; then
        print_success "$description installed successfully"
    fi
    log "INFO" "Package installed successfully: $package"
}

# System update function
update_system() {
    print_info "Updating system packages..."
    log "INFO" "Starting system update"
    
    case "$PACKAGE_MANAGER" in
        dnf)
            if run_with_spinner "Updating system packages" dnf upgrade -y >/dev/null 2>&1; then
                if run_with_spinner "Installing essential tools" dnf install -y curl wget net-tools nmap-ncat atop >/dev/null 2>&1; then
                    print_success "Essential tools installed: curl, wget, net-tools, netcat, atop"
                    log "SUCCESS" "Essential tools installed successfully (dnf)"
                    # Verify installations
                    for tool in curl wget netstat nc atop; do
                        if command -v "$tool" >/dev/null 2>&1; then
                            log "INFO" "Verified: $tool is available"
                        else
                            log "WARNING" "Essential tool not found: $tool"
                        fi
                    done
                else
                    print_error "Failed to install essential tools"
                    log "ERROR" "Essential tools installation failed (dnf)"
                fi
            fi
            ;;
        yum)
            if run_with_spinner "Updating system packages" yum update -y >/dev/null 2>&1; then
                if run_with_spinner "Installing essential tools" yum install -y curl wget net-tools nmap-ncat atop >/dev/null 2>&1; then
                    print_success "Essential tools installed: curl, wget, net-tools, netcat, atop"
                    log "SUCCESS" "Essential tools installed successfully (yum)"
                    # Verify installations
                    for tool in curl wget netstat nc atop; do
                        if command -v "$tool" >/dev/null 2>&1; then
                            log "INFO" "Verified: $tool is available"
                        else
                            log "WARNING" "Essential tool not found: $tool"
                        fi
                    done
                else
                    print_error "Failed to install essential tools"
                    log "ERROR" "Essential tools installation failed (yum)"
                fi
            fi
            ;;
        apt)
            if run_with_spinner "Updating package lists" apt-get update >/dev/null 2>&1; then
                if run_with_spinner "Upgrading system packages" apt-get upgrade -y >/dev/null 2>&1; then
                    if run_with_spinner "Installing essential tools" apt-get install -y curl wget net-tools netcat-openbsd atop >/dev/null 2>&1; then
                        print_success "Essential tools installed: curl, wget, net-tools, netcat, atop"
                        log "SUCCESS" "Essential tools installed successfully (apt)"
                        # Verify installations
                        for tool in curl wget netstat nc atop; do
                            if command -v "$tool" >/dev/null 2>&1; then
                                log "INFO" "Verified: $tool is available"
                            else
                                log "WARNING" "Essential tool not found: $tool"
                            fi
                        done
                    else
                        print_error "Failed to install essential tools"
                        log "ERROR" "Essential tools installation failed (apt)"
                    fi
                fi
            fi
            ;;
        zypper)
            if run_with_spinner "Refreshing repositories" zypper refresh >/dev/null 2>&1; then
                if run_with_spinner "Upgrading system packages" zypper dist-upgrade -y >/dev/null 2>&1; then
                    if run_with_spinner "Installing essential tools" zypper install -y curl wget net-tools netcat-openbsd atop >/dev/null 2>&1; then
                        print_success "Essential tools installed: curl, wget, net-tools, netcat, atop"
                        log "SUCCESS" "Essential tools installed successfully (zypper)"
                        # Verify installations
                        for tool in curl wget netstat nc atop; do
                            if command -v "$tool" >/dev/null 2>&1; then
                                log "INFO" "Verified: $tool is available"
                            else
                                log "WARNING" "Essential tool not found: $tool"
                            fi
                        done
                    else
                        print_error "Failed to install essential tools"
                        log "ERROR" "Essential tools installation failed (zypper)"
                    fi
                fi
            fi
            ;;
        pacman)
            if run_with_spinner "Updating system packages" pacman -Syu --noconfirm >/dev/null 2>&1; then
                if run_with_spinner "Installing essential tools" pacman -S --noconfirm curl wget net-tools gnu-netcat atop >/dev/null 2>&1; then
                    print_success "Essential tools installed: curl, wget, net-tools, netcat, atop"
                    log "SUCCESS" "Essential tools installed successfully (pacman)"
                    # Verify installations
                    for tool in curl wget netstat nc atop; do
                        if command -v "$tool" >/dev/null 2>&1; then
                            log "INFO" "Verified: $tool is available"
                        else
                            log "WARNING" "Essential tool not found: $tool"
                        fi
                    done
                else
                    print_error "Failed to install essential tools"
                    log "ERROR" "Essential tools installation failed (pacman)"
                fi
            fi
            ;;
    esac
    
    print_success "System updated successfully"
    log "INFO" "System update completed"
}

# Setup repositories
setup_repositories() {
    print_info "Setting up package repositories..."
    log "INFO" "Setting up repositories for $OS_NAME"
    
    case "$PACKAGE_MANAGER" in
        dnf|yum)
            # Install EPEL repository
            if ! rpm -qa | grep -q epel-release; then
                install_package "epel-release" "EPEL Repository"
            fi
            
            # Install Remi repository for PHP
            if [[ "$OS_NAME" =~ (AlmaLinux|Rocky|CentOS|Red) ]]; then
                if ! rpm -qa | grep -q remi-release; then
                    if [[ "$OS_VERSION" =~ ^9 ]]; then
                        $PACKAGE_MANAGER install -y https://rpms.remirepo.net/enterprise/remi-release-9.rpm >/dev/null 2>&1
                    elif [[ "$OS_VERSION" =~ ^8 ]]; then
                        $PACKAGE_MANAGER install -y https://rpms.remirepo.net/enterprise/remi-release-8.rpm >/dev/null 2>&1
                    fi
                    print_success "Remi repository installed"
                fi
            fi
            ;;
        apt)
            # Add Ondrej PHP repository for Ubuntu/Debian
            if ! grep -q "ondrej/php" /etc/apt/sources.list.d/* 2>/dev/null; then
                apt-get install -y software-properties-common >/dev/null 2>&1
                add-apt-repository -y ppa:ondrej/php >/dev/null 2>&1
                apt-get update >/dev/null 2>&1
                print_success "Ondrej PHP repository added"
            fi
            ;;
    esac
    
    print_success "Repositories configured successfully"
    log "INFO" "Repository setup completed"
}

# Install Apache web server
install_apache() {
    print_info "Installing Apache web server..."
    log "INFO" "Starting Apache installation"
    
    local apache_package=""
    local service_name=""
    
    case "$PACKAGE_MANAGER" in
        dnf|yum)
            apache_package="httpd"
            service_name="httpd"
            ;;
        apt)
            apache_package="apache2"
            service_name="apache2"
            ;;
        zypper)
            apache_package="apache2"
            service_name="apache2"
            ;;
        pacman)
            apache_package="apache"
            service_name="httpd"
            ;;
    esac
    
    install_package "$apache_package" "Apache Web Server"
    
    # Ensure DocumentRoot directory exists before starting Apache
    local web_root="/var/www/html"
    case "$PACKAGE_MANAGER" in
        zypper)
            web_root="/srv/www/htdocs"
            ;;
        pacman)
            web_root="/srv/http"
            ;;
    esac
    mkdir -p "$web_root"
    
    # Start and enable Apache
    systemctl start "$service_name"
    if systemctl enable "$service_name" >/dev/null 2>&1; then
        print_success "$service_name service enabled for startup"
    else
        print_warning "Failed to enable $service_name service for startup"
    fi
    INSTALLED_SERVICES+=("$service_name")
    
    # Configure firewall
    configure_firewall_http
    
    # Create default index.php
    create_default_index "apache"
    
    # Remove default index.html to ensure our custom index.php loads
    rm -f "$web_root/index.html"
    
    print_success "Apache installed and started successfully"
    log "INFO" "Apache installation completed"
}

# Install Nginx web server
install_nginx() {
    print_info "Installing Nginx web server..."
    log "INFO" "Starting Nginx installation"
    
    local nginx_package="nginx"
    local service_name="nginx"
    
    install_package "$nginx_package" "Nginx Web Server"
    
    # Ensure DocumentRoot directory exists before starting Nginx
    local web_root="/usr/share/nginx/html"
    case "$PACKAGE_MANAGER" in
        apt)
            web_root="/var/www/html"
            ;;
        zypper)
            web_root="/srv/www/htdocs"
            ;;
        pacman)
            web_root="/usr/share/nginx/html"
            ;;
    esac
    mkdir -p "$web_root"
    
    # Start and enable Nginx
    systemctl start "$service_name"
    if systemctl enable "$service_name" >/dev/null 2>&1; then
        print_success "$service_name service enabled for startup"
    else
        print_warning "Failed to enable $service_name service for startup"
    fi
    INSTALLED_SERVICES+=("$service_name")
    
    # Configure firewall
    configure_firewall_http
    
    # Create default index.php
    create_default_index "nginx"
    
    print_success "Nginx installed and started successfully"
    log "INFO" "Nginx installation completed"
}

# Install MySQL
install_mysql() {
    print_info "Installing MySQL server..."
    log "INFO" "Starting MySQL installation"
    
    # Clean up any previous installation remnants
    print_info "Cleaning up any previous MySQL installation..."
    systemctl stop mysqld 2>/dev/null || true
    systemctl stop mysql 2>/dev/null || true
    systemctl stop mariadb 2>/dev/null || true
    
    # Remove any existing data directories that might cause conflicts
    if [[ -d "/var/lib/mysql" && ! -f "/var/lib/mysql/mysql/user.frm" ]]; then
        # Only remove if it's empty or corrupted (no user table)
        rm -rf /var/lib/mysql 2>/dev/null || true
        log "INFO" "Removed existing empty/corrupted MySQL data directory"
    fi
    
    local mysql_packages=()
    local service_name="mysqld"
    
    case "$PACKAGE_MANAGER" in
        dnf|yum)
            mysql_packages=("mysql-server")
            ;;
        apt)
            mysql_packages=("mysql-server")
            service_name="mysql"
            # Set non-interactive installation
            export DEBIAN_FRONTEND=noninteractive
            ;;
        zypper)
            mysql_packages=("mysql" "mysql-server")
            service_name="mysql"
            ;;
        pacman)
            mysql_packages=("mysql")
            service_name="mysqld"
            ;;
    esac
    
    # Install MySQL packages individually
    for package in "${mysql_packages[@]}"; do
        install_package "$package" "MySQL package: $package"
    done
    
    # Initialize MySQL (for RHEL-based systems)
    if [[ "$PACKAGE_MANAGER" == "dnf" || "$PACKAGE_MANAGER" == "yum" ]]; then
        if [[ ! -d "/var/lib/mysql/mysql" ]] || [[ -f "/var/lib/mysql/ibdata1" ]]; then
            print_info "Initializing MySQL database..."
            log "INFO" "Cleaning and initializing MySQL data directory"
            
            # Stop MySQL if running
            systemctl stop "$service_name" 2>/dev/null || true
            
            # Clean existing data directory to prevent corruption
            rm -rf /var/lib/mysql/*
            
            # Initialize with proper ownership
            mysqld --initialize-insecure --user=mysql --datadir=/var/lib/mysql
            chown -R mysql:mysql /var/lib/mysql
            
            log "INFO" "MySQL database initialized successfully"
        fi
    fi
    
    # Start and enable MySQL
    if ! systemctl start "$service_name"; then
        print_error "Failed to start MySQL service"
        log "ERROR" "MySQL service startup failed"
        return 1
    fi
    systemctl enable "$service_name"
    INSTALLED_SERVICES+=("$service_name")
    
    # Secure MySQL installation
    secure_mysql_installation
    
    print_success "MySQL installed and configured successfully"
    log "INFO" "MySQL installation completed"
}

# Secure MySQL installation
secure_mysql_installation() {
    print_info "Securing MySQL installation..."
    log "INFO" "Starting MySQL secure installation"
    
    # Generate cryptographically secure random password
    local mysql_root_password=$(secure_random_password)
    
    # Wait for MySQL to be fully ready
    sleep 2
    
    # Use OS-specific authentication method for MySQL security
    local secured=false
    
    case "$PACKAGE_MANAGER" in
        dnf|yum)
            # RHEL-based systems (AlmaLinux, Rocky, CentOS, RHEL)
            print_info "Using RHEL-based MySQL security method..."
            if mysql -u root <<EOF >/dev/null 2>&1
ALTER USER 'root'@'localhost' IDENTIFIED BY '$mysql_root_password';
DELETE FROM mysql.user WHERE User='';
DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1');
DROP DATABASE IF EXISTS test;
DELETE FROM mysql.db WHERE Db='test' OR Db='test\\_%';
FLUSH PRIVILEGES;
EOF
            then
                secured=true
                log "INFO" "MySQL secured using RHEL passwordless method"
            else
                log "WARNING" "RHEL passwordless method failed, trying sudo method"
                # Fallback to sudo method
                if sudo mysql -u root <<EOF >/dev/null 2>&1
ALTER USER 'root'@'localhost' IDENTIFIED BY '$mysql_root_password';
DELETE FROM mysql.user WHERE User='';
DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1');
DROP DATABASE IF EXISTS test;
DELETE FROM mysql.db WHERE Db='test' OR Db='test\\_%';
FLUSH PRIVILEGES;
EOF
                then
                    secured=true
                    log "INFO" "MySQL secured using RHEL sudo method"
                fi
            fi
            ;;
        apt)
            # Debian/Ubuntu systems
            print_info "Using Debian/Ubuntu MySQL security method..."
            if sudo mysql -u root <<EOF >/dev/null 2>&1
ALTER USER 'root'@'localhost' IDENTIFIED BY '$mysql_root_password';
DELETE FROM mysql.user WHERE User='';
DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1');
DROP DATABASE IF EXISTS test;
DELETE FROM mysql.db WHERE Db='test' OR Db='test\\_%';
FLUSH PRIVILEGES;
EOF
            then
                secured=true
                log "INFO" "MySQL secured using Debian/Ubuntu sudo method"
            else
                log "WARNING" "Debian/Ubuntu sudo method failed, trying passwordless method"
                # Fallback to passwordless method
                if mysql -u root <<EOF >/dev/null 2>&1
ALTER USER 'root'@'localhost' IDENTIFIED BY '$mysql_root_password';
DELETE FROM mysql.user WHERE User='';
DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1');
DROP DATABASE IF EXISTS test;
DELETE FROM mysql.db WHERE Db='test' OR Db='test\\_%';
FLUSH PRIVILEGES;
EOF
                then
                    secured=true
                    log "INFO" "MySQL secured using Debian/Ubuntu passwordless method"
                fi
            fi
            ;;
        zypper)
            # openSUSE systems
            print_info "Using openSUSE MySQL security method..."
            if mysql -u root <<EOF >/dev/null 2>&1
ALTER USER 'root'@'localhost' IDENTIFIED BY '$mysql_root_password';
DELETE FROM mysql.user WHERE User='';
DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1');
DROP DATABASE IF EXISTS test;
DELETE FROM mysql.db WHERE Db='test' OR Db='test\\_%';
FLUSH PRIVILEGES;
EOF
            then
                secured=true
                log "INFO" "MySQL secured using openSUSE passwordless method"
            fi
            ;;
        pacman)
            # Arch Linux systems
            print_info "Using Arch Linux MySQL security method..."
            if mysql -u root <<EOF >/dev/null 2>&1
ALTER USER 'root'@'localhost' IDENTIFIED BY '$mysql_root_password';
DELETE FROM mysql.user WHERE User='';
DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1');
DROP DATABASE IF EXISTS test;
DELETE FROM mysql.db WHERE Db='test' OR Db='test\\_%';
FLUSH PRIVILEGES;
EOF
            then
                secured=true
                log "INFO" "MySQL secured using Arch Linux passwordless method"
            fi
            ;;
        *)
            print_warning "Unknown package manager: $PACKAGE_MANAGER"
            log "WARNING" "Unknown package manager for MySQL security: $PACKAGE_MANAGER"
            ;;
    esac
    
    if [[ "$secured" != "true" ]]; then
        print_error "Failed to secure MySQL installation"
        log "ERROR" "MySQL security setup failed - all authentication methods failed"
        
        # Additional debugging information
        print_info "Checking MySQL service status for debugging..."
        systemctl status mysqld --no-pager -l 2>/dev/null || systemctl status mysql --no-pager -l 2>/dev/null || true
        
        # Check if MySQL is actually running
        if systemctl is-active mysqld >/dev/null 2>&1 || systemctl is-active mysql >/dev/null 2>&1; then
            print_info "MySQL service is running, but authentication failed"
            log "ERROR" "MySQL service active but authentication methods failed"
        else
            print_error "MySQL service is not running properly"
            log "ERROR" "MySQL service not active - installation may have failed"
        fi
        
        return 1
    fi
    
    # Save credentials using secure file creation
    local credentials="[client]
user=root
password=$mysql_root_password"
    
    create_secure_file "/root/.my.cnf" "$credentials" "600"
    
    print_success "MySQL secured with root password"
    print_info "MySQL root password saved to /root/.my.cnf"
    log "INFO" "MySQL secured and credentials saved (password not logged for security)"
    
    # Track successful installation
    INSTALLED_DATABASES+=("mysql")
}

# Install MariaDB
install_mariadb() {
    print_info "Installing MariaDB server..."
    log "INFO" "Starting MariaDB installation"
    
    # Clean up any previous installation remnants
    print_info "Cleaning up any previous MariaDB installation..."
    systemctl stop mariadb 2>/dev/null || true
    systemctl stop mysql 2>/dev/null || true
    systemctl stop mysqld 2>/dev/null || true
    
    # Remove any existing data directories that might cause conflicts
    if [[ -d "/var/lib/mysql" && ! -f "/var/lib/mysql/mysql/user.frm" ]]; then
        # Only remove if it's empty or corrupted (no user table)
        rm -rf /var/lib/mysql 2>/dev/null || true
        log "INFO" "Removed existing empty/corrupted MySQL data directory"
    fi
    
    local mariadb_packages=()
    local service_name="mariadb"
    
    case "$PACKAGE_MANAGER" in
        dnf|yum)
            mariadb_packages=("mariadb-server" "mariadb")
            ;;
        apt)
            mariadb_packages=("mariadb-server" "mariadb-client")
            ;;
        zypper)
            mariadb_packages=("mariadb" "mariadb-server")
            ;;
        pacman)
            mariadb_packages=("mariadb")
            ;;
    esac
    
    # Install MariaDB packages individually
    for package in "${mariadb_packages[@]}"; do
        install_package "$package" "MariaDB package: $package"
    done
    
    # Initialize MariaDB if needed
    if [[ ! -d "/var/lib/mysql/mysql" ]]; then
        print_info "Initializing MariaDB database..."
        case "$PACKAGE_MANAGER" in
            dnf|yum)
                mysql_install_db --user=mysql --datadir=/var/lib/mysql >/dev/null
                ;;
            apt)
                # Debian/Ubuntu: MariaDB usually auto-initializes, but ensure it's done
                mysqld --initialize-insecure --user=mysql --datadir=/var/lib/mysql >/dev/null 2>&1 || true
                ;;
            zypper)
                mysql_install_db --user=mysql --datadir=/var/lib/mysql >/dev/null
                ;;
            pacman)
                mariadb-install-db --user=mysql --basedir=/usr --datadir=/var/lib/mysql >/dev/null
                ;;
        esac
        log "INFO" "MariaDB database initialized"
    fi
    
    # Start and enable MariaDB
    systemctl start "$service_name"
    if systemctl enable "$service_name" >/dev/null 2>&1; then
        print_success "$service_name service enabled for startup"
    else
        print_warning "Failed to enable $service_name service for startup"
    fi
    INSTALLED_SERVICES+=("$service_name")
    
    # Secure MariaDB installation
    secure_mariadb_installation
    
    print_success "MariaDB installed and configured successfully"
    log "INFO" "MariaDB installation completed"
}

# Secure MariaDB installation
secure_mariadb_installation() {
    print_info "Securing MariaDB installation..."
    log "INFO" "Starting MariaDB secure installation"
    
    # Generate cryptographically secure random password
    local mariadb_root_password=$(secure_random_password)
    
    # Wait for MariaDB to be fully ready
    sleep 2
    
    # Use OS-specific authentication method for MariaDB security
    local secured=false
    
    case "$PACKAGE_MANAGER" in
        dnf|yum)
            # RHEL-based systems (AlmaLinux, Rocky, CentOS, RHEL)
            # Typically use passwordless root authentication initially
            print_info "Using RHEL-based MariaDB security method..."
            if mysql -u root <<EOF >/dev/null 2>&1
ALTER USER 'root'@'localhost' IDENTIFIED BY '$mariadb_root_password';
DELETE FROM mysql.user WHERE User='';
DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1');
DROP DATABASE IF EXISTS test;
DELETE FROM mysql.db WHERE Db='test' OR Db='test\\_%';
FLUSH PRIVILEGES;
EOF
            then
                secured=true
                log "INFO" "MariaDB secured using RHEL passwordless method"
            else
                log "WARNING" "RHEL passwordless method failed, trying sudo method"
                # Fallback to sudo method
                if sudo mysql -u root <<EOF >/dev/null 2>&1
ALTER USER 'root'@'localhost' IDENTIFIED BY '$mariadb_root_password';
DELETE FROM mysql.user WHERE User='';
DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1');
DROP DATABASE IF EXISTS test;
DELETE FROM mysql.db WHERE Db='test' OR Db='test\\_%';
FLUSH PRIVILEGES;
EOF
                then
                    secured=true
                    log "INFO" "MariaDB secured using RHEL sudo method"
                fi
            fi
            ;;
        apt)
            # Debian/Ubuntu systems typically use unix_socket authentication
            print_info "Using Debian/Ubuntu MariaDB security method..."
            if sudo mysql -u root <<EOF >/dev/null 2>&1
ALTER USER 'root'@'localhost' IDENTIFIED BY '$mariadb_root_password';
DELETE FROM mysql.user WHERE User='';
DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1');
DROP DATABASE IF EXISTS test;
DELETE FROM mysql.db WHERE Db='test' OR Db='test\\_%';
FLUSH PRIVILEGES;
EOF
            then
                secured=true
                log "INFO" "MariaDB secured using Debian/Ubuntu sudo method"
            else
                log "WARNING" "Debian/Ubuntu sudo method failed, trying passwordless method"
                # Fallback to passwordless method
                if mysql -u root <<EOF >/dev/null 2>&1
ALTER USER 'root'@'localhost' IDENTIFIED BY '$mariadb_root_password';
DELETE FROM mysql.user WHERE User='';
DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1');
DROP DATABASE IF EXISTS test;
DELETE FROM mysql.db WHERE Db='test' OR Db='test\\_%';
FLUSH PRIVILEGES;
EOF
                then
                    secured=true
                    log "INFO" "MariaDB secured using Debian/Ubuntu passwordless method"
                fi
            fi
            ;;
        zypper)
            # openSUSE systems
            print_info "Using openSUSE MariaDB security method..."
            if mysql -u root <<EOF >/dev/null 2>&1
ALTER USER 'root'@'localhost' IDENTIFIED BY '$mariadb_root_password';
DELETE FROM mysql.user WHERE User='';
DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1');
DROP DATABASE IF EXISTS test;
DELETE FROM mysql.db WHERE Db='test' OR Db='test\\_%';
FLUSH PRIVILEGES;
EOF
            then
                secured=true
                log "INFO" "MariaDB secured using openSUSE passwordless method"
            fi
            ;;
        pacman)
            # Arch Linux systems
            print_info "Using Arch Linux MariaDB security method..."
            if mysql -u root <<EOF >/dev/null 2>&1
ALTER USER 'root'@'localhost' IDENTIFIED BY '$mariadb_root_password';
DELETE FROM mysql.user WHERE User='';
DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1');
DROP DATABASE IF EXISTS test;
DELETE FROM mysql.db WHERE Db='test' OR Db='test\\_%';
FLUSH PRIVILEGES;
EOF
            then
                secured=true
                log "INFO" "MariaDB secured using Arch Linux passwordless method"
            fi
            ;;
        *)
            print_warning "Unknown package manager: $PACKAGE_MANAGER"
            log "WARNING" "Unknown package manager for MariaDB security: $PACKAGE_MANAGER"
            ;;
    esac
    
    if [[ "$secured" != "true" ]]; then
        print_error "Failed to secure MariaDB installation"
        log "ERROR" "MariaDB security setup failed - all authentication methods failed"
        
        # Additional debugging information
        print_info "Checking MariaDB service status for debugging..."
        systemctl status mariadb --no-pager -l 2>/dev/null || true
        
        # Check if MariaDB is actually running
        if systemctl is-active mariadb >/dev/null 2>&1; then
            print_info "MariaDB service is running, but authentication failed"
            log "ERROR" "MariaDB service active but authentication methods failed"
        else
            print_error "MariaDB service is not running properly"
            log "ERROR" "MariaDB service not active - installation may have failed"
        fi
        
        return 1
    fi
    
    # Save credentials using secure file creation
    local credentials="[client]
user=root
password=$mariadb_root_password"
    
    create_secure_file "/root/.my.cnf" "$credentials" "600"
    
    print_success "MariaDB secured with root password"
    print_info "MariaDB root password saved to /root/.my.cnf"
    log "INFO" "MariaDB secured and credentials saved (password not logged for security)"
    
    # Track successful installation
    INSTALLED_DATABASES+=("mariadb")
}

# Install PostgreSQL
install_postgresql() {
    print_info "Installing PostgreSQL server..."
    log "INFO" "Starting PostgreSQL installation"
    
    # Clean up any previous installation remnants
    print_info "Cleaning up any previous PostgreSQL installation..."
    systemctl stop postgresql 2>/dev/null || true
    systemctl stop postgresql-16 2>/dev/null || true
    systemctl stop postgresql-15 2>/dev/null || true
    systemctl stop postgresql-14 2>/dev/null || true
    systemctl stop postgresql-13 2>/dev/null || true
    
    # Remove any existing data directories that might cause conflicts
    if [[ -d "/var/lib/pgsql" && ! -f "/var/lib/pgsql/data/PG_VERSION" ]]; then
        # Only remove if it's empty or corrupted (no PG_VERSION file)
        rm -rf /var/lib/pgsql 2>/dev/null || true
        log "INFO" "Removed existing empty/corrupted PostgreSQL data directory"
    fi
    if [[ -d "/var/lib/postgresql" && ! -f "/var/lib/postgresql/*/main/PG_VERSION" ]]; then
        # Only remove if it's empty or corrupted (no PG_VERSION file)
        rm -rf /var/lib/postgresql 2>/dev/null || true
        log "INFO" "Removed existing empty/corrupted PostgreSQL data directory"
    fi
    
    local postgresql_packages=()
    local service_name="postgresql"
    local postgres_version=""
    
    case "$PACKAGE_MANAGER" in
        dnf|yum)
            postgresql_packages=("postgresql-server" "postgresql-contrib")
            service_name="postgresql"
            ;;
        apt)
            postgresql_packages=("postgresql" "postgresql-contrib")
            service_name="postgresql"
            ;;
        zypper)
            postgresql_packages=("postgresql-server" "postgresql-contrib")
            service_name="postgresql"
            ;;
        pacman)
            postgresql_packages=("postgresql")
            service_name="postgresql"
            ;;
    esac
    
    # Install PostgreSQL packages
    for package in "${postgresql_packages[@]}"; do
        install_package "$package" "PostgreSQL package: $package"
    done
    
    # Initialize PostgreSQL database (for RHEL-based systems)
    if [[ "$PACKAGE_MANAGER" == "dnf" || "$PACKAGE_MANAGER" == "yum" ]]; then
        if [[ ! -d "/var/lib/pgsql/data/base" ]]; then
            print_info "Initializing PostgreSQL database..."
            postgresql-setup --initdb
            log "INFO" "PostgreSQL database initialized"
        fi
    fi
    
    # Initialize PostgreSQL database (for Arch)
    if [[ "$PACKAGE_MANAGER" == "pacman" ]]; then
        if [[ ! -d "/var/lib/postgres/data/base" ]]; then
            print_info "Initializing PostgreSQL database..."
            sudo -u postgres initdb -D /var/lib/postgres/data
            log "INFO" "PostgreSQL database initialized"
        fi
    fi
    
    # Start and enable PostgreSQL
    systemctl start "$service_name"
    if systemctl enable "$service_name" >/dev/null 2>&1; then
        print_success "$service_name service enabled for startup"
    else
        print_warning "Failed to enable $service_name service for startup"
    fi
    INSTALLED_SERVICES+=("$service_name")
    
    # Create a development database and user
    setup_postgresql_dev_user
    
    print_success "PostgreSQL installed and configured successfully"
    log "INFO" "PostgreSQL installation completed"
}

# Setup PostgreSQL development user
setup_postgresql_dev_user() {
    print_info "Setting up PostgreSQL development user..."
    log "INFO" "Creating PostgreSQL development user"
    
    # Generate random password for dev user
    local dev_password=$(openssl rand -base64 12)
    
    # Configure PostgreSQL for password authentication
    local pg_hba_conf=""
    local postgresql_conf=""
    
    # Find PostgreSQL configuration files based on distribution
    if [[ "$PACKAGE_MANAGER" == "dnf" || "$PACKAGE_MANAGER" == "yum" ]]; then
        pg_hba_conf="/var/lib/pgsql/data/pg_hba.conf"
        postgresql_conf="/var/lib/pgsql/data/postgresql.conf"
    elif [[ "$PACKAGE_MANAGER" == "apt" ]]; then
        # Ubuntu/Debian - find the version directory
        local pg_version=$(ls /etc/postgresql/ | head -n1)
        pg_hba_conf="/etc/postgresql/$pg_version/main/pg_hba.conf"
        postgresql_conf="/etc/postgresql/$pg_version/main/postgresql.conf"
    elif [[ "$PACKAGE_MANAGER" == "zypper" ]]; then
        pg_hba_conf="/var/lib/pgsql/data/pg_hba.conf"
        postgresql_conf="/var/lib/pgsql/data/postgresql.conf"
    elif [[ "$PACKAGE_MANAGER" == "pacman" ]]; then
        pg_hba_conf="/var/lib/postgres/data/pg_hba.conf"
        postgresql_conf="/var/lib/postgres/data/postgresql.conf"
    fi
    
    # Backup original pg_hba.conf
    if [[ -f "$pg_hba_conf" ]]; then
        cp "$pg_hba_conf" "$pg_hba_conf.backup"
        
        # Configure authentication for local connections
        print_info "Configuring PostgreSQL authentication..."
        
        # Add md5 authentication for webdev user
        sed -i '/^local.*all.*all.*peer/i local   webdev_db    webdev                                  md5' "$pg_hba_conf"
        sed -i '/^host.*all.*all.*127.0.0.1\/32.*ident/i host    webdev_db    webdev      127.0.0.1/32            md5' "$pg_hba_conf"
        
        # Restart PostgreSQL to apply authentication changes
        systemctl restart postgresql
        sleep 2
    fi
    
    # Wait for PostgreSQL to be fully ready
    sleep 3
    
    # Create development user and database with error handling
    local pg_setup_success=false
    
    case "$PACKAGE_MANAGER" in
        dnf|yum|zypper)
            # RHEL-based and openSUSE systems
            print_info "Using RHEL/openSUSE PostgreSQL setup method..."
            if sudo -u postgres psql <<EOF >/dev/null 2>&1
CREATE USER webdev WITH ENCRYPTED PASSWORD '$dev_password';
CREATE DATABASE webdev_db OWNER webdev;
GRANT ALL PRIVILEGES ON DATABASE webdev_db TO webdev;
\q
EOF
            then
                pg_setup_success=true
                log "INFO" "PostgreSQL user created using RHEL/openSUSE method"
            else
                log "WARNING" "RHEL/openSUSE PostgreSQL setup failed"
            fi
            ;;
        apt)
            # Debian/Ubuntu systems
            print_info "Using Debian/Ubuntu PostgreSQL setup method..."
            if sudo -u postgres psql <<EOF >/dev/null 2>&1
CREATE USER webdev WITH ENCRYPTED PASSWORD '$dev_password';
CREATE DATABASE webdev_db OWNER webdev;
GRANT ALL PRIVILEGES ON DATABASE webdev_db TO webdev;
\q
EOF
            then
                pg_setup_success=true
                log "INFO" "PostgreSQL user created using Debian/Ubuntu method"
            else
                log "WARNING" "Debian/Ubuntu PostgreSQL setup failed"
            fi
            ;;
        pacman)
            # Arch Linux systems
            print_info "Using Arch Linux PostgreSQL setup method..."
            if sudo -u postgres psql <<EOF >/dev/null 2>&1
CREATE USER webdev WITH ENCRYPTED PASSWORD '$dev_password';
CREATE DATABASE webdev_db OWNER webdev;
GRANT ALL PRIVILEGES ON DATABASE webdev_db TO webdev;
\q
EOF
            then
                pg_setup_success=true
                log "INFO" "PostgreSQL user created using Arch Linux method"
            else
                log "WARNING" "Arch Linux PostgreSQL setup failed"
            fi
            ;;
        *)
            print_warning "Unknown package manager: $PACKAGE_MANAGER"
            log "WARNING" "Unknown package manager for PostgreSQL setup: $PACKAGE_MANAGER"
            ;;
    esac
    
    if [[ "$pg_setup_success" != "true" ]]; then
        print_error "Failed to create PostgreSQL development user"
        log "ERROR" "PostgreSQL development user creation failed"
        
        # Additional debugging information
        print_info "Checking PostgreSQL service status for debugging..."
        systemctl status postgresql --no-pager -l 2>/dev/null || true
        
        # Check if PostgreSQL is actually running
        if systemctl is-active postgresql >/dev/null 2>&1; then
            print_info "PostgreSQL service is running, but user creation failed"
            log "ERROR" "PostgreSQL service active but user creation failed"
        else
            print_error "PostgreSQL service is not running properly"
            log "ERROR" "PostgreSQL service not active - installation may have failed"
        fi
        
        return 1
    fi
    
    # Save credentials for easy access
    cat > /root/postgresql-info.txt <<EOF
PostgreSQL Development Credentials:
Database: webdev_db
Username: webdev
Password: $dev_password

Connection Methods:
1. Interactive (prompts for password):
   psql -h 127.0.0.1 -U webdev -d webdev_db
   
2. With password environment variable:
   PGPASSWORD='$dev_password' psql -h 127.0.0.1 -U webdev -d webdev_db

When prompted, enter password: $dev_password

Documentation:
Official PostgreSQL Documentation: https://www.postgresql.org/docs/
EOF
    
    chmod 600 /root/postgresql-info.txt
    
    print_success "PostgreSQL development user created"
    print_info "Development credentials saved to /root/postgresql-info.txt"
    log "INFO" "PostgreSQL development user configured"
    
    # Track successful installation
    INSTALLED_DATABASES+=("postgresql")
}

# Install SQLite
install_sqlite() {
    print_info "Installing SQLite..."
    log "INFO" "Starting SQLite installation"
    
    local sqlite_packages=()
    
    case "$PACKAGE_MANAGER" in
        dnf|yum)
            sqlite_packages=("sqlite")
            ;;
        apt)
            sqlite_packages=("sqlite3")
            ;;
        zypper)
            sqlite_packages=("sqlite3")
            ;;
        pacman)
            sqlite_packages=("sqlite")
            ;;
    esac
    
    # Install SQLite packages
    for package in "${sqlite_packages[@]}"; do
        install_package "$package" "SQLite package: $package"
    done
    
    # Create a sample database for testing
    setup_sqlite_sample
    
    print_success "SQLite installed successfully"
    log "INFO" "SQLite installation completed"
}

# Setup SQLite sample database
setup_sqlite_sample() {
    print_info "Creating SQLite sample database..."
    log "INFO" "Setting up SQLite sample database"
    
    # Create sample database in /var/lib/sqlite
    mkdir -p /var/lib/sqlite
    
    # Determine the correct sqlite command
    local sqlite_cmd=""
    case "$PACKAGE_MANAGER" in
        dnf|yum|pacman)
            sqlite_cmd="sqlite3"
            ;;
        apt|zypper)
            sqlite_cmd="sqlite3"
            ;;
    esac
    
    # Create sample database with basic table
    $sqlite_cmd /var/lib/sqlite/sample.db <<EOF
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO users (name, email) VALUES 
('Test User', 'test@example.com'),
('Sample User', 'sample@example.com');

.quit
EOF
    
    # Set proper permissions
    chown -R root:root /var/lib/sqlite
    chmod 755 /var/lib/sqlite
    chmod 644 /var/lib/sqlite/sample.db
    
    # Create info file
    cat > /root/sqlite-info.txt <<EOF
SQLite Installation Information:
Command: $sqlite_cmd
Sample Database: /var/lib/sqlite/sample.db
Usage: $sqlite_cmd /var/lib/sqlite/sample.db
Test Query: SELECT * FROM users;
EOF
    
    chmod 600 /root/sqlite-info.txt
    
    print_success "SQLite sample database created"
    print_info "SQLite information saved to /root/sqlite-info.txt"
    log "INFO" "SQLite sample database configured"
    
    # Track successful installation
    INSTALLED_DATABASES+=("sqlite")
}

# Install PHP versions
install_php() {
    # Check if PHP installation was skipped
    if [[ "${SELECTED_PHP_VERSIONS[0]}" == "none" ]]; then
        print_info "Skipping PHP installation as requested"
        log "INFO" "PHP installation skipped by user choice"
        return 0
    fi
    
    print_info "Installing PHP versions: ${SELECTED_PHP_VERSIONS[*]}"
    log "INFO" "Starting PHP installation for versions: ${SELECTED_PHP_VERSIONS[*]}"
    
    for version in "${SELECTED_PHP_VERSIONS[@]}"; do
        install_php_version "$version"
    done
    
    # Set default PHP version (already selected during initial setup)
    if [[ -n "$DEFAULT_PHP_VERSION" ]]; then
        set_default_php_version "$DEFAULT_PHP_VERSION"
    else
        # Fallback to first version if somehow not set
        local default_version="${SELECTED_PHP_VERSIONS[0]}"
        set_default_php_version "$default_version"
    fi
    
    print_success "All PHP versions installed successfully"
    log "INFO" "PHP installation completed"
}

# Install specific PHP version
install_php_version() {
    local version="$1"
    print_info "Installing PHP $version..."
    log "INFO" "Installing PHP version $version"
    
    local php_packages=()
    local version_nodot="${version//./}"
    
    case "$PACKAGE_MANAGER" in
        dnf|yum)
            # For multiple PHP versions on RHEL, we need to use SCL packages
            # Check if this is the first PHP version being installed
            if [[ ${#SELECTED_PHP_VERSIONS[@]} -gt 1 ]]; then
                # Multiple PHP versions: use SCL packages
                local version_nodot="${version//./}"
                php_packages=(
                    "php$version_nodot"
                    "php$version_nodot-php-cli"
                    "php$version_nodot-php-fpm"
                    "php$version_nodot-php-common"
                    "php$version_nodot-php-mysqlnd"
                    "php$version_nodot-php-xml"
                    "php$version_nodot-php-curl"
                    "php$version_nodot-php-mbstring"
                    "php$version_nodot-php-zip"
                    "php$version_nodot-php-gd"
                    "php$version_nodot-php-intl"
                    "php$version_nodot-php-opcache"
                )
            else
                # Single PHP version: use module stream
                $PACKAGE_MANAGER module reset php -y >/dev/null 2>&1 || true
                $PACKAGE_MANAGER module enable php:remi-$version -y >/dev/null 2>&1 || true
                
                php_packages=(
                    "php"
                    "php-cli"
                    "php-fpm"
                    "php-common"
                    "php-mysql"
                    "php-xml"
                    "php-json"
                    "php-curl"
                    "php-mbstring"
                    "php-zip"
                    "php-gd"
                    "php-intl"
                    "php-opcache"
                )
            fi
            ;;
        apt)
            php_packages=(
                "php$version"
                "php$version-cli"
                "php$version-fpm"
                "php$version-common"
                "php$version-mysql"
                "php$version-xml"
                "php$version-curl"
                "php$version-mbstring"
                "php$version-zip"
                "php$version-gd"
                "php$version-intl"
                "php$version-opcache"
            )
            ;;
        zypper)
            php_packages=(
                "php$version_nodot"
                "php$version_nodot-cli"
                "php$version_nodot-fpm"
                "php$version_nodot-mysql"
                "php$version_nodot-xml"
                "php$version_nodot-curl"
                "php$version_nodot-mbstring"
                "php$version_nodot-zip"
                "php$version_nodot-gd"
                "php$version_nodot-intl"
                "php$version_nodot-opcache"
            )
            ;;
        pacman)
            php_packages=(
                "php"
                "php-fpm"
            )
            ;;
    esac
    
    # Install PHP packages
    for package in "${php_packages[@]}"; do
        install_package "$package" "PHP $version package: $package"
    done
    
    print_info "PHP $version packages installed, configuring services..."
    
    # Configure PHP-FPM
    configure_php_fpm "$version"
    
    print_success "PHP $version installed successfully"
    log "INFO" "PHP $version installation completed"
}

# Configure PHP-FPM
configure_php_fpm() {
    local version="$1"
    print_info "Configuring PHP-FPM for version $version..."
    log "INFO" "Configuring PHP-FPM for PHP $version"
    
    local fpm_service=""
    local fpm_config=""
    
    case "$PACKAGE_MANAGER" in
        dnf|yum)
            # Handle multiple PHP versions on RHEL
            if [[ ${#SELECTED_PHP_VERSIONS[@]} -gt 1 ]]; then
                local version_nodot="${version//./}"
                fpm_service="php$version_nodot-php-fpm"
                fpm_config="/etc/opt/remi/php$version_nodot/php-fpm.d/www.conf"
            else
                fpm_service="php-fpm"
                fpm_config="/etc/php-fpm.d/www.conf"
            fi
            ;;
        apt)
            fpm_service="php$version-fpm"
            fpm_config="/etc/php/$version/fpm/pool.d/www.conf"
            ;;
        zypper)
            local version_nodot="${version//./}"
            fpm_service="php-fpm$version_nodot"
            fpm_config="/etc/php$version_nodot/fpm/php-fpm.d/www.conf"
            ;;
        pacman)
            fpm_service="php-fpm"
            fpm_config="/etc/php/php-fpm.d/www.conf"
            ;;
    esac
    
    # Start and enable PHP-FPM
    if systemctl list-unit-files | grep -q "$fpm_service"; then
        systemctl start "$fpm_service"
        systemctl enable "$fpm_service"
        INSTALLED_SERVICES+=("$fpm_service")
        print_success "PHP-FPM service started and enabled"
    fi
    
    log "INFO" "PHP-FPM configuration completed for PHP $version"
}


# Set default PHP version
set_default_php_version() {
    local version="$1"
    print_info "Setting PHP $version as default..."
    log "INFO" "Setting PHP $version as default version"
    
    case "$PACKAGE_MANAGER" in
        dnf|yum)
            # For multiple PHP versions on RHEL, create symlinks
            if [[ ${#SELECTED_PHP_VERSIONS[@]} -gt 1 ]]; then
                local version_nodot="${version//./}"
                ln -sf "/opt/remi/php$version_nodot/root/usr/bin/php" "/usr/local/bin/php" 2>/dev/null || true
                print_success "PHP $version set as default (via symlink)"
            else
                print_info "PHP $version is the default (single version installed)"
            fi
            ;;
        apt)
            if command -v update-alternatives >/dev/null 2>&1; then
                update-alternatives --set php "/usr/bin/php$version"
                print_success "PHP $version set as default"
            fi
            ;;
    esac
    
    log "INFO" "Default PHP version set to $version"
}

# Configure Apache for PHP
configure_apache_php() {
    print_info "Configuring Apache for PHP..."
    log "INFO" "Configuring Apache for PHP integration"
    
    # Use the DEFAULT_PHP_VERSION instead of first selected version
    local default_version="$DEFAULT_PHP_VERSION"
    if [[ -z "$default_version" ]]; then
        default_version="${SELECTED_PHP_VERSIONS[0]}"
    fi
    
    case "$PACKAGE_MANAGER" in
        dnf|yum)
            # Install mod_php for the default PHP version on RHEL
            local version_nodot="${default_version//./}"
            install_package "php$version_nodot-php" "PHP $default_version Apache module"
            
            # Restart Apache to load PHP module
            systemctl restart httpd
            ;;
        apt)
            # Enable PHP modules for Apache
            a2enmod "php$default_version"
            systemctl restart apache2
            ;;
        zypper)
            # Configure Apache for PHP
            local version_nodot="${default_version//./}"
            echo "LoadModule php${version_nodot}_module /usr/lib64/apache2/mod_php${version_nodot}.so" > /etc/apache2/conf.d/php${version_nodot}.conf
            systemctl restart apache2
            ;;
    esac
    
    print_success "Apache configured for PHP $default_version"
    log "INFO" "Apache-PHP integration configured for version $default_version"
}

# Configure Nginx for PHP
configure_nginx_php() {
    print_info "Configuring Nginx for PHP..."
    log "INFO" "Configuring Nginx for PHP integration"
    
    local nginx_config=""
    # Use the DEFAULT_PHP_VERSION instead of first selected version
    local default_version="$DEFAULT_PHP_VERSION"
    if [[ -z "$default_version" ]]; then
        default_version="${SELECTED_PHP_VERSIONS[0]}"
    fi
    local php_fpm_service=""
    
    # Determine PHP-FPM service name and configure for Unix socket by default
    case "$PACKAGE_MANAGER" in
        dnf|yum)
            nginx_config="/etc/nginx/conf.d/default.conf" 
            php_fpm_service="php-fpm"
            # Use Unix socket by default (secure, fast) with TCP fallback if needed
            ;;
        apt)
            nginx_config="/etc/nginx/sites-available/default"
            php_fpm_service="php${default_version}-fpm"
            # Ubuntu/Debian already uses Unix socket by default
            ;;
        zypper)
            nginx_config="/etc/nginx/conf.d/default.conf"
            local version_nodot="${default_version//./}"
            php_fpm_service="php-fmp${version_nodot}"
            ;;
        pacman)
            nginx_config="/etc/nginx/nginx.conf"
            php_fpm_service="php-fpm"
            ;;
    esac
    
    # Start and enable PHP-FPM service(s)
    case "$PACKAGE_MANAGER" in
        dnf|yum)
            # For RHEL systems with multiple PHP versions, start each version's FPM service
            if [[ ${#SELECTED_PHP_VERSIONS[@]} -gt 1 ]]; then
                for version in "${SELECTED_PHP_VERSIONS[@]}"; do
                    local version_nodot="${version//./}"
                    local version_service="php$version_nodot-php-fpm"
                    print_info "Starting PHP-FPM service: $version_service"
                    
                    if ! systemctl is-active --quiet "$version_service"; then
                        systemctl start "$version_service" || {
                            print_error "Failed to start PHP-FPM service: $version_service"
                            log "ERROR" "PHP-FPM service failed to start: $version_service"
                            return 1
                        }
                    fi
                    systemctl enable "$version_service" 2>/dev/null || true
                done
                
                # Configure PHP-FPM services to use Unix sockets
                print_info "Configuring PHP-FPM services for Unix socket connection..."
                
                # Create socket directory
                mkdir -p /run/php-fpm
                chown nginx:nginx /run/php-fpm 2>/dev/null || chown apache:apache /run/php-fpm 2>/dev/null || true
                chmod 755 /run/php-fpm
                
                # Ensure socket directory persists across reboots
                cat > /etc/tmpfiles.d/php-fpm-sockets.conf <<EOF
# PHP-FPM socket directory
d /run/php-fpm 0755 nginx nginx -
EOF
                
                for version in "${SELECTED_PHP_VERSIONS[@]}"; do
                    local version_nodot="${version//./}"
                    local version_service="php$version_nodot-php-fpm"
                    local fpm_config="/etc/opt/remi/php$version_nodot/php-fpm.d/www.conf"
                    local socket_path="/run/php-fpm/php$version_nodot.sock"
                    
                    if [[ -f "$fpm_config" ]]; then
                        # Configure for Unix socket
                        sed -i "s|^listen = .*|listen = $socket_path|" "$fpm_config"
                        sed -i "s|^;listen.owner = .*|listen.owner = nginx|" "$fpm_config"
                        sed -i "s|^;listen.group = .*|listen.group = nginx|" "$fpm_config"
                        sed -i "s|^;listen.mode = .*|listen.mode = 0660|" "$fpm_config"
                        sed -i 's|^listen.acl_users = .*|;listen.acl_users = apache|' "$fpm_config"
                        sed -i '/^listen.allowed_clients = /d' "$fpm_config"
                        print_info "Configured $version_service for Unix socket ($socket_path)"
                        log "INFO" "PHP-FPM $version configured for socket: $socket_path"
                        
                        # Restart service to apply socket configuration
                        systemctl restart "$version_service"
                        
                        # Verify socket was created
                        sleep 1
                        if [[ -S "$socket_path" ]]; then
                            log "SUCCESS" "PHP-FPM socket created: $socket_path"
                        else
                            log "WARNING" "PHP-FPM socket not immediately available: $socket_path"
                        fi
                    fi
                done
                
                # Use the first version's service for the subsequent config checks
                local version_nodot="${SELECTED_PHP_VERSIONS[0]//./}"
                php_fpm_service="php$version_nodot-php-fpm"
            else
                # Single PHP version
                print_info "Starting PHP-FPM service: $php_fpm_service"
                if ! systemctl is-active --quiet "$php_fpm_service"; then
                    systemctl start "$php_fpm_service" || {
                        print_error "Failed to start PHP-FPM service: $php_fpm_service"
                        log "ERROR" "PHP-FPM service failed to start"
                        return 1
                    }
                fi
                systemctl enable "$php_fpm_service" 2>/dev/null || true
            fi
            ;;
        *)
            # For other package managers, use the original single-service logic
            print_info "Starting PHP-FPM service: $php_fpm_service"
            if ! systemctl is-active --quiet "$php_fpm_service"; then
                systemctl start "$php_fpm_service" || {
                    print_error "Failed to start PHP-FPM service: $php_fpm_service"
                    log "ERROR" "PHP-FPM service failed to start"
                    return 1
                }
            fi
            systemctl enable "$php_fpm_service" 2>/dev/null || true
            ;;
    esac
    
    if systemctl is-active --quiet "$php_fpm_service"; then
        print_success "PHP-FPM service is running"
        log "INFO" "PHP-FPM service started successfully"
        
        # Check what PHP-FPM is listening on
        print_info "Checking PHP-FPM configuration..."
        if [[ "$PACKAGE_MANAGER" == "dnf" || "$PACKAGE_MANAGER" == "yum" ]]; then
            # For RHEL/CentOS, check the pool configuration
            local fpm_pool_config="/etc/php-fpm.d/www.conf"
            if [[ -f "$fpm_pool_config" ]]; then
                # Check if it's set to TCP or socket
                local listen_config=$(grep -E "^listen\s*=" "$fpm_pool_config" | head -1)
                print_info "PHP-FPM listen config: $listen_config"
                log "INFO" "PHP-FPM listen configuration: $listen_config"
                
                # Ensure socket directory exists and has correct permissions
                mkdir -p /run/php-fpm
                chown nginx:nginx /run/php-fpm
                chmod 755 /run/php-fpm
                
                # Restart PHP-FPM to create the socket
                if [[ -f "$fpm_pool_config" ]] && grep -q "^listen = /run/php-fpm/www.sock" "$fpm_pool_config"; then
                    print_info "Restarting PHP-FPM to create Unix socket..."
                    systemctl restart "$php_fpm_service"
                    sleep 2  # Wait for socket creation
                    
                    if [[ -S "/run/php-fpm/www.sock" ]]; then
                        print_success "PHP-FPM Unix socket created successfully"
                        log "INFO" "PHP-FPM Unix socket configuration verified"
                    else
                        print_error "Failed to create Unix socket, falling back to TCP"
                        sed -i 's/^listen = .*/listen = 127.0.0.1:9000/' "$fpm_pool_config"
                        systemctl restart "$php_fpm_service"
                        log "WARN" "Fallback to TCP configuration"
                    fi
                fi
            fi
        fi
    else
        print_error "PHP-FPM service failed to start"
        systemctl status "$php_fpm_service" --no-pager
        return 1
    fi
    
    # Backup original config if it exists
    if [[ -f "$nginx_config" ]]; then
        cp "$nginx_config" "$nginx_config.backup.$(date +%Y%m%d_%H%M%S)" 2>/dev/null || true
    fi
    
    # Create basic PHP-enabled Nginx configuration
    case "$PACKAGE_MANAGER" in
        dnf|yum)
            # Always use Unix socket for Nginx (better security and performance)
            local default_version_nodot="${DEFAULT_PHP_VERSION//./}"
            if [[ -z "$default_version_nodot" ]]; then
                default_version_nodot="${SELECTED_PHP_VERSIONS[0]//./}"
            fi
            local fastcgi_backend="unix:/run/php-fpm/php$default_version_nodot.sock"
            print_info "Using Unix socket for PHP-FPM: $fastcgi_backend"
            log "INFO" "Nginx configured for PHP-FPM socket: $fastcgi_backend"
            
            cat > "$nginx_config" <<EOF
server {
    listen       80 default_server;
    listen       [::]:80 default_server;
    server_name  _;
    root         /usr/share/nginx/html;
    index        index.php index.html index.htm;

    location / {
        try_files \$uri \$uri/ =404;
    }

    location ~ \.php$ {
        try_files \$uri =404;
        fastcgi_pass $fastcgi_backend;
        fastcgi_index index.php;
        fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
        include fastcgi_params;
    }

    location ~ /\.ht {
        deny all;
    }
}
EOF
            ;;
        apt)
            cat > "$nginx_config" <<EOF
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    
    root /var/www/html;
    index index.php index.html index.htm index.nginx-debian.html;
    
    server_name _;
    
    location / {
        try_files \$uri \$uri/ =404;
    }
    
    location ~ \.php$ {
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:/var/run/php/php${default_version}-fpm.sock;
    }
    
    location ~ /\.ht {
        deny all;
    }
}
EOF
            ;;
    esac
    
    # Test configuration and restart Nginx
    print_info "Testing Nginx configuration..."
    if nginx -t 2>/dev/null; then
        print_info "Restarting Nginx..."
        systemctl restart nginx
        
        # Wait a moment for services to fully start
        sleep 2
        
        # Test PHP-FPM connection
        print_info "Testing PHP-FPM connection..."
        case "$PACKAGE_MANAGER" in
            dnf|yum)
                if [[ -S "/run/php-fpm/www.sock" ]]; then
                    print_success "PHP-FPM Unix socket exists"
                else
                    print_warning "PHP-FPM Unix socket not found"
                    ls -la /run/php-fpm/ 2>/dev/null || true
                fi
                ;;
            apt)
                if [[ -S "/var/run/php/php${default_version}-fpm.sock" ]]; then
                    print_success "PHP-FPM socket exists"
                else
                    print_warning "PHP-FPM socket not found"
                    ls -la /var/run/php/ 2>/dev/null || true
                fi
                ;;
        esac
        
        print_success "Nginx configured for PHP $default_version"
        log "INFO" "Nginx-PHP integration configured for version $default_version"
    else
        print_error "Nginx configuration test failed"
        log "ERROR" "Nginx-PHP integration configuration failed"
        nginx -t
        return 1
    fi
}

# Create default index.php file
create_default_index() {
    local web_server="$1"
    local web_root=""
    
    # Determine web root based on server and OS
    case "$web_server" in
        apache)
            case "$PACKAGE_MANAGER" in
                dnf|yum)
                    web_root="/var/www/html"
                    ;;
                apt)
                    web_root="/var/www/html"
                    ;;
                zypper)
                    web_root="/srv/www/htdocs"
                    ;;
                pacman)
                    web_root="/srv/http"
                    ;;
            esac
            ;;
        nginx)
            case "$PACKAGE_MANAGER" in
                dnf|yum)
                    web_root="/usr/share/nginx/html"
                    ;;
                apt)
                    web_root="/var/www/html"
                    ;;
                zypper)
                    web_root="/srv/www/htdocs"
                    ;;
                pacman)
                    web_root="/usr/share/nginx/html"
                    ;;
            esac
            ;;
    esac
    
    # Ensure web root directory exists
    mkdir -p "$web_root"
    
    # Check if PHP is installed
    if [[ "${SELECTED_PHP_VERSIONS[0]}" != "none" ]]; then
        # Create index.php with PHP functionality
        print_info "Creating default index.php in $web_root..."
        log "INFO" "Creating default index.php for $web_server in $web_root"
        
        # Create index.php with Hello World and phpinfo
        cat > "$web_root/index.php" <<'EOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Web Development Environment Setup</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .header { background: #4CAF50; color: white; padding: 20px; border-radius: 5px; margin-bottom: 20px; }
        .success-box { background: #4CAF50; color: white; padding: 20px; border-radius: 5px; margin-bottom: 20px; }
        .phpinfo { margin-top: 30px; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🎉 Hello World!</h1>
        <p>Your web development environment is successfully installed and running!</p>
    </div>
    
    <div class="success-box">
        <h2>Installation Success</h2>
        <p>✅ Web server is running</p>
        <p>✅ PHP is working correctly</p>
        <p>✅ File permissions are set properly</p>
        <p><strong>PHP Version:</strong> <?php echo phpversion(); ?></p>
        <p><strong>Current Time:</strong> <?php echo date('Y-m-d H:i:s T'); ?></p>
    </div>
    
    <div class="phpinfo">
        <h2>PHP Configuration</h2>
        <?php phpinfo(); ?>
    </div>
</body>
</html>
EOF
        
        # Set proper permissions for PHP file
        chown -R apache:apache "$web_root" 2>/dev/null || chown -R www-data:www-data "$web_root" 2>/dev/null || chown -R nginx:nginx "$web_root" 2>/dev/null || true
        chmod 644 "$web_root/index.php"
        
        print_success "Default index.php created at $web_root/index.php"
        log "INFO" "Default index.php created successfully"
        
    else
        # Create index.html without PHP functionality
        print_info "Creating default index.html in $web_root..."
        log "INFO" "Creating default index.html for $web_server in $web_root (no PHP)"
        
        # Create index.html with static content
        cat > "$web_root/index.html" <<'EOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Web Server Setup Complete</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; background-color: #f5f5f5; }
        .container { max-width: 800px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .header { background: #2196F3; color: white; padding: 20px; border-radius: 5px; margin-bottom: 20px; text-align: center; }
        .success-box { background: #4CAF50; color: white; padding: 20px; border-radius: 5px; margin-bottom: 20px; }
        .info-box { background: #f9f9f9; border: 1px solid #ddd; padding: 20px; border-radius: 5px; margin-bottom: 20px; }
        .footer { text-align: center; margin-top: 30px; color: #666; }
        h1 { margin: 0; }
        h2 { color: #333; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🎉 Hello World!</h1>
            <p>Your web server is successfully installed and running!</p>
        </div>
        
        <div class="success-box">
            <h2>Installation Success</h2>
            <p>✅ Web server is running</p>
            <p>✅ Static file serving is enabled</p>
            <p>✅ File permissions are set properly</p>
            <p><strong>Server Time:</strong> <span id="current-time"></span></p>
        </div>
        
        <div class="info-box">
            <h2>Server Information</h2>
            <p><strong>Web Root:</strong> This page is served from your web server's document root</p>
            <p><strong>Configuration:</strong> Static HTML/CSS/JavaScript files are ready to be served</p>
            <p><strong>Note:</strong> PHP was not installed, so this server will serve static files only</p>
        </div>
        
        <div class="info-box">
            <h2>Next Steps</h2>
            <p>📁 Place your HTML, CSS, and JavaScript files in the web root directory</p>
            <p>🌐 Your website is now ready to serve static content</p>
            <p>🔒 Consider setting up SSL certificates for HTTPS</p>
            <p>🛡️ Review security settings and firewall configuration</p>
        </div>
        
        <div class="footer">
            <p>Web development environment setup completed successfully!</p>
        </div>
    </div>
    
    <script>
        // Display current time
        function updateTime() {
            const now = new Date();
            document.getElementById('current-time').textContent = now.toLocaleString();
        }
        updateTime();
        setInterval(updateTime, 1000);
    </script>
</body>
</html>
EOF
        
        # Set proper permissions for HTML file
        chown -R apache:apache "$web_root" 2>/dev/null || chown -R www-data:www-data "$web_root" 2>/dev/null || chown -R nginx:nginx "$web_root" 2>/dev/null || true
        chmod 644 "$web_root/index.html"
        
        print_success "Default index.html created at $web_root/index.html"
        log "INFO" "Default index.html created successfully"
    fi
}

# Install Composer (PHP package manager)
install_composer() {
    print_info "Installing Composer (PHP package manager)..."
    log "INFO" "Starting Composer installation"
    
    # Check if PHP is available (needed for Composer)
    if ! command -v php >/dev/null 2>&1; then
        print_error "PHP is required for Composer but not found. Install PHP first."
        log "ERROR" "Composer installation failed: PHP not available"
        return 1
    fi
    
    # Download and install Composer using secure temporary directory
    print_info "Downloading Composer installer..."
    
    # Create secure temporary directory
    local temp_dir=$(mktemp -d)
    trap "rm -rf '$temp_dir'" EXIT
    cd "$temp_dir"
    
    # Download composer installer with signature verification
    if php -r "copy('https://getcomposer.org/installer', 'composer-setup.php');"; then
        print_success "Composer installer downloaded"
    else
        print_error "Failed to download Composer installer"
        log "ERROR" "Composer installer download failed"
        return 1
    fi
    
    # Verify installer signature
    print_info "Verifying Composer installer signature..."
    if ! EXPECTED_SIGNATURE="$(wget -q -O - https://composer.github.io/installer.sig)"; then
        print_error "Failed to download Composer signature"
        log "ERROR" "Composer signature download failed"
        return 1
    fi
    
    ACTUAL_SIGNATURE="$(php -r "echo hash_file('sha384', 'composer-setup.php');")"
    
    if [[ "$EXPECTED_SIGNATURE" != "$ACTUAL_SIGNATURE" ]]; then
        print_error "Composer installer signature verification failed"
        log "ERROR" "Composer installer signature mismatch"
        return 1
    fi
    
    print_success "Composer installer signature verified"
    log "INFO" "Composer installer signature verified"
    
    # Install Composer globally with path validation
    local install_dir="/usr/local/bin"
    if validate_file_path "$install_dir"; then
        print_info "Installing Composer to $install_dir..."
        if php composer-setup.php --install-dir="$install_dir" --filename=composer; then
            print_success "Composer installation command completed"
        else
            print_error "Composer installation command failed"
            log "ERROR" "php composer-setup.php command failed"
            return 1
        fi
    else
        print_error "Invalid installation directory: $install_dir"
        return 1
    fi
    
    # Verify installation - check file exists and is executable
    if [[ -f "/usr/local/bin/composer" && -x "/usr/local/bin/composer" ]]; then
        # Update PATH for current session to ensure composer command works
        export PATH="/usr/local/bin:$PATH"
        local composer_version=$(/usr/local/bin/composer --version --no-ansi 2>/dev/null)
        print_success "Composer installed successfully: $composer_version"
        log "INFO" "Composer installation completed: $composer_version"
        
        # Create global composer directory with proper permissions and validation
        if [[ -n "$USERNAME" ]] && validate_username "$USERNAME"; then
            local composer_dir="/home/$USERNAME/.composer"
            if validate_file_path "$composer_dir"; then
                mkdir -p "$composer_dir"
                chown -R "$USERNAME:$USERNAME" "$composer_dir"
                chmod 755 "$composer_dir"
                print_info "Composer global directory created for user: $USERNAME"
            else
                print_error "Invalid composer directory path for user: $USERNAME"
            fi
        fi
        
        # Set up global bin directory in PATH (add to bashrc if user exists)
        if [[ -n "$USERNAME" ]] && validate_username "$USERNAME"; then
            local bashrc_file="/home/$USERNAME/.bashrc"
            if validate_file_path "$bashrc_file"; then
                echo 'export PATH="$HOME/.composer/vendor/bin:$PATH"' >> "$bashrc_file"
                print_info "Composer bin directory added to PATH for user: $USERNAME"
            fi
        fi
        
        return 0
    else
        print_error "Composer installation failed"
        log "ERROR" "Composer installation verification failed"
        return 1
    fi
}

# Install Node.js and npm
install_nodejs() {
    print_info "Installing Node.js 18+ and npm..."
    log "INFO" "Starting Node.js installation"
    
    # Define Node.js version to install (LTS)
    local NODE_MAJOR=18
    
    case "$PACKAGE_MANAGER" in
        dnf|yum)
            # Install NodeSource repository for RHEL-based systems
            print_info "Setting up NodeSource repository for Node.js ${NODE_MAJOR}..."
            curl -fsSL https://rpm.nodesource.com/setup_${NODE_MAJOR}.x | bash -
            if [[ $? -ne 0 ]]; then
                print_error "Failed to setup NodeSource repository"
                log "ERROR" "NodeSource repository setup failed"
                return 1
            fi
            install_package "nodejs" "Node.js from NodeSource"
            ;;
        apt)
            # Install NodeSource repository for Debian-based systems
            print_info "Setting up NodeSource repository for Node.js ${NODE_MAJOR}..."
            apt-get update
            apt-get install -y ca-certificates curl gnupg
            mkdir -p /etc/apt/keyrings
            curl -fsSL https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key | gpg --dearmor -o /etc/apt/keyrings/nodesource.gpg
            echo "deb [signed-by=/etc/apt/keyrings/nodesource.gpg] https://deb.nodesource.com/node_${NODE_MAJOR}.x nodistro main" | tee /etc/apt/sources.list.d/nodesource.list
            apt-get update
            install_package "nodejs" "Node.js from NodeSource"
            ;;
        zypper)
            # For openSUSE, try to install a newer version or use NodeSource
            print_info "Setting up NodeSource repository for Node.js ${NODE_MAJOR}..."
            zypper install -y curl
            curl -fsSL https://rpm.nodesource.com/setup_${NODE_MAJOR}.x | bash -
            if [[ $? -ne 0 ]]; then
                print_warning "NodeSource setup failed, falling back to system packages"
                install_package "nodejs18" "Node.js 18" || install_package "nodejs" "Node.js"
                install_package "npm18" "npm 18" || install_package "npm" "npm"
            else
                install_package "nodejs" "Node.js from NodeSource"
            fi
            ;;
        pacman)
            # Arch Linux typically has recent Node.js versions
            install_package "nodejs" "Node.js"
            install_package "npm" "npm"
            ;;
        *)
            print_error "Unsupported package manager for Node.js installation"
            log "ERROR" "Node.js installation: Unsupported package manager"
            return 1
            ;;
    esac
    
    # Verify Node.js installation
    if command -v node >/dev/null 2>&1; then
        local node_version=$(node --version)
        local node_major_version=$(echo "$node_version" | sed 's/v\([0-9]*\).*/\1/')
        
        print_success "Node.js installed successfully: $node_version"
        log "INFO" "Node.js installation completed: $node_version"
        
        # Check if Node.js version meets Claude Code requirements (>=18.0.0)
        if [[ "$node_major_version" -ge 18 ]]; then
            print_success "Node.js version meets Claude Code requirements (>=18.0.0)"
            log "INFO" "Node.js version compatible with Claude Code: $node_version"
        else
            print_warning "Node.js version $node_version may not meet Claude Code requirements (>=18.0.0)"
            log "WARNING" "Node.js version may be incompatible with Claude Code: $node_version"
        fi
    else
        print_error "Node.js installation verification failed"
        log "ERROR" "Node.js installation verification failed"
        return 1
    fi
    
    # Verify npm installation
    if command -v npm >/dev/null 2>&1; then
        local npm_version=$(npm --version)
        print_success "npm installed successfully: $npm_version"
        log "INFO" "npm installation completed: $npm_version"
        
        # Update npm to latest version (with better error handling)
        print_info "Updating npm to latest version..."
        if npm install -g npm@11.4.2 >/dev/null 2>&1; then
            local updated_npm_version=$(npm --version)
            print_success "npm updated successfully: $updated_npm_version"
            log "INFO" "npm updated to version: $updated_npm_version"
        else
            print_info "Failed to update npm to latest version (current version works fine)"
            log "INFO" "npm update failed, keeping current version: $npm_version"
        fi
        
        # Set up npm global directory for user (if user exists)
        if [[ -n "$USERNAME" ]]; then
            # Create npm global directory
            mkdir -p "/home/$USERNAME/.npm-global"
            chown -R "$USERNAME:$USERNAME" "/home/$USERNAME/.npm-global"
            
            # Configure npm to use the new directory
            sudo -u "$USERNAME" npm config set prefix "/home/$USERNAME/.npm-global"
            
            # Add npm global bin to PATH
            echo 'export PATH="$HOME/.npm-global/bin:$PATH"' >> "/home/$USERNAME/.bashrc"
            
            print_info "npm global directory configured for user: $USERNAME"
            log "INFO" "npm global directory configured for user: $USERNAME"
        fi
        
        return 0
    else
        print_error "npm installation verification failed"
        log "ERROR" "npm installation verification failed"
        return 1
    fi
}

# Install Git
install_git() {
    print_info "Installing Git..."
    log "INFO" "Starting Git installation"
    
    local git_package="git"
    
    # Install Git package
    install_package "$git_package" "Git version control system"
    if [[ $? -ne 0 ]]; then
        print_error "Failed to install Git"
        log "ERROR" "Git installation failed"
        return 1
    fi
    
    # Verify Git installation
    if command -v git >/dev/null 2>&1; then
        local git_version=$(git --version)
        print_success "Git installed successfully: $git_version"
        log "INFO" "Git installation completed: $git_version"
        
        # Set up basic Git configuration template (users can customize)
        print_info "Setting up basic Git configuration template..."
        git config --system init.defaultBranch main 2>/dev/null || true
        git config --system pull.rebase false 2>/dev/null || true
        
        # Create global gitignore template if it doesn't exist
        if [[ ! -f "/etc/gitignore" ]]; then
            cat > /etc/gitignore <<EOF
# Logs
*.log
npm-debug.log*
yarn-debug.log*
yarn-error.log*

# Runtime data
pids
*.pid
*.seed
*.pid.lock

# Dependency directories
node_modules/
vendor/

# IDE
.vscode/
.idea/
*.swp
*.swo

# OS generated files
.DS_Store
.DS_Store?
._*
.Spotlight-V100
.Trashes
ehthumbs.db
Thumbs.db

# Temporary files
*.tmp
*.temp
*~
EOF
            print_info "Created global gitignore template at /etc/gitignore"
            log "INFO" "Global gitignore template created"
        fi
        
        # If domain user exists, set up user-specific Git configuration
        if [[ -n "$USERNAME" ]]; then
            print_info "Setting up Git configuration for user: $USERNAME"
            sudo -u "$USERNAME" git config --global init.defaultBranch main
            sudo -u "$USERNAME" git config --global pull.rebase false
            sudo -u "$USERNAME" git config --global core.excludesfile "/etc/gitignore"
            print_info "Git configured for user $USERNAME (email and name need to be set by user)"
            log "INFO" "Git user configuration set for $USERNAME"
        fi
        
        return 0
    else
        print_error "Git installation verification failed"
        log "ERROR" "Git installation verification failed"
        return 1
    fi
}

# Install GitHub CLI
install_github_cli() {
    print_info "Installing GitHub CLI..."
    log "INFO" "Starting GitHub CLI installation"
    
    local gh_installed=false
    
    case "$PACKAGE_MANAGER" in
        dnf|yum)
            # Add GitHub CLI repository for RHEL/CentOS
            print_info "Adding GitHub CLI repository..."
            
            # Try official method first
            if ! dnf config-manager --add-repo https://cli.github.com/packages/rpm/gh-cli.repo >/dev/null 2>&1; then
                # Fallback to manual repo file creation
                print_info "Using fallback repository configuration..."
                cat > /etc/yum.repos.d/gh-cli.repo <<EOF
[gh-cli]
name=packages for the GitHub CLI
baseurl=https://cli.github.com/packages/rpm
enabled=1
gpgcheck=1
gpgkey=https://cli.github.com/packages/githubcli-archive-keyring.gpg
EOF
            fi
            
            # Import GPG key with multiple fallback methods
            print_info "Importing GitHub CLI GPG key..."
            if ! rpm --import https://cli.github.com/packages/githubcli-archive-keyring.gpg 2>/dev/null; then
                print_info "Primary GitHub keyring failed, trying RPM repository key..."
                if ! rpm --import https://packagecloud.io/github/git-lfs/gpgkey 2>/dev/null; then
                    print_warning "GPG key import failed, trying direct binary installation..."
                    gh_installed=false
                else
                    print_success "GPG key imported successfully"
                fi
            else
                print_success "GPG key imported successfully"
            fi
            
            # Try package installation if GPG worked
            if [[ "$gh_installed" == false ]]; then
                if install_package "gh" "GitHub CLI" 2>/dev/null; then
                    gh_installed=true
                fi
            fi
            ;;
        apt)
            # Add GitHub CLI repository for Ubuntu/Debian
            print_info "Adding GitHub CLI repository..."
            
            # Download and install keyring
            if curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg | dd of=/usr/share/keyrings/githubcli-archive-keyring.gpg 2>/dev/null; then
                chmod go+r /usr/share/keyrings/githubcli-archive-keyring.gpg
                echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" > /etc/apt/sources.list.d/github-cli.list
                print_success "GitHub CLI repository keyring installed"
                
                if apt-get update >/dev/null 2>&1 && install_package "gh" "GitHub CLI" 2>/dev/null; then
                    gh_installed=true
                fi
            else
                print_warning "Keyring download failed, trying direct binary installation..."
                gh_installed=false
            fi
            ;;
        zypper)
            # Add GitHub CLI repository for openSUSE
            print_info "Adding GitHub CLI repository..."
            if zypper addrepo https://cli.github.com/packages/rpm/gh-cli.repo >/dev/null 2>&1; then
                print_success "GitHub CLI repository added"
            else
                print_info "Using manual repository configuration..."
                zypper addrepo --name "GitHub CLI" https://cli.github.com/packages/rpm/ gh-cli >/dev/null 2>&1 || true
            fi
            
            if zypper refresh >/dev/null 2>&1 && install_package "gh" "GitHub CLI" 2>/dev/null; then
                gh_installed=true
            fi
            ;;
        pacman)
            # GitHub CLI is available in Arch community repository
            if install_package "github-cli" "GitHub CLI" 2>/dev/null; then
                gh_installed=true
            fi
            ;;
    esac
    
    # Fallback to direct binary installation if package method failed
    if [[ "$gh_installed" == false ]]; then
        print_info "Package installation failed, trying direct binary download..."
        log "INFO" "Falling back to direct GitHub CLI binary installation"
        
        # Detect architecture
        local arch=""
        case "$(uname -m)" in
            x86_64) arch="amd64" ;;
            aarch64) arch="arm64" ;;
            armv7l) arch="armv6" ;;
            *) 
                print_error "Unsupported architecture for GitHub CLI binary installation"
                return 1
                ;;
        esac
        
        # Download latest release info
        print_info "Detecting latest GitHub CLI version..."
        local latest_url="https://api.github.com/repos/cli/cli/releases/latest"
        local download_url=""
        
        if command -v curl >/dev/null 2>&1; then
            download_url=$(curl -s "$latest_url" | grep "browser_download_url.*linux_${arch}.tar.gz" | cut -d '"' -f 4 | head -n 1)
        elif command -v wget >/dev/null 2>&1; then
            download_url=$(wget -qO- "$latest_url" | grep "browser_download_url.*linux_${arch}.tar.gz" | cut -d '"' -f 4 | head -n 1)
        fi
        
        if [[ -n "$download_url" ]]; then
            print_info "Downloading GitHub CLI binary from: $download_url"
            cd /tmp
            
            # Download and extract
            if curl -L "$download_url" -o gh.tar.gz 2>/dev/null || wget "$download_url" -O gh.tar.gz 2>/dev/null; then
                tar -xzf gh.tar.gz
                
                # Find the extracted directory
                local gh_dir=$(find /tmp -maxdepth 1 -type d -name "gh_*_linux_${arch}" | head -n 1)
                
                if [[ -n "$gh_dir" && -f "$gh_dir/bin/gh" ]]; then
                    # Install binary and man pages
                    cp "$gh_dir/bin/gh" /usr/local/bin/
                    chmod +x /usr/local/bin/gh
                    
                    # Install man pages if available
                    if [[ -d "$gh_dir/share/man" ]]; then
                        cp -r "$gh_dir/share/man/"* /usr/share/man/ 2>/dev/null || true
                    fi
                    
                    # Clean up
                    rm -rf gh.tar.gz "$gh_dir"
                    
                    gh_installed=true
                    print_success "GitHub CLI installed via direct binary download"
                    log "INFO" "GitHub CLI binary installation completed"
                else
                    print_error "Failed to extract GitHub CLI binary"
                    rm -f gh.tar.gz
                    rm -rf gh_*
                fi
            else
                print_error "Failed to download GitHub CLI binary"
            fi
        else
            print_error "Could not determine GitHub CLI download URL"
        fi
    fi
    
    # Verify GitHub CLI installation
    if command -v gh >/dev/null 2>&1; then
        local gh_version=$(gh --version | head -n 1)
        print_success "GitHub CLI installed successfully: $gh_version"
        log "INFO" "GitHub CLI installation completed: $gh_version"
        
        # Set up GitHub CLI completion for bash (if user exists)
        if [[ -n "$USERNAME" ]]; then
            print_info "Setting up GitHub CLI completion for user: $USERNAME"
            # Add GitHub CLI completion to user's bashrc
            if ! grep -q "gh completion bash" "/home/$USERNAME/.bashrc" 2>/dev/null; then
                echo "" >> "/home/$USERNAME/.bashrc"
                echo "# GitHub CLI completion" >> "/home/$USERNAME/.bashrc"
                echo 'eval "$(gh completion -s bash)"' >> "/home/$USERNAME/.bashrc"
                print_info "GitHub CLI bash completion added for user $USERNAME"
                log "INFO" "GitHub CLI bash completion configured for $USERNAME"
            fi
        fi
        
        return 0
    else
        print_error "GitHub CLI installation verification failed"
        log "ERROR" "GitHub CLI installation verification failed"
        return 1
    fi
}

# Install Claude AI Code
install_claude_ai() {
    print_info "Installing Claude AI Code..."
    log "INFO" "Starting Claude AI Code installation"
    
    # Check if Node.js is available and meets requirements
    if ! command -v node >/dev/null 2>&1; then
        print_error "Node.js is required for Claude AI Code installation"
        log "ERROR" "Claude AI Code: Node.js not found"
        return 1
    fi
    
    local node_version=$(node --version)
    local node_major_version=$(echo "$node_version" | sed 's/v\([0-9]*\).*/\1/')
    
    if [[ "$node_major_version" -lt 18 ]]; then
        print_error "Claude AI Code requires Node.js >= 18.0.0 (current: $node_version)"
        log "ERROR" "Claude AI Code: Node.js version incompatible: $node_version"
        return 1
    fi
    
    print_info "Node.js version compatible: $node_version"
    
    # Check if npm is available
    if ! command -v npm >/dev/null 2>&1; then
        print_error "npm is required for Claude AI Code installation"
        log "ERROR" "Claude AI Code: npm not found"
        return 1
    fi
    
    # Install Claude AI Code globally
    print_info "Installing Claude AI Code via npm..."
    if npm install -g @anthropic-ai/claude-code; then
        print_success "Claude AI Code installed successfully"
        log "INFO" "Claude AI Code installation completed"
        
        # Verify installation
        if command -v claude >/dev/null 2>&1; then
            print_success "Claude AI Code verified: installed and available"
            log "INFO" "Claude AI Code verification completed: installed and available"
            
            # Add helpful information
            print_info "To use Claude AI Code, run: claude"
            print_info "For help, run: claude --help"
            log "INFO" "Claude AI Code usage information provided"
            
            return 0
        else
            print_warning "Claude AI Code installed but command verification failed"
            log "WARNING" "Claude AI Code command verification failed"
            return 0
        fi
    else
        print_error "Failed to install Claude AI Code via npm"
        log "ERROR" "Claude AI Code npm installation failed"
        return 1
    fi
}


# Configure firewall for HTTP
configure_firewall_http() {
    print_info "Configuring firewall for HTTP/HTTPS..."
    log "INFO" "Configuring firewall rules"
    
    if command -v firewall-cmd >/dev/null 2>&1; then
        # Ensure firewalld is running
        if ! systemctl is-active --quiet firewalld; then
            print_info "Starting firewalld service..."
            systemctl start firewalld
            systemctl enable firewalld
            log "INFO" "Firewalld service started and enabled"
        fi
        
        # RHEL/CentOS firewall
        firewall-cmd --permanent --add-service=http
        firewall-cmd --permanent --add-service=https
        
        # Add user IP to whitelist if provided
        if [[ -n "$USER_IP" ]]; then
            firewall-cmd --permanent --add-rich-rule="rule family='ipv4' source address='$USER_IP' accept"
            print_success "IP $USER_IP whitelisted in firewall"
        fi
        
        firewall-cmd --reload
        print_success "Firewall configured for HTTP/HTTPS"
        
    elif command -v ufw >/dev/null 2>&1; then
        # Ubuntu/Debian firewall
        ufw allow 'Apache Full'
        
        # Add user IP to whitelist if provided
        if [[ -n "$USER_IP" ]]; then
            ufw allow from "$USER_IP"
            print_success "IP $USER_IP whitelisted in firewall"
        fi
        
        print_success "UFW configured for Apache"
    fi
    
    log "INFO" "Firewall configuration completed"
}

# Create user and domain setup
create_user_and_domain() {
    if [[ "$CREATE_USER" != true ]]; then
        return
    fi
    
    print_info "Creating user $USERNAME and setting up domain $DOMAIN_NAME..."
    log "INFO" "Creating user: $USERNAME for domain: $DOMAIN_NAME"
    
    # Create user with home directory
    if ! id "$USERNAME" >/dev/null 2>&1; then
        useradd -m -s /bin/bash "$USERNAME"
        print_success "User $USERNAME created"
    else
        print_info "User $USERNAME already exists"
    fi
    
    # Create web directory
    local web_dir="/home/$USERNAME/public_html"
    mkdir -p "$web_dir"
    chown "$USERNAME:$USERNAME" "$web_dir"
    
    # Create Hello World PHP page
    cat > "$web_dir/index.php" <<EOF
<?php
echo "<h1>Hello World!</h1>";
echo "<p>Welcome to $DOMAIN_NAME</p>";
echo "<p>Server: " . \$_SERVER['HTTP_HOST'] . "</p>";
echo "<p>PHP Version: " . phpversion() . "</p>";
echo "<p>Current Time: " . date('Y-m-d H:i:s') . "</p>";
phpinfo();
?>
EOF
    
    chown "$USERNAME:$USERNAME" "$web_dir/index.php"
    
    # Create virtual host
    create_virtual_host
    
    print_success "User and domain setup completed"
    log "INFO" "User and domain setup completed"
}

# Create virtual host
create_virtual_host() {
    print_info "Creating virtual host for $DOMAIN_NAME..."
    log "INFO" "Creating virtual host for domain: $DOMAIN_NAME"
    
    local vhost_config=""
    local web_dir="/home/$USERNAME/public_html"
    
    case "$SELECTED_WEBSERVER" in
        apache)
            case "$PACKAGE_MANAGER" in
                dnf|yum)
                    vhost_config="/etc/httpd/conf.d/${DOMAIN_NAME}.conf"
                    ;;
                apt)
                    vhost_config="/etc/apache2/sites-available/${DOMAIN_NAME}.conf"
                    ;;
                zypper)
                    vhost_config="/etc/apache2/vhosts.d/${DOMAIN_NAME}.conf"
                    ;;
            esac
            
            # Create Apache virtual host
            cat > "$vhost_config" <<EOF
<VirtualHost *:80>
    ServerName $DOMAIN_NAME
    ServerAlias www.$DOMAIN_NAME
    DocumentRoot $web_dir
    
    <Directory $web_dir>
        AllowOverride All
        Require all granted
    </Directory>
    
    ErrorLog logs/${DOMAIN_NAME}_error.log
    CustomLog logs/${DOMAIN_NAME}_access.log common
</VirtualHost>
EOF
            
            # Enable site on Debian/Ubuntu
            if [[ "$PACKAGE_MANAGER" == "apt" ]]; then
                a2ensite "$DOMAIN_NAME"
                systemctl reload apache2
            else
                systemctl reload httpd
            fi
            ;;
    esac
    
    print_success "Virtual host created for $DOMAIN_NAME"
    log "INFO" "Virtual host configuration completed"
}

# Install Fail2ban
install_fail2ban() {
    print_info "Installing Fail2ban security service..."
    log "INFO" "Starting Fail2ban installation"
    
    # Install Fail2ban
    install_package "fail2ban" "Fail2ban Security Service"
    
    # Determine correct log paths for different OS
    local ssh_logpath=""
    local apache_error_logpath=""
    local apache_access_logpath=""
    
    case "$PACKAGE_MANAGER" in
        dnf|yum)
            ssh_logpath="/var/log/secure"
            apache_error_logpath="/var/log/httpd/error_log"
            apache_access_logpath="/var/log/httpd/access_log"
            ;;
        apt)
            ssh_logpath="/var/log/auth.log"
            apache_error_logpath="/var/log/apache2/error.log"
            apache_access_logpath="/var/log/apache2/access.log"
            ;;
        zypper)
            ssh_logpath="/var/log/messages"
            apache_error_logpath="/var/log/apache2/error_log"
            apache_access_logpath="/var/log/apache2/access_log"
            ;;
        pacman)
            ssh_logpath="/var/log/auth.log"
            apache_error_logpath="/var/log/httpd/error_log"
            apache_access_logpath="/var/log/httpd/access_log"
            ;;
    esac
    
    # Create custom jail configuration
    cat > /etc/fail2ban/jail.local <<EOF
[DEFAULT]
# Ban time in seconds (1 hour)
bantime = 3600

# Find time window (10 minutes)
findtime = 600

# Number of failures before ban
maxretry = 5

# Ignore IP addresses (add user IP if provided)
ignoreip = 127.0.0.1/8 ::1
EOF

    # Add user IP to ignore list if provided
    if [[ -n "$USER_IP" ]]; then
        sed -i "s/ignoreip = 127.0.0.1\/8 ::1/ignoreip = 127.0.0.1\/8 ::1 $USER_IP/" /etc/fail2ban/jail.local
        print_success "User IP $USER_IP added to Fail2ban ignore list"
        log "INFO" "User IP $USER_IP added to Fail2ban ignore list"
    fi
    
    # Add SSH jail with correct log path
    cat >> /etc/fail2ban/jail.local <<EOF

[sshd]
enabled = true
port = ssh
logpath = $ssh_logpath
maxretry = 3
EOF

    # Add Apache jail if Apache is selected
    if [[ "$SELECTED_WEBSERVER" == "apache" ]]; then
        cat >> /etc/fail2ban/jail.local <<EOF

[apache-auth]
enabled = true
port = http,https
logpath = $apache_error_logpath
maxretry = 6

[apache-badbots]
enabled = true
port = http,https
logpath = $apache_access_logpath
maxretry = 2

[apache-noscript]
enabled = true
port = http,https
logpath = $apache_access_logpath
maxretry = 6
EOF
    fi
    
    # Ensure log files exist (create empty if they don't)
    touch "$ssh_logpath" 2>/dev/null || true
    if [[ "$SELECTED_WEBSERVER" == "apache" ]]; then
        touch "$apache_error_logpath" 2>/dev/null || true
        touch "$apache_access_logpath" 2>/dev/null || true
    fi
    
    # Start and enable Fail2ban
    print_info "Starting Fail2ban service..."
    if ! systemctl start fail2ban; then
        print_warning "Fail2ban failed to start, checking configuration..."
        
        # Check configuration
        if command -v fail2ban-client >/dev/null 2>&1; then
            fail2ban-client -t
        fi
        
        # Try to restart with more verbose output
        systemctl status fail2ban --no-pager || true
        
        # Attempt restart
        systemctl restart fail2ban || {
            print_error "Failed to start Fail2ban service"
            log "ERROR" "Fail2ban service failed to start"
            return 1
        }
    fi
    
    if systemctl enable fail2ban >/dev/null 2>&1; then
        print_success "Created fail2ban symlink"
        log "INFO" "Fail2ban service enabled for startup"
    else
        print_warning "Failed to enable fail2ban service for startup"
        log "WARNING" "Failed to enable fail2ban service for startup"
    fi
    INSTALLED_SERVICES+=("fail2ban")
    
    print_success "Fail2ban installed and configured successfully"
    log "INFO" "Fail2ban installation completed"
}

# Validate Fail2ban
validate_fail2ban() {
    print_info "Validating Fail2ban installation..."
    log "INFO" "Validating Fail2ban service"
    
    # Check if service is running
    if systemctl is-active --quiet fail2ban; then
        print_success "Fail2ban service is running"
        log "INFO" "Fail2ban service validation: PASSED"
    else
        print_error "Fail2ban service is not running"
        log "ERROR" "Fail2ban service validation: FAILED"
        
        # Provide debugging information
        print_info "Debugging Fail2ban service status..."
        systemctl status fail2ban --no-pager | head -10 | while read line; do
            log "DEBUG" "Fail2ban status: $line"
        done
        
        # Check if configuration is valid
        if command -v fail2ban-client >/dev/null 2>&1; then
            print_info "Testing Fail2ban configuration..."
            if fail2ban-client -t 2>/dev/null; then
                print_info "Fail2ban configuration is valid"
                log "INFO" "Fail2ban configuration test: PASSED"
                
                # Try to start the service
                print_info "Attempting to restart Fail2ban service..."
                if systemctl restart fail2ban; then
                    print_success "Fail2ban service restarted successfully"
                    log "INFO" "Fail2ban service restart: SUCCESS"
                else
                    print_error "Failed to restart Fail2ban service"
                    log "ERROR" "Fail2ban service restart: FAILED"
                    return 1
                fi
            else
                print_error "Fail2ban configuration is invalid"
                log "ERROR" "Fail2ban configuration test: FAILED"
                
                # Show configuration errors
                fail2ban-client -t 2>&1 | head -5 | while read line; do
                    log "ERROR" "Fail2ban config error: $line"
                done
                return 1
            fi
        fi
        
        # Check again after restart attempt
        if ! systemctl is-active --quiet fail2ban; then
            return 1
        fi
    fi
    
    # Check jail status
    if command -v fail2ban-client >/dev/null 2>&1; then
        local jail_status=$(fail2ban-client status 2>/dev/null | grep "Jail list:" | cut -d: -f2 | xargs)
        if [[ -n "$jail_status" ]]; then
            print_success "Active Fail2ban jails: $jail_status"
            log "INFO" "Fail2ban jails validation: PASSED - $jail_status"
            
            # Show jail details
            for jail in $jail_status; do
                local jail_info=$(fail2ban-client status "$jail" 2>/dev/null | grep -E "Currently failed|Currently banned" | xargs || true)
                if [[ -n "$jail_info" ]]; then
                    print_info "Jail '$jail': $jail_info"
                    log "INFO" "Fail2ban jail '$jail': $jail_info"
                fi
            done
        else
            print_warning "No active Fail2ban jails found"
            log "WARNING" "Fail2ban jails validation: WARNING"
        fi
    fi
    
    return 0
}

# Validation functions
validate_apache() {
    print_info "Validating Apache installation..."
    log "INFO" "Validating Apache service"
    
    local service_name=""
    case "$PACKAGE_MANAGER" in
        dnf|yum)
            service_name="httpd"
            ;;
        *)
            service_name="apache2"
            ;;
    esac
    
    # Check if service is running
    if systemctl is-active --quiet "$service_name"; then
        print_success "Apache service is running"
        log "INFO" "Apache service validation: PASSED"
    else
        print_error "Apache service is not running"
        log "ERROR" "Apache service validation: FAILED"
        return 1
    fi
    
    # Check if listening on port 80
    if netstat -tlnp 2>/dev/null | grep -q ":80 " || ss -tlnp 2>/dev/null | grep -q ":80 "; then
        print_success "Apache is listening on port 80"
        log "INFO" "Apache port 80 validation: PASSED"
    else
        print_error "Apache is not listening on port 80"
        log "ERROR" "Apache port 80 validation: FAILED"
        return 1
    fi
    
    # Test HTTP response
    if command -v curl >/dev/null 2>&1; then
        if curl -s -o /dev/null -w "%{http_code}" http://localhost | grep -q "200\|403"; then
            print_success "Apache HTTP response test passed"
            log "INFO" "Apache HTTP response validation: PASSED"
        else
            print_warning "Apache HTTP response test failed (this may be normal)"
            log "WARNING" "Apache HTTP response validation: WARNING"
        fi
        
        # Test PHP functionality with index.php (only if PHP was selected)
        if [[ "${SELECTED_PHP_VERSIONS[0]}" != "none" ]]; then
            local php_response=$(curl -s http://localhost/index.php 2>/dev/null | head -1)
            if [[ "$php_response" == *"DOCTYPE html"* ]]; then
                print_success "Apache PHP index.php test passed"
                log "INFO" "Apache PHP index.php validation: PASSED"
            else
                print_warning "Apache PHP index.php test failed"
                log "WARNING" "Apache PHP index.php validation: WARNING"
            fi
        fi
    fi
    
    # Check if index file exists (PHP or HTML based on selection)
    local web_root="/var/www/html"
    [[ "$PACKAGE_MANAGER" == "zypper" ]] && web_root="/srv/www/htdocs"
    [[ "$PACKAGE_MANAGER" == "pacman" ]] && web_root="/srv/http"
    
    if [[ "${SELECTED_PHP_VERSIONS[0]}" != "none" ]]; then
        # Check for index.php when PHP is installed
        if [[ -f "$web_root/index.php" ]]; then
            print_success "Default index.php file exists at $web_root/index.php"
            log "INFO" "Apache index.php file validation: PASSED"
        else
            print_error "Default index.php file missing at $web_root/index.php"
            log "ERROR" "Apache index.php file validation: FAILED"
            return 1
        fi
    else
        # Check for index.html when PHP is not installed
        if [[ -f "$web_root/index.html" ]]; then
            print_success "Default index.html file exists at $web_root/index.html"
            log "INFO" "Apache index.html file validation: PASSED"
        else
            print_error "Default index.html file missing at $web_root/index.html"
            log "ERROR" "Apache index.html file validation: FAILED"
            return 1
        fi
    fi
    
    return 0
}

# Enhanced socket validation for Nginx-PHP integration
validate_nginx_php_sockets() {
    if [[ "$SELECTED_WEBSERVER" != "nginx" || "${SELECTED_PHP_VERSIONS[0]}" == "none" ]]; then
        return 0  # Skip if not using Nginx with PHP
    fi
    
    print_info "Validating Nginx-PHP socket communication..."
    log "INFO" "Starting Nginx-PHP socket validation"
    
    local default_version_nodot="${DEFAULT_PHP_VERSION//./}"
    if [[ -z "$default_version_nodot" ]]; then
        default_version_nodot="${SELECTED_PHP_VERSIONS[0]//./}"
    fi
    local socket_path="/run/php-fpm/php${default_version_nodot}.sock"
    local validation_failed=false
    
    # Test 1: Socket file exists
    if [[ ! -S "$socket_path" ]]; then
        print_error "PHP-FPM socket missing: $socket_path"
        log "ERROR" "Socket validation failed: Socket file does not exist: $socket_path"
        log "ERROR" "Diagnostic: PHP-FPM service may have failed to create socket file"
        log "ERROR" "Suggested check: systemctl status php${default_version_nodot}-php-fpm"
        validation_failed=true
    else
        log "SUCCESS" "Socket file exists: $socket_path"
    fi
    
    # Test 2: Socket permissions
    if [[ -S "$socket_path" ]] && ! sudo -u nginx test -r "$socket_path" 2>/dev/null; then
        print_error "Nginx cannot access PHP-FPM socket: $socket_path"
        log "ERROR" "Socket validation failed: Permission denied for nginx user"
        log "ERROR" "Diagnostic: Socket permissions or ownership issue detected"
        log "ERROR" "Suggested fix: chown nginx:nginx $socket_path && chmod 660 $socket_path"
        validation_failed=true
    elif [[ -S "$socket_path" ]]; then
        log "SUCCESS" "Socket permissions validated for nginx user"
    fi
    
    # Test 3: PHP-FPM service listening on socket
    if [[ -S "$socket_path" ]] && ! netstat -xl 2>/dev/null | grep -q "$socket_path"; then
        print_error "PHP-FPM not listening on socket: $socket_path"
        log "ERROR" "Socket validation failed: PHP-FPM service not listening on socket"
        log "ERROR" "Diagnostic: PHP-FPM configuration may be incorrect"
        log "ERROR" "Suggested check: grep '^listen' /etc/opt/remi/php${default_version_nodot}/php-fpm.d/www.conf"
        validation_failed=true
    elif [[ -S "$socket_path" ]]; then
        log "SUCCESS" "PHP-FPM listening on socket: $socket_path"
    fi
    
    # Test 4: Nginx configuration points to correct socket
    local nginx_config="/etc/nginx/conf.d/default.conf"
    if [[ -f "$nginx_config" ]] && ! grep -q "fastcgi_pass unix:$socket_path" "$nginx_config"; then
        print_error "Nginx not configured for correct socket path"
        log "ERROR" "Socket validation failed: Nginx configuration mismatch"
        log "ERROR" "Expected: fastcgi_pass unix:$socket_path"
        log "ERROR" "Suggested check: grep fastcgi_pass $nginx_config"
        validation_failed=true
    elif [[ -f "$nginx_config" ]]; then
        log "SUCCESS" "Nginx configured for correct socket: $socket_path"
    fi
    
    # Test 5: End-to-end PHP test (only if previous tests passed)
    if [[ "$validation_failed" == false ]]; then
        local php_test_response=$(curl -s http://localhost/index.php 2>/dev/null | head -1)
        if [[ "$php_test_response" != *"DOCTYPE html"* ]]; then
            print_warning "PHP processing test inconclusive"
            log "WARNING" "Socket validation: End-to-end test did not return expected HTML"
            log "WARNING" "Response received: $php_test_response"
            log "WARNING" "Suggested check: curl -v http://localhost/index.php"
            log "WARNING" "Suggested check: journalctl -u php${default_version_nodot}-php-fpm --no-pager -l"
        else
            print_success "Nginx-PHP socket communication validated successfully"
            log "SUCCESS" "End-to-end socket communication test passed"
        fi
    fi
    
    if [[ "$validation_failed" == true ]]; then
        log "ERROR" "Nginx-PHP socket validation failed - see errors above"
        return 1
    fi
    
    return 0
}

validate_nginx() {
    print_info "Validating Nginx installation..."
    log "INFO" "Validating Nginx service"
    
    local service_name="nginx"
    
    # Check if service is running
    if systemctl is-active --quiet "$service_name"; then
        print_success "Nginx service is running"
        log "INFO" "Nginx service validation: PASSED"
    else
        print_error "Nginx service is not running"
        log "ERROR" "Nginx service validation: FAILED"
        return 1
    fi
    
    # Check if listening on port 80
    if netstat -tlnp 2>/dev/null | grep -q ":80 " || ss -tlnp 2>/dev/null | grep -q ":80 "; then
        print_success "Nginx is listening on port 80"
        log "INFO" "Nginx port 80 validation: PASSED"
    else
        print_error "Nginx is not listening on port 80"
        log "ERROR" "Nginx port 80 validation: FAILED"
        return 1
    fi
    
    # Test HTTP response
    if command -v curl >/dev/null 2>&1; then
        if curl -s -o /dev/null -w "%{http_code}" http://localhost | grep -q "200\|403"; then
            print_success "Nginx HTTP response test passed"
            log "INFO" "Nginx HTTP response validation: PASSED"
        else
            print_warning "Nginx HTTP response test failed (this may be normal)"
            log "WARNING" "Nginx HTTP response validation: WARNING"
        fi
        
        # Test PHP functionality with index.php (only if PHP was selected)
        if [[ "${SELECTED_PHP_VERSIONS[0]}" != "none" ]]; then
            local php_response=$(curl -s http://localhost/index.php 2>/dev/null | head -1)
            if [[ "$php_response" == *"DOCTYPE html"* ]]; then
                print_success "Nginx PHP index.php test passed"
                log "INFO" "Nginx PHP index.php validation: PASSED"
            else
                print_warning "Nginx PHP index.php test failed"
                log "WARNING" "Nginx PHP index.php validation: WARNING"
            fi
        fi
    fi
    
    # Check if index.php file exists
    local web_root="/var/www/html"
    case "$PACKAGE_MANAGER" in
        dnf|yum)
            web_root="/usr/share/nginx/html"
            ;;
        zypper)
            web_root="/srv/www/htdocs"
            ;;
        pacman)
            web_root="/usr/share/nginx/html"
            ;;
    esac
    
    if [[ "${SELECTED_PHP_VERSIONS[0]}" != "none" ]]; then
        # Check for index.php when PHP is installed
        if [[ -f "$web_root/index.php" ]]; then
            print_success "Default index.php file exists at $web_root/index.php"
            log "INFO" "Nginx index.php file validation: PASSED"
        else
            print_error "Default index.php file missing at $web_root/index.php"
            log "ERROR" "Nginx index.php file validation: FAILED"
            return 1
        fi
    else
        # Check for index.html when PHP is not installed
        if [[ -f "$web_root/index.html" ]]; then
            print_success "Default index.html file exists at $web_root/index.html"
            log "INFO" "Nginx index.html file validation: PASSED"
        else
            print_error "Default index.html file missing at $web_root/index.html"
            log "ERROR" "Nginx index.html file validation: FAILED"
            return 1
        fi
    fi
    
    return 0
}

validate_mysql() {
    print_info "Validating MySQL installation..."
    log "INFO" "Validating MySQL service"
    
    local service_name=""
    case "$PACKAGE_MANAGER" in
        apt)
            service_name="mysql"
            ;;
        *)
            service_name="mysqld"
            ;;
    esac
    
    # Check if service is running
    if systemctl is-active --quiet "$service_name"; then
        print_success "MySQL service is running"
        log "INFO" "MySQL service validation: PASSED"
    else
        print_error "MySQL service is not running"
        log "ERROR" "MySQL service validation: FAILED"
        return 1
    fi
    
    # Check if listening on port 3306
    if netstat -tlnp 2>/dev/null | grep -q ":3306 " || ss -tlnp 2>/dev/null | grep -q ":3306 "; then
        print_success "MySQL is listening on port 3306"
        log "INFO" "MySQL port 3306 validation: PASSED"
    else
        print_error "MySQL is not listening on port 3306"
        log "ERROR" "MySQL port 3306 validation: FAILED"
        return 1
    fi
    
    # Test database connection
    if mysql -e "SELECT 1;" >/dev/null 2>&1; then
        print_success "MySQL connection test passed"
        log "INFO" "MySQL connection validation: PASSED"
    else
        print_error "MySQL connection test failed"
        log "ERROR" "MySQL connection validation: FAILED"
        return 1
    fi
    
    return 0
}

# Validate MariaDB installation
validate_mariadb() {
    print_info "Validating MariaDB installation..."
    log "INFO" "Validating MariaDB service"
    
    local service_name="mariadb"
    
    # Check if service is running
    if systemctl is-active --quiet "$service_name"; then
        print_success "MariaDB service is running"
        log "INFO" "MariaDB service validation: PASSED"
    else
        print_error "MariaDB service is not running"
        log "ERROR" "MariaDB service validation: FAILED"
        return 1
    fi
    
    # Check if listening on port 3306
    if netstat -tlnp 2>/dev/null | grep -q ":3306 " || ss -tlnp 2>/dev/null | grep -q ":3306 "; then
        print_success "MariaDB is listening on port 3306"
        log "INFO" "MariaDB port 3306 validation: PASSED"
    else
        print_error "MariaDB is not listening on port 3306"
        log "ERROR" "MariaDB port 3306 validation: FAILED"
        return 1
    fi
    
    # Test database connection
    if mysql -e "SELECT 1;" >/dev/null 2>&1; then
        print_success "MariaDB connection test passed"
        log "INFO" "MariaDB connection validation: PASSED"
    else
        print_error "MariaDB connection test failed"
        log "ERROR" "MariaDB connection validation: FAILED"
        return 1
    fi
    
    return 0
}

validate_php() {
    print_info "Validating PHP installation..."
    log "INFO" "Validating PHP installation"
    
    # Check PHP CLI
    if command -v php >/dev/null 2>&1; then
        local php_version=$(php -r "echo PHP_VERSION;" 2>/dev/null)
        print_success "PHP CLI available"
        log "INFO" "PHP CLI validation: PASSED - PHP $php_version"
    else
        print_error "PHP CLI not available"
        log "ERROR" "PHP CLI validation: FAILED"
        return 1
    fi
    
    # Test PHP info page
    if [[ "$CREATE_USER" == true ]]; then
        local web_dir="/home/$USERNAME/public_html"
        if [[ -f "$web_dir/index.php" ]]; then
            print_success "PHP test page created at $web_dir/index.php"
            log "INFO" "PHP test page validation: PASSED"
        else
            print_error "PHP test page not found"
            log "ERROR" "PHP test page validation: FAILED"
            return 1
        fi
    fi
    
    return 0
}

# Run all installations
run_installations() {
    print_info "Starting installation process..."
    log "INFO" "Beginning installation phase"
    
    # Update system first
    update_system
    
    # Setup repositories
    setup_repositories
    
    # Install selected web server
    if [[ "$SELECTED_WEBSERVER" == "apache" ]]; then
        install_apache
    elif [[ "$SELECTED_WEBSERVER" == "nginx" ]]; then
        install_nginx
    fi
    
    # Install selected databases
    print_info "Debug: SELECTED_DATABASES = '${SELECTED_DATABASES[*]}'"
    log "DEBUG" "Database selection debug: SELECTED_DATABASES = '${SELECTED_DATABASES[*]}'"
    
    if [[ "${SELECTED_DATABASES[0]}" == "none" ]]; then
        print_info "Skipping database installation as requested"
        log "INFO" "Database installation skipped by user choice"
    else
        for database in "${SELECTED_DATABASES[@]}"; do
            case "$database" in
                mysql)
                    install_mysql
                    ;;
                mariadb)
                    install_mariadb
                    ;;
                postgresql)
                    print_info "Starting PostgreSQL installation..."
                    install_postgresql
                    ;;
                sqlite)
                    print_info "Starting SQLite installation..."
                    install_sqlite
                    ;;
                *)
                    print_warning "Unknown database selection: '$database'"
                    log "WARNING" "Unknown database selection: '$database'"
                    ;;
            esac
        done
        
        # Save installed databases list for removal tracking
        if [[ ${#INSTALLED_DATABASES[@]} -gt 0 ]]; then
            printf '%s\n' "${INSTALLED_DATABASES[@]}" > /root/.installed_databases
            log "INFO" "Installed databases tracked: ${INSTALLED_DATABASES[*]}"
        fi
    fi
    
    # Install PHP versions
    install_php
    
    # Configure web server for PHP (only if PHP was installed)
    if [[ "${SELECTED_PHP_VERSIONS[0]}" != "none" ]]; then
        if [[ "$SELECTED_WEBSERVER" == "apache" ]]; then
            configure_apache_php
        elif [[ "$SELECTED_WEBSERVER" == "nginx" ]]; then
            configure_nginx_php
        fi
    else
        print_info "Skipping web server PHP configuration (PHP not installed)"
        log "INFO" "Web server PHP configuration skipped - PHP not installed"
    fi
    
    # Install selected package managers
    if [[ "${SELECTED_PACKAGE_MANAGERS[0]}" != "none" ]]; then
        for package_manager in "${SELECTED_PACKAGE_MANAGERS[@]}"; do
            case "$package_manager" in
                composer)
                    install_composer
                    ;;
                nodejs)
                    install_nodejs
                    ;;
                *)
                    print_warning "Unknown package manager: $package_manager"
                    log "WARNING" "Unknown package manager selection: $package_manager"
                    ;;
            esac
        done
    else
        print_info "Skipping package manager installation as requested"
        log "INFO" "Package manager installation skipped by user choice"
    fi
    
    # Install selected development tools
    if [[ "${SELECTED_DEVELOPMENT_TOOLS[0]}" != "none" ]]; then
        for dev_tool in "${SELECTED_DEVELOPMENT_TOOLS[@]}"; do
            case "$dev_tool" in
                git)
                    install_git
                    ;;
                github-cli)
                    install_github_cli
                    ;;
                claude-ai)
                    # Ensure Node.js is installed before installing Claude AI Code
                    if ! command -v node >/dev/null 2>&1; then
                        print_info "Node.js required for Claude AI Code - installing Node.js first..."
                        install_nodejs
                    fi
                    install_claude_ai
                    ;;
                *)
                    print_warning "Unknown development tool: $dev_tool"
                    log "WARNING" "Unknown development tool selection: $dev_tool"
                    ;;
            esac
        done
    else
        print_info "Skipping development tools installation as requested"
        log "INFO" "Development tools installation skipped by user choice"
    fi
    
    # Create user and domain setup
    create_user_and_domain
    
    # Install Fail2ban
    install_fail2ban
    
    print_success "Installation phase completed"
    log "INFO" "Installation phase completed successfully"
}

# Detect OS for removal (simplified version)
detect_os_for_removal() {
    # Skip log file initialization here - will be handled by remove_installation()
    
    local os_name=""
    local package_manager=""
    
    if [[ -f /etc/os-release ]]; then
        source /etc/os-release
        os_name="$NAME"
    else
        print_error "Cannot detect operating system"
        exit 1
    fi
    
    # Determine package manager
    if command -v dnf >/dev/null 2>&1; then
        package_manager="dnf"
    elif command -v yum >/dev/null 2>&1; then
        package_manager="yum"
    elif command -v apt >/dev/null 2>&1; then
        package_manager="apt"
    elif command -v zypper >/dev/null 2>&1; then
        package_manager="zypper"
    elif command -v pacman >/dev/null 2>&1; then
        package_manager="pacman"
    else
        print_error "Unsupported package manager"
        exit 1
    fi
    
    log "INFO" "Removal mode - Detected OS: $os_name"
    log "INFO" "Removal mode - Package manager: $package_manager"
    
    # Store in global variables for removal functions
    export OS_NAME="$os_name"
    export PACKAGE_MANAGER="$package_manager"
}

# Validate package managers
validate_package_managers() {
    print_info "Validating package managers..."
    log "INFO" "Starting package managers validation"
    
    local validation_failed=false
    
    for package_manager in "${SELECTED_PACKAGE_MANAGERS[@]}"; do
        case "$package_manager" in
            composer)
                if command -v composer >/dev/null 2>&1; then
                    local composer_version=$(composer --version --no-ansi 2>/dev/null)
                    print_success "Composer validation: PASSED - $composer_version"
                    log "INFO" "Composer validation: PASSED - $composer_version"
                else
                    print_error "Composer validation: FAILED"
                    log "ERROR" "Composer validation: FAILED"
                    validation_failed=true
                fi
                ;;
            nodejs)
                # Validate Node.js
                if command -v node >/dev/null 2>&1; then
                    local node_version=$(node --version)
                    print_success "Node.js validation: PASSED - $node_version"
                    log "INFO" "Node.js validation: PASSED - $node_version"
                else
                    print_error "Node.js validation: FAILED"
                    log "ERROR" "Node.js validation: FAILED"
                    validation_failed=true
                fi
                
                # Validate npm
                if command -v npm >/dev/null 2>&1; then
                    local npm_version=$(npm --version)
                    print_success "npm validation: PASSED - $npm_version"
                    log "INFO" "npm validation: PASSED - $npm_version"
                else
                    print_error "npm validation: FAILED"
                    log "ERROR" "npm validation: FAILED"
                    validation_failed=true
                fi
                ;;
            none)
                print_info "Package managers validation: SKIPPED (none selected)"
                log "INFO" "Package managers validation skipped - none selected"
                ;;
            *)
                print_warning "Unknown package manager for validation: $package_manager"
                log "WARNING" "Unknown package manager for validation: $package_manager"
                ;;
        esac
    done
    
    if [[ "$validation_failed" == true ]]; then
        return 1
    else
        return 0
    fi
}

# Validate development tools
validate_development_tools() {
    print_info "Validating development tools..."
    log "INFO" "Starting development tools validation"
    
    local validation_failed=false
    
    for dev_tool in "${SELECTED_DEVELOPMENT_TOOLS[@]}"; do
        case "$dev_tool" in
            git)
                if command -v git >/dev/null 2>&1; then
                    local git_version=$(git --version)
                    print_success "Git validation: PASSED - $git_version"
                    log "INFO" "Git validation: PASSED - $git_version"
                else
                    print_error "Git validation: FAILED"
                    log "ERROR" "Git validation: FAILED"
                    validation_failed=true
                fi
                ;;
            github-cli)
                if command -v gh >/dev/null 2>&1; then
                    local gh_version=$(gh --version | head -n 1)
                    print_success "GitHub CLI validation: PASSED - $gh_version"
                    log "INFO" "GitHub CLI validation: PASSED - $gh_version"
                else
                    print_error "GitHub CLI validation: FAILED"
                    log "ERROR" "GitHub CLI validation: FAILED"
                    validation_failed=true
                fi
                ;;
            claude-ai)
                if command -v claude >/dev/null 2>&1; then
                    print_success "Claude AI Code validation: PASSED - installed and available"
                    log "INFO" "Claude AI Code validation: PASSED - installed and available"
                else
                    print_error "Claude AI Code validation: FAILED"
                    log "ERROR" "Claude AI Code validation: FAILED"
                    validation_failed=true
                fi
                ;;
            none)
                print_info "Development tools validation: SKIPPED (none selected)"
                log "INFO" "Development tools validation skipped - none selected"
                ;;
            *)
                print_warning "Unknown development tool for validation: $dev_tool"
                log "WARNING" "Unknown development tool for validation: $dev_tool"
                ;;
        esac
    done
    
    if [[ "$validation_failed" == true ]]; then
        return 1
    else
        return 0
    fi
}

# Validate all installations
run_validations() {
    print_info "Starting validation phase..."
    log "INFO" "Beginning validation phase"
    
    local validation_failed=false
    
    # Validate Apache
    if [[ "$SELECTED_WEBSERVER" == "apache" ]]; then
        if ! validate_apache; then
            validation_failed=true
        fi
    fi
    
    # Validate Nginx
    if [[ "$SELECTED_WEBSERVER" == "nginx" ]]; then
        if ! validate_nginx; then
            validation_failed=true
        fi
    fi
    
    # Validate databases
    if [[ "${SELECTED_DATABASES[0]}" == "none" ]]; then
        print_info "Skipping database validation (none selected)"
        log "INFO" "Database validation skipped - none selected"
    else
        for database in "${SELECTED_DATABASES[@]}"; do
            case "$database" in
                mysql)
                    if ! validate_mysql; then
                        validation_failed=true
                    fi
                    ;;
                mariadb)
                    if ! validate_mariadb; then
                        validation_failed=true
                    fi
                    ;;
                postgresql)
                    if ! validate_postgresql; then
                        validation_failed=true
                    fi
                    ;;
                sqlite)
                    if ! validate_sqlite; then
                        validation_failed=true
                    fi
                    ;;
            esac
        done
    fi
    
    # Validate PHP (only if PHP was installed)
    if [[ "${SELECTED_PHP_VERSIONS[0]}" != "none" ]]; then
        if ! validate_php; then
            validation_failed=true
        fi
    else
        print_info "Skipping PHP validation (none selected)"
        log "INFO" "PHP validation skipped - none selected"
    fi
    
    # Validate Nginx-PHP socket integration (only if both Nginx and PHP are installed)
    if ! validate_nginx_php_sockets; then
        validation_failed=true
    fi
    
    # Validate package managers
    if [[ "${SELECTED_PACKAGE_MANAGERS[0]}" != "none" ]]; then
        if ! validate_package_managers; then
            validation_failed=true
        fi
    else
        print_info "Skipping package managers validation (none selected)"
        log "INFO" "Package managers validation skipped - none selected"
    fi
    
    # Validate development tools
    if [[ "${SELECTED_DEVELOPMENT_TOOLS[0]}" != "none" ]]; then
        if ! validate_development_tools; then
            validation_failed=true
        fi
    else
        print_info "Skipping development tools validation (none selected)"
        log "INFO" "Development tools validation skipped - none selected"
    fi
    
    # Validate Fail2ban
    if ! validate_fail2ban; then
        validation_failed=true
    fi
    
    if [[ "$validation_failed" == true ]]; then
        print_error "Some validations failed. Check the log for details."
        log "ERROR" "Validation phase completed with errors"
        return 1
    else
        print_success "All validations passed!"
        log "INFO" "Validation phase completed successfully"
        return 0
    fi
}

# Removal function
remove_installation() {
    # Create removal log file FIRST
    # Clean up old removal log files before creating new one
    rm -f "${SCRIPT_DIR}"/removal-log-*.log 2>/dev/null || true
    REMOVAL_LOG_FILE="${SCRIPT_DIR}/removal-log-$(date +%Y%m%d-%H%M%S).log"
    LOG_FILE="$REMOVAL_LOG_FILE"  # Redirect logging to removal log
    touch "$REMOVAL_LOG_FILE"  # Create the removal log file
    
    echo -e "${BLUE}===========================================================================${NC}"
    echo -e "${WHITE}                        PACKAGE UNINSTALL MODE${NC}"
    echo -e "${BLUE}===========================================================================${NC}"
    echo ""
    echo ""
    echo "   This will remove all components installed by this script."
    echo ""
    echo -e "   ${LIGHT_GREY}[INFO]${NC} Uninstall log: ${LIGHT_GREY}$REMOVAL_LOG_FILE${NC}"
    echo ""
    
    # Show verbose option if not already enabled
    if [[ "$VERBOSE_LOGGING" != true ]]; then
        print_tip "Use '${LIGHT_GREY}./setup.sh --verbose --remove${NC}' for detailed removal logs."
        echo ""
        echo ""
    fi
    
    # Initialize required variables for removal
    detect_os_for_removal
    
    log "COMPLETION" "Removal process initiated"
    
    # Skip confirmation in non-interactive mode
    if [[ "$NON_INTERACTIVE" == "true" ]]; then
        print_info "   Auto-proceeding with removal (non-interactive mode)"
        log "INFO" "Auto-proceeding with removal (non-interactive mode)"
        echo ""
        echo -e "${BLUE}===========================================================================${NC}"
        echo ""
    else
        echo -e "${BLUE}===========================================================================${NC}"
        echo ""
        read -p "   Are you sure you want to remove all installed components? (y/N): " -r
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            print_info "Removal cancelled"
            log "INFO" "Removal cancelled by user"
            
            # Clean up empty removal log file since removal was cancelled
            if [[ -n "$REMOVAL_LOG_FILE" && -f "$REMOVAL_LOG_FILE" ]]; then
                rm -f "$REMOVAL_LOG_FILE" 2>/dev/null || true
            fi
            
            exit 0
        fi
    fi
    
    
    print_info "Starting removal process..."
    log "COMPLETION" "Starting removal process"
    
    # Stop all services first
    stop_all_services
    
    # Remove Fail2ban
    remove_fail2ban
    
    # Remove user and domain setup
    remove_user_and_domain
    
    # Remove PHP
    remove_php
    
    # Remove package managers
    remove_package_managers
    
    # Remove essential tools
    remove_essential_tools
    
    # Remove development tools
    remove_development_tools
    
    # Remove database
    remove_database
    
    # Remove web server
    remove_webserver
    
    # Clean up repositories
    remove_repositories
    
    # Clean up firewall rules
    cleanup_firewall
    
    # Final cleanup - capture file count
    local cleanup_count=$(final_cleanup 2>&1 | grep -o '[0-9]\+ files removed' | grep -o '[0-9]\+' || echo "0")
    
    echo ""
    echo -e "${BLUE}====================================================================${NC}"
    echo -e "${WHITE}                REMOVAL COMPLETED SUCCESSFULLY${NC}"
    echo -e "${BLUE}====================================================================${NC}"
    echo ""
    echo "  • Repositories cleaned up successfully"
    echo "  • Firewall rules cleaned up"
    if [[ "$cleanup_count" -gt 0 ]]; then
        echo "  • $cleanup_count items cleaned up during final cleanup"
    else
        echo "  • Final cleanup completed"
    fi
    echo "  • All components have been removed from the system."
    echo "  • The server has been restored to its original state."
    echo "  • Removal log saved to: $REMOVAL_LOG_FILE"
    echo ""
    echo -e "  🔄 ${WHITE}Important: To clear stale command references, run:${NC} ${BLUE}hash -r${NC}"
    echo ""
    echo -e "${BLUE}====================================================================${NC}"
    echo ""
    
    log "COMPLETION" "Removal process completed successfully"
    log "COMPLETION" "All components removed from the system"
    log "COMPLETION" "Server restored to original state"
    
    
    exit 0
}

# Stop all services
stop_all_services() {
    print_info "Stopping all installed services..."
    log "COMPLETION" "Stopping services"
    
    local services_to_stop=("fail2ban" "httpd" "apache2" "nginx" "mysqld" "mysql" "php-fpm" "php8.2-fpm" "php8.3-fpm" "php8.4-fpm")
    
    for service in "${services_to_stop[@]}"; do
        if systemctl is-active --quiet "$service" 2>/dev/null; then
            if [[ "$VERBOSE_LOGGING" == true ]]; then
                print_info "Stopping service: $service"
            fi
            systemctl stop "$service" 2>/dev/null || true
            systemctl disable "$service" 2>/dev/null || true
            log "INFO" "Service stopped and disabled: $service"
        fi
    done
    
    print_success "Services stopped"
    log "COMPLETION" "All applicable services stopped"
}

# Helper function for safe package removal with proper error capture and logging
safe_package_remove() {
    local package="$1"
    local package_manager="$2"
    local removal_output=""
    local removal_success=true
    
    # Check if package is installed first
    case "$package_manager" in
        dnf|yum)
            if ! rpm -q "$package" >/dev/null 2>&1; then
                log "INFO" "Package '$package' not installed, skipping removal"
                return 0
            fi
            ;;
        apt)
            if ! dpkg -l "$package" >/dev/null 2>&1; then
                log "INFO" "Package '$package' not installed, skipping removal"
                return 0
            fi
            ;;
        zypper)
            if ! rpm -q "$package" >/dev/null 2>&1; then
                log "INFO" "Package '$package' not installed, skipping removal"
                return 0
            fi
            ;;
        pacman)
            if ! pacman -Q "$package" >/dev/null 2>&1; then
                log "INFO" "Package '$package' not installed, skipping removal"
                return 0
            fi
            ;;
    esac
    
    # Attempt package removal with proper error capture
    case "$package_manager" in
        dnf|yum)
            removal_output=$(dnf remove -y "$package" 2>&1)
            if [[ $? -ne 0 ]]; then
                removal_success=false
            fi
            ;;
        apt)
            removal_output=$(apt-get remove --purge -y "$package" 2>&1)
            if [[ $? -ne 0 ]]; then
                removal_success=false
            fi
            ;;
        zypper)
            removal_output=$(zypper remove -y "$package" 2>&1)
            if [[ $? -ne 0 ]]; then
                removal_success=false
            fi
            ;;
        pacman)
            removal_output=$(pacman -Rs --noconfirm "$package" 2>&1)
            if [[ $? -ne 0 ]]; then
                removal_success=false
            fi
            ;;
    esac
    
    # Log results properly
    if [[ "$removal_success" == "true" ]]; then
        log "INFO" "Successfully removed package: $package"
        if [[ "$VERBOSE_LOGGING" == true ]]; then
            print_info "Removed: $package"
        fi
    else
        # Check if it's just a common warning vs actual error
        if echo "$removal_output" | grep -qi "No match for\|not installed\|not found"; then
            log "INFO" "Package '$package' was not installed"
        else
            log "WARNING" "Package removal had warnings for '$package': $removal_output"
            print_warning "Warnings during removal of $package (check log for details)"
        fi
    fi
    
    return 0
}

# Remove Fail2ban
remove_fail2ban() {
    print_info "Removing Fail2ban..."
    log "COMPLETION" "Removing Fail2ban"
    
    # Remove configuration files
    if [[ -f /etc/fail2ban/jail.local ]]; then
        rm -f /etc/fail2ban/jail.local
        log "INFO" "Removed Fail2ban configuration: jail.local"
    fi
    
    # Remove package
    local removal_success=true
    case "$PACKAGE_MANAGER" in
        dnf|yum)
            if ! dnf remove -y fail2ban 2>/dev/null; then
                removal_success=false
            fi
            ;;
        apt)
            if ! apt-get remove --purge -y fail2ban 2>/dev/null || ! apt-get autoremove -y 2>/dev/null; then
                removal_success=false
            fi
            ;;
        zypper)
            if ! zypper remove -y fail2ban 2>/dev/null; then
                removal_success=false
            fi
            ;;
        pacman)
            if ! pacman -Rs --noconfirm fail2ban 2>/dev/null; then
                removal_success=false
            fi
            ;;
    esac
    
    if [[ "$removal_success" == true ]]; then
        print_success "Fail2ban removed"
        log "COMPLETION" "Fail2ban removal completed successfully"
    else
        print_warning "Fail2ban removal completed with warnings"
        log "WARNING" "Fail2ban removal completed with some failures"
    fi
}

# Remove user and domain setup
remove_user_and_domain() {
    print_info "Removing user accounts and domain configurations..."
    log "INFO" "Removing user and domain setup"
    
    # Remove virtual host configurations
    case "$PACKAGE_MANAGER" in
        dnf|yum)
            rm -f /etc/httpd/conf.d/*.conf 2>/dev/null || true
            ;;
        apt)
            # Disable and remove all custom sites
            for site in /etc/apache2/sites-available/*.conf; do
                if [[ -f "$site" && "$site" != "/etc/apache2/sites-available/000-default.conf" && "$site" != "/etc/apache2/sites-available/default-ssl.conf" ]]; then
                    sitename=$(basename "$site" .conf)
                    a2dissite "$sitename" 2>/dev/null || true
                    rm -f "$site"
                    log "INFO" "Removed Apache site: $sitename"
                fi
            done
            ;;
        zypper)
            rm -f /etc/apache2/vhosts.d/*.conf 2>/dev/null || true
            ;;
    esac
    
    # Remove users created by the script
    if [[ -n "$USERNAME" ]] && id "$USERNAME" >/dev/null 2>&1; then
        print_info "Removing user: $USERNAME"
        userdel -r "$USERNAME" 2>/dev/null || true
        log "INFO" "User removed: $USERNAME"
    fi
    
    # Look for users with public_html directories (likely created by script)
    for user_home in /home/*/public_html; do
        if [[ -d "$user_home" ]]; then
            local username=$(basename "$(dirname "$user_home")")
            if [[ "$username" != "root" && "$username" != "." && "$username" != ".." ]]; then
                print_info "Found user with public_html: $username"
                if [[ "$NON_INTERACTIVE" == "true" ]]; then
                    # In non-interactive mode, auto-remove users with public_html (likely script-created)
                    print_info "Auto-removing user $username (non-interactive mode)"
                    log "INFO" "Auto-removing user $username (non-interactive mode)"
                    userdel -r "$username" 2>/dev/null || true
                    log "INFO" "User removed: $username"
                else
                    read -p "Remove user $username? (y/N): " -r
                    if [[ $REPLY =~ ^[Yy]$ ]]; then
                        userdel -r "$username" 2>/dev/null || true
                        log "INFO" "User removed: $username"
                    fi
                fi
            fi
        fi
    done
    
    print_success "User and domain cleanup completed"
}

# Remove PHP
remove_php() {
    print_info "Starting PHP removal..."
    log "INFO" "Removing PHP"
    
    case "$PACKAGE_MANAGER" in
        dnf|yum)
            print_info "Removing PHP packages via $PACKAGE_MANAGER..."
            # Reset PHP module
            dnf module reset php -y 2>/dev/null || true
            
            # Remove standard PHP packages (single version installs)
            local php_packages=(
                "php" "php-cli" "php-fpm" "php-common" "php-mysql" "php-xml" 
                "php-json" "php-curl" "php-mbstring" "php-zip" "php-gd" 
                "php-intl" "php-opcache"
            )
            
            for package in "${php_packages[@]}"; do
                safe_package_remove "$package" "$PACKAGE_MANAGER"
            done
            
            # Remove SCL PHP packages (multiple version installs)
            local php_versions=("82" "83" "84")
            for version in "${php_versions[@]}"; do
                if [[ "$VERBOSE_LOGGING" == true ]]; then
                    print_info "Removing PHP $version SCL packages..."
                fi
                local scl_packages=(
                    "php$version" "php$version-php-cli" "php$version-php-fpm" "php$version-php-common"
                    "php$version-php-mysqlnd" "php$version-php-xml" "php$version-php-curl" 
                    "php$version-php-mbstring" "php$version-php-zip" "php$version-php-gd" 
                    "php$version-php-intl" "php$version-php-opcache"
                )
                
                for package in "${scl_packages[@]}"; do
                    safe_package_remove "$package" "$PACKAGE_MANAGER"
                done
            done
            ;;
        apt)
            print_info "Removing PHP packages via $PACKAGE_MANAGER..."
            # Remove all PHP versions
            local php_versions=("8.2" "8.3" "8.4")
            for version in "${php_versions[@]}"; do
                print_info "Removing PHP $version..."
                local php_packages=(
                    "php$version" "php$version-cli" "php$version-fpm" "php$version-common"
                    "php$version-mysql" "php$version-xml" "php$version-curl" "php$version-mbstring"
                    "php$version-zip" "php$version-gd" "php$version-intl" "php$version-opcache"
                )
                
                for package in "${php_packages[@]}"; do
                    apt-get remove --purge -y "$package" 2>/dev/null || true
                done
            done
            
            # Remove PHP common packages
            apt-get remove --purge -y php-common 2>/dev/null || true
            apt-get autoremove -y 2>/dev/null || true
            ;;
        zypper)
            print_info "Removing PHP packages via $PACKAGE_MANAGER..."
            # Remove PHP packages
            zypper remove -y php82* php83* php84* 2>/dev/null || true
            ;;
        pacman)
            print_info "Removing PHP packages via $PACKAGE_MANAGER..."
            pacman -Rs --noconfirm php php-fpm 2>/dev/null || true
            ;;
        *)
            print_warning "Unknown package manager: $PACKAGE_MANAGER"
            ;;
    esac
    
    # Remove PHP configuration directories
    rm -rf /etc/php* 2>/dev/null || true
    
    # Remove Remi SCL directories (for multiple PHP versions)
    rm -rf /opt/remi/php82* 2>/dev/null || true
    rm -rf /opt/remi/php83* 2>/dev/null || true
    rm -rf /opt/remi/php84* 2>/dev/null || true
    # Remove empty remi directory if no other SCL packages remain
    rmdir /opt/remi 2>/dev/null || true
    
    # Remove PHP symlink if it exists
    rm -f /usr/local/bin/php 2>/dev/null || true
    
    print_success "PHP removed"
    log "INFO" "PHP removal completed"
}

# Remove essential tools
remove_essential_tools() {
    print_info "Starting essential tools removal..."
    log "INFO" "Removing essential tools"
    
    case "$PACKAGE_MANAGER" in
        dnf)
            # Remove essential tools packages
            for package in curl wget net-tools nmap-ncat atop; do
                if rpm -q "$package" >/dev/null 2>&1; then
                    print_info "Removing essential tool: $package"
                    dnf remove -y "$package" >/dev/null 2>&1 || true
                    log "INFO" "Removed essential tool: $package"
                fi
            done
            ;;
        yum)
            # Remove essential tools packages
            for package in curl wget net-tools nmap-ncat atop; do
                if rpm -q "$package" >/dev/null 2>&1; then
                    print_info "Removing essential tool: $package"
                    yum remove -y "$package" >/dev/null 2>&1 || true
                    log "INFO" "Removed essential tool: $package"
                fi
            done
            ;;
        apt)
            # Remove essential tools packages
            for package in curl wget net-tools netcat-openbsd atop; do
                if dpkg -l "$package" 2>/dev/null | grep -q "^ii"; then
                    print_info "Removing essential tool: $package"
                    apt-get remove --purge -y "$package" >/dev/null 2>&1 || true
                    log "INFO" "Removed essential tool: $package"
                fi
            done
            ;;
        zypper)
            # Remove essential tools packages
            for package in curl wget net-tools netcat-openbsd atop; do
                if zypper se -i "$package" >/dev/null 2>&1; then
                    print_info "Removing essential tool: $package"
                    zypper remove -y "$package" >/dev/null 2>&1 || true
                    log "INFO" "Removed essential tool: $package"
                fi
            done
            ;;
        pacman)
            # Remove essential tools packages
            for package in curl wget net-tools gnu-netcat atop; do
                if pacman -Q "$package" >/dev/null 2>&1; then
                    print_info "Removing essential tool: $package"
                    pacman -R --noconfirm "$package" >/dev/null 2>&1 || true
                    log "INFO" "Removed essential tool: $package"
                fi
            done
            ;;
        *)
            print_warning "Unknown package manager: $PACKAGE_MANAGER"
            log "WARNING" "Unknown package manager for essential tools removal: $PACKAGE_MANAGER"
            ;;
    esac
    
    print_success "Essential tools removal completed"
    log "INFO" "Essential tools removal completed"
}

# Remove package managers
remove_package_managers() {
    print_info "Starting package managers removal..."
    log "INFO" "Removing package managers"
    
    # Remove Composer
    if [[ -f "/usr/local/bin/composer" ]]; then
        print_info "Removing Composer..."
        rm -f "/usr/local/bin/composer"
        print_success "Composer removed"
        log "INFO" "Composer removed from /usr/local/bin/composer"
    fi
    
    # Remove Node.js and npm
    case "$PACKAGE_MANAGER" in
        dnf|yum)
            print_info "Removing Node.js and npm via $PACKAGE_MANAGER..."
            dnf remove -y nodejs npm 2>/dev/null || true
            ;;
        apt)
            print_info "Removing Node.js and npm via $PACKAGE_MANAGER..."
            apt-get remove -y nodejs npm 2>/dev/null || true
            apt-get autoremove -y 2>/dev/null || true
            ;;
        zypper)
            print_info "Removing Node.js and npm via $PACKAGE_MANAGER..."
            zypper remove -y nodejs npm 2>/dev/null || true
            ;;
        pacman)
            print_info "Removing Node.js and npm via $PACKAGE_MANAGER..."
            pacman -Rns --noconfirm nodejs npm 2>/dev/null || true
            ;;
    esac
    
    # Clean up user-specific configuration directories
    print_info "Cleaning up package manager configuration..."
    
    # Remove Composer global directories
    for user_home in /home/*; do
        if [[ -d "$user_home" && -d "$user_home/.composer" ]]; then
            print_info "Removing Composer config for $(basename "$user_home")"
            rm -rf "$user_home/.composer"
        fi
        # Clean up npm global directories
        if [[ -d "$user_home" && -d "$user_home/.npm-global" ]]; then
            print_info "Removing npm global config for $(basename "$user_home")"
            rm -rf "$user_home/.npm-global"
        fi
        # Remove npm cache
        if [[ -d "$user_home" && -d "$user_home/.npm" ]]; then
            print_info "Removing npm cache for $(basename "$user_home")"
            rm -rf "$user_home/.npm"
        fi
    done
    
    # Remove global npm cache
    rm -rf /root/.npm 2>/dev/null || true
    rm -rf /root/.npm-global 2>/dev/null || true
    rm -rf /root/.composer 2>/dev/null || true
    
    print_success "Package managers removed"
    log "INFO" "Package managers removal completed"
}

# Remove development tools
remove_development_tools() {
    print_info "Starting development tools removal..."
    log "INFO" "Removing development tools"
    
    # Remove Git
    case "$PACKAGE_MANAGER" in
        dnf|yum)
            print_info "Removing Git via $PACKAGE_MANAGER..."
            dnf remove -y git 2>/dev/null || true
            ;;
        apt)
            print_info "Removing Git via $PACKAGE_MANAGER..."
            apt-get remove -y git 2>/dev/null || true
            ;;
        zypper)
            print_info "Removing Git via $PACKAGE_MANAGER..."
            zypper remove -y git 2>/dev/null || true
            ;;
        pacman)
            print_info "Removing Git via $PACKAGE_MANAGER..."
            pacman -Rns --noconfirm git 2>/dev/null || true
            ;;
    esac
    
    # Remove GitHub CLI
    case "$PACKAGE_MANAGER" in
        dnf|yum)
            print_info "Removing GitHub CLI via $PACKAGE_MANAGER..."
            dnf remove -y gh 2>/dev/null || true
            # Remove repository
            rm -f /etc/yum.repos.d/gh-cli.repo 2>/dev/null || true
            ;;
        apt)
            print_info "Removing GitHub CLI via $PACKAGE_MANAGER..."
            apt-get remove -y gh 2>/dev/null || true
            # Remove repository and keyring
            rm -f /etc/apt/sources.list.d/github-cli.list 2>/dev/null || true
            rm -f /usr/share/keyrings/githubcli-archive-keyring.gpg 2>/dev/null || true
            ;;
        zypper)
            print_info "Removing GitHub CLI via $PACKAGE_MANAGER..."
            zypper remove -y gh 2>/dev/null || true
            # Remove repository
            zypper removerepo gh-cli 2>/dev/null || true
            ;;
        pacman)
            print_info "Removing GitHub CLI via $PACKAGE_MANAGER..."
            pacman -Rns --noconfirm github-cli 2>/dev/null || true
            ;;
    esac
    
    
    # Clean up configuration files
    print_info "Cleaning up development tools configuration..."
    
    # Remove global Git configuration and templates
    rm -f /etc/gitignore 2>/dev/null || true
    rm -rf /etc/skel/.gitconfig 2>/dev/null || true
    
    # Clean up user-specific Git and GitHub CLI configuration
    for user_home in /home/*; do
        if [[ -d "$user_home" ]]; then
            local username=$(basename "$user_home")
            print_info "Removing development tools config for $username"
            # Remove Git configuration
            sudo -u "$username" git config --global --unset-all init.defaultBranch 2>/dev/null || true
            sudo -u "$username" git config --global --unset-all pull.rebase 2>/dev/null || true
            sudo -u "$username" git config --global --unset-all core.excludesfile 2>/dev/null || true
            # Remove GitHub CLI configuration
            rm -rf "$user_home/.config/gh" 2>/dev/null || true
        fi
    done
    
    # Remove root Git and GitHub CLI configuration
    rm -rf /root/.config/gh 2>/dev/null || true
    rm -f /root/.gitconfig 2>/dev/null || true
    
    print_success "Development tools removed"
    log "INFO" "Development tools removal completed"
}

# Database-specific removal functions
remove_mysql_packages() {
    case "$PACKAGE_MANAGER" in
        dnf|yum)
            dnf remove -y mysql-server mysql 2>/dev/null || true
            ;;
        apt)
            apt-get remove --purge -y mysql-server mysql-client mysql-common 2>/dev/null || true
            ;;
        zypper)
            zypper remove -y mysql mysql-server 2>/dev/null || true
            ;;
        pacman)
            pacman -Rs --noconfirm mysql 2>/dev/null || true
            ;;
    esac
}

remove_mysql_data() {
    # Stop all MySQL services (different names on different systems)
    systemctl stop mysqld 2>/dev/null || true
    systemctl stop mysql 2>/dev/null || true
    systemctl stop mariadb 2>/dev/null || true
    
    # Remove data directories (both common locations)
    rm -rf /var/lib/mysql* 2>/dev/null || true
    rm -rf /var/lib/mysqld* 2>/dev/null || true
    
    # Remove configuration files and credentials
    rm -f /root/.my.cnf 2>/dev/null || true
    rm -rf /etc/mysql* 2>/dev/null || true
    rm -rf /etc/mysqld* 2>/dev/null || true
    
    # Remove any socket files
    rm -f /var/run/mysqld/mysqld.sock 2>/dev/null || true
    rm -f /run/mysqld/mysqld.sock 2>/dev/null || true
    rm -f /tmp/mysql.sock 2>/dev/null || true
    
    # Remove log files that might cause issues
    rm -f /var/log/mysqld.log 2>/dev/null || true
    rm -f /var/log/mysql.log 2>/dev/null || true
    
    print_success "MySQL data and configuration removed"
    log "INFO" "MySQL data directories and configuration files removed"
}

remove_mariadb_packages() {
    case "$PACKAGE_MANAGER" in
        dnf|yum)
            dnf remove -y mariadb-server mariadb 2>/dev/null || true
            ;;
        apt)
            apt-get remove --purge -y mariadb-server mariadb-client mariadb-common 2>/dev/null || true
            ;;
        zypper)
            zypper remove -y mariadb mariadb-server 2>/dev/null || true
            ;;
        pacman)
            pacman -Rs --noconfirm mariadb 2>/dev/null || true
            ;;
    esac
}

remove_mariadb_data() {
    # Stop all MariaDB services
    systemctl stop mariadb 2>/dev/null || true
    systemctl stop mysql 2>/dev/null || true
    systemctl stop mysqld 2>/dev/null || true
    
    # Remove data directories (both common locations)
    rm -rf /var/lib/mysql* 2>/dev/null || true
    rm -rf /var/lib/mariadb* 2>/dev/null || true
    
    # Remove configuration files and credentials
    rm -f /root/.my.cnf 2>/dev/null || true
    rm -rf /etc/mysql* 2>/dev/null || true
    rm -rf /etc/mariadb* 2>/dev/null || true
    
    # Remove any socket files
    rm -f /var/run/mysqld/mysqld.sock 2>/dev/null || true
    rm -f /run/mysqld/mysqld.sock 2>/dev/null || true
    
    print_success "MariaDB data and configuration removed"
    log "INFO" "MariaDB data directories and configuration files removed"
}

remove_postgresql_packages() {
    case "$PACKAGE_MANAGER" in
        dnf|yum)
            dnf remove -y postgresql-server postgresql-contrib postgresql 2>/dev/null || true
            ;;
        apt)
            apt-get remove --purge -y postgresql postgresql-contrib postgresql-client 2>/dev/null || true
            ;;
        zypper)
            zypper remove -y postgresql-server postgresql-contrib postgresql 2>/dev/null || true
            ;;
        pacman)
            pacman -Rs --noconfirm postgresql 2>/dev/null || true
            ;;
    esac
}

remove_postgresql_data() {
    # Stop all PostgreSQL services (different names on different systems)
    systemctl stop postgresql 2>/dev/null || true
    systemctl stop postgresql-16 2>/dev/null || true
    systemctl stop postgresql-15 2>/dev/null || true
    systemctl stop postgresql-14 2>/dev/null || true
    systemctl stop postgresql-13 2>/dev/null || true
    
    # Remove data directories (multiple possible locations)
    rm -rf /var/lib/pgsql* 2>/dev/null || true
    rm -rf /var/lib/postgres* 2>/dev/null || true
    rm -rf /var/lib/postgresql* 2>/dev/null || true
    
    # Remove configuration files
    rm -rf /etc/postgresql* 2>/dev/null || true
    rm -f /root/postgresql-info.txt 2>/dev/null || true
    
    # Remove socket files
    rm -f /var/run/postgresql/.s.PGSQL.* 2>/dev/null || true
    rm -f /tmp/.s.PGSQL.* 2>/dev/null || true
    
    # Remove log files that might cause issues
    rm -f /var/log/postgresql* 2>/dev/null || true
    
    print_success "PostgreSQL data and configuration removed"
    log "INFO" "PostgreSQL data directories and configuration files removed"
}

remove_sqlite_packages() {
    case "$PACKAGE_MANAGER" in
        dnf|yum)
            dnf remove -y sqlite 2>/dev/null || true
            ;;
        apt)
            apt-get remove --purge -y sqlite3 2>/dev/null || true
            ;;
        zypper)
            zypper remove -y sqlite3 2>/dev/null || true
            ;;
        pacman)
            pacman -Rs --noconfirm sqlite 2>/dev/null || true
            ;;
    esac
}

remove_sqlite_data() {
    rm -rf /var/lib/sqlite* 2>/dev/null || true
    rm -f /root/sqlite-info.txt 2>/dev/null || true
}

# Remove database
remove_database() {
    log "INFO" "Starting database removal"
    
    # Load list of installed databases
    local installed_databases=()
    if [[ -f "/root/.installed_databases" ]]; then
        while IFS= read -r database; do
            installed_databases+=("$database")
        done < "/root/.installed_databases"
        log "INFO" "Found installed databases: ${installed_databases[*]}"
    else
        print_warning "No database installation tracking found - performing comprehensive cleanup"
        log "WARNING" "No .installed_databases file found - doing full cleanup"
        installed_databases=("mysql" "mariadb" "postgresql" "sqlite")
    fi
    
    if [[ ${#installed_databases[@]} -eq 0 ]]; then
        log "INFO" "No databases to remove"
        return 0
    fi
    
    # Remove each installed database
    for database in "${installed_databases[@]}"; do
        case "$database" in
            mysql)
                print_info "Removing MySQL..."
                remove_mysql_packages
                remove_mysql_data
                ;;
            mariadb)
                print_info "Removing MariaDB..."
                remove_mariadb_packages
                remove_mariadb_data
                ;;
            postgresql)
                print_info "Removing PostgreSQL..."
                remove_postgresql_packages
                remove_postgresql_data
                ;;
            sqlite)
                print_info "Removing SQLite..."
                remove_sqlite_packages
                remove_sqlite_data
                ;;
            *)
                print_warning "Unknown database type: $database"
                log "WARNING" "Unknown database type in tracking file: $database"
                ;;
        esac
    done
    
    # Clean up any remaining packages (APT only)
    if [[ "$PACKAGE_MANAGER" == "apt" ]]; then
        apt-get autoremove -y 2>/dev/null || true
    fi
    
    # Remove tracking file
    rm -f /root/.installed_databases 2>/dev/null || true
    
    log "INFO" "Database removal completed"
}

# Remove web server
remove_webserver() {
    print_info "Starting web server removal..."
    log "INFO" "Removing web server"
    
    case "$PACKAGE_MANAGER" in
        dnf|yum)
            print_info "Removing web server packages via $PACKAGE_MANAGER..."
            # Remove Apache packages
            safe_package_remove "httpd" "$PACKAGE_MANAGER"
            safe_package_remove "httpd-tools" "$PACKAGE_MANAGER"
            # Remove Nginx packages
            safe_package_remove "nginx" "$PACKAGE_MANAGER"
            ;;
        apt)
            print_info "Removing web server packages via $PACKAGE_MANAGER..."
            # Remove Apache packages
            safe_package_remove "apache2" "$PACKAGE_MANAGER"
            safe_package_remove "apache2-utils" "$PACKAGE_MANAGER"
            safe_package_remove "apache2-bin" "$PACKAGE_MANAGER"
            safe_package_remove "apache2-data" "$PACKAGE_MANAGER"
            # Remove Nginx packages
            safe_package_remove "nginx" "$PACKAGE_MANAGER"
            safe_package_remove "nginx-common" "$PACKAGE_MANAGER"
            safe_package_remove "nginx-core" "$PACKAGE_MANAGER"
            # Clean up orphaned packages
            if apt-get autoremove -y >/dev/null 2>&1; then
                log "INFO" "Cleaned up orphaned packages"
            fi
            ;;
        zypper)
            print_info "Removing web server packages via $PACKAGE_MANAGER..."
            safe_package_remove "apache2" "$PACKAGE_MANAGER"
            safe_package_remove "nginx" "$PACKAGE_MANAGER"
            ;;
        pacman)
            print_info "Removing web server packages via $PACKAGE_MANAGER..."
            safe_package_remove "apache" "$PACKAGE_MANAGER"
            safe_package_remove "nginx" "$PACKAGE_MANAGER"
            ;;
        *)
            print_warning "Unknown package manager: $PACKAGE_MANAGER"
            log "WARNING" "Unknown package manager: $PACKAGE_MANAGER"
            ;;
    esac
    
    # Remove web server configuration directories
    rm -rf /etc/httpd* 2>/dev/null || true
    rm -rf /etc/apache2* 2>/dev/null || true
    rm -rf /etc/nginx* 2>/dev/null || true
    
    # Remove web server data directories
    rm -rf /var/www* 2>/dev/null || true
    rm -rf /var/log/httpd* 2>/dev/null || true
    rm -rf /var/log/apache2* 2>/dev/null || true
    rm -rf /var/log/nginx* 2>/dev/null || true
    
    print_success "Web server removed"
    log "INFO" "Web server removal completed"
}

# Remove repositories
remove_repositories() {
    log "INFO" "Removing repositories"
    
    case "$PACKAGE_MANAGER" in
        dnf|yum)
            # Remove Remi repository using safe package removal
            safe_package_remove "remi-release" "$PACKAGE_MANAGER"
            # Note: We don't remove EPEL as it might be used by other software
            ;;
        apt)
            # Remove Ondrej PHP repository
            if add-apt-repository --remove -y ppa:ondrej/php >/dev/null 2>&1; then
                log "INFO" "Removed Ondrej PHP repository"
            else
                log "INFO" "Ondrej PHP repository was not installed"
            fi
            if apt-get update >/dev/null 2>&1; then
                log "INFO" "Updated package lists after repository removal"
            fi
            ;;
        zypper)
            # Remove any added repositories
            if zypper removerepo php >/dev/null 2>&1; then
                log "INFO" "Removed PHP repository"
            else
                log "INFO" "PHP repository was not configured"
            fi
            ;;
    esac
    
    log "INFO" "Repository cleanup completed"
}

# Clean up firewall rules
cleanup_firewall() {
    log "INFO" "Cleaning up firewall"
    
    if command -v firewall-cmd >/dev/null 2>&1; then
        # Remove HTTP/HTTPS services
        firewall-cmd --permanent --remove-service=http 2>/dev/null || true
        firewall-cmd --permanent --remove-service=https 2>/dev/null || true
        
        # Remove user IP whitelist rule if it exists
        if [[ -n "$USER_IP" ]]; then
            firewall-cmd --permanent --remove-rich-rule="rule family='ipv4' source address='$USER_IP' accept" 2>/dev/null || true
        fi
        
        firewall-cmd --reload 2>/dev/null || true
        # Status captured for removal banner
        
    elif command -v ufw >/dev/null 2>&1; then
        # Remove Apache rules
        ufw delete allow 'Apache Full' 2>/dev/null || true
        ufw delete allow 'Apache' 2>/dev/null || true
        
        # Remove user IP rule if it exists
        if [[ -n "$USER_IP" ]]; then
            ufw delete allow from "$USER_IP" 2>/dev/null || true
        fi
        
        # Status captured for removal banner
    fi
    
    log "INFO" "Firewall cleanup completed"
}

# Final cleanup
final_cleanup() {
    log "INFO" "Final cleanup"
    
    # Clean package cache
    case "$PACKAGE_MANAGER" in
        dnf)
            dnf clean all 2>/dev/null || true
            ;;
        yum)
            yum clean all 2>/dev/null || true
            ;;
        apt)
            apt-get autoclean 2>/dev/null || true
            apt-get autoremove -y 2>/dev/null || true
            ;;
        zypper)
            zypper clean 2>/dev/null || true
            ;;
        pacman)
            pacman -Sc --noconfirm 2>/dev/null || true
            ;;
    esac
    
    # Remove any leftover configuration files
    rm -f /etc/fail2ban/jail.local 2>/dev/null || true
    
    # Remove temporary files
    rm -f /tmp/install-* 2>/dev/null || true
    
    # Remove installation log files (keeping only removal logs)
    rm -f "${SCRIPT_DIR}"/install-log-*.log 2>/dev/null || true
    
    # Clear bash command cache to prevent stale command locations
    hash -r 2>/dev/null || true
    
    log "INFO" "Final cleanup completed"
}

# Main function
main() {
    # Parse command line arguments
    # Check for non-interactive mode and auto preset flag first
    for arg in "$@"; do
        if [[ "$arg" == "--auto" ]]; then
            AUTO_PRESET=true
        elif [[ "$arg" == "--non-interactive" ]]; then
            if [[ -f "./setup-noninteractive.sh" ]]; then
                source "./setup-noninteractive.sh"
                parse_noninteractive_args "$@"
                check_early_nothing_to_install
                break
            else
                print_error "Non-interactive mode requires setup-noninteractive.sh"
                exit 1
            fi
        fi
    done
    
    # If --auto was detected with a preset, enable non-interactive mode
    for arg in "$@"; do
        if [[ "$arg" =~ ^--preset= && "$AUTO_PRESET" == "true" ]]; then
            if [[ -f "./setup-noninteractive.sh" ]]; then
                source "./setup-noninteractive.sh"
                NON_INTERACTIVE=true
                break
            else
                print_error "Auto preset mode requires setup-noninteractive.sh"
                exit 1
            fi
        fi
    done
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            --ssh-client-ip=*)
                # Extract SSH client IP passed from non-sudo execution
                DETECTED_SSH_CLIENT_IP="${1#*=}"
                log "INFO" "SSH client IP provided via parameter: $DETECTED_SSH_CLIENT_IP"
                ;;
            --remove)
                # Check if verbose flag was also provided
                if [[ "${2:-}" == "--verbose" || "${2:-}" == "-v" ]]; then
                    VERBOSE_LOGGING=true
                    shift
                fi
                remove_installation
                ;;
            --verbose|-v)
                VERBOSE_LOGGING=true
                # Check if remove flag follows
                if [[ "${2:-}" == "--remove" ]]; then
                    shift
                    remove_installation
                fi
                shift
                ;;
            --auto)
                # Enable auto-proceed for presets (skip confirmation)
                AUTO_PRESET=true
                shift
                ;;
            --help|-h)
                echo ""
                echo -e "   ${BLUE}Multi-OS Web Stack Builder Setup${NC}"
                echo ""
                echo "   A comprehensive script for installing complete web development stacks"
                echo "   across RHEL, Debian, SUSE, and Arch Linux distributions with security hardening."
                echo ""
                echo "   Usage: sudo $0 [options]"
                echo ""
                echo -e "   ${BLUE}Quick Preset Options:${NC}"
                echo "     --preset=lamp         Apache + MySQL + PHP 8.3 + Composer + Git"
                echo "     --preset=lemp         Nginx + MySQL + PHP 8.3 + Composer + Git"
                echo "     --preset=minimal      Apache + MySQL"
                echo "     --preset=full         Everything with sensible defaults"
                echo "     --auto                Auto-proceed with presets (skip confirmation prompt)"
                echo ""
                echo -e "   ${BLUE}Interactive Mode Options:${NC}"
                echo "     --remove              Remove all installed components"
                echo "     --verbose, -v         Enable verbose logging"
                echo "     --remove --verbose    Remove with detailed logging"
                echo "     --help, -h            Show this help message"
                echo "     --list-options        Show all available component values for non-interactive mode"
                echo ""
                echo -e "   ${BLUE}Non-Interactive Mode Options:${NC}"
                echo "     --non-interactive                 Enable non-interactive mode"
                echo "     --skip                            Skip unspecified components (default to 'none')"
                echo "     --list-options                    Show all available component values"
                echo "     --webserver=apache|nginx|none     Select web server"
                echo "     --database=mysql,mariadb,postgresql,sqlite,none"
                echo "                                       Select databases (comma-separated)"
                echo "     --php=8.2,8.3,8.4                Select PHP versions (comma-separated, can install multiple)"
                echo "     --php-default=8.2                 optional. If used sets default PHP version. If not, first PHP version installed is default"
                echo "     --package-managers=composer,nodejs,none"
                echo "                                       Select package managers (comma-separated)"
                echo "     --dev-tools=git,github-cli,claude,none"
                echo "                                       Select development tools (comma-separated)"
                echo "     --domain=example.com              Domain name for virtual host"
                echo "     --username=webuser                Username for domain setup: start with letter/underscore,"
                echo "                                       lowercase letters/numbers/underscore/dash only, 3-32 chars, cannot be existing user"
                echo ""
                echo -e "   ${BLUE}Non-Interactive Examples:${NC}"
                echo ""
                echo -e "     ${BLUE}# Quick presets (easiest way to get started)${NC}"
                echo "     sudo $0 --preset=lamp                # Apache, PHP 8.3, MySQL, Composer, git, Fail2ban, Firewall config"
                echo "     sudo $0 --preset=lamp --auto         # Apache, PHP 8.3, MySQL, Composer, git, Fail2ban, Firewall config - Auto-Install"
                echo "     sudo $0 --preset=lemp                # Nginx, PHP 8.3, MySQL, Composer, git, Fail2ban, Firewall config"
                echo "     sudo $0 --preset=minimal             # Apache, MySQL, Fail2ban, Firewall config"
                echo ""
                echo -e "     ${BLUE}# Minimal installation${NC}"
                echo "     sudo $0 --non-interactive --webserver=nginx --skip"
                echo ""
                echo -e "     ${BLUE}# Single PHP version (becomes default automatically)${NC}"
                echo "     sudo $0 --non-interactive --webserver=apache --database=mysql --php=8.2"
                echo ""
                echo -e "     ${BLUE}# Multiple PHP versions, explicit default (8.3 becomes default)${NC}"
                echo "     sudo $0 --non-interactive --webserver=nginx --database=postgresql,sqlite \\"
                echo "       --php=8.2,8.3,8.4 --php-default=8.3"
                echo ""
                echo -e "     ${BLUE}# Multiple PHP versions, first becomes default (8.2 becomes default)${NC}"
                echo "     sudo $0 --non-interactive --webserver=apache --database=mysql \\"
                echo "       --php=8.2,8.3"
                echo ""
                echo -e "     ${BLUE}# Development environment with domain${NC}"
                echo "     sudo $0 --non-interactive --webserver=nginx --database=mysql --php=8.4 \\"
                echo "       --package-managers=composer,nodejs --dev-tools=git,claude \\"
                echo "       --domain=dev.local --username=developer"
                echo ""
                exit 0
                ;;
            --list-options)
                echo "Available Components for Non-Interactive Mode:"
                echo ""
                echo "Presets (easiest option):"
                echo "  lamp, lemp, minimal, full"
                echo ""
                echo "Web Servers:"
                echo "  apache, nginx, none"
                echo ""
                echo "Databases:"
                echo "  mysql, mariadb, postgresql, sqlite, mongodb, redis, none"
                echo ""
                echo "PHP Versions:"
                echo "  8.2, 8.3, 8.4, none"
                echo ""
                echo "Package Managers:"
                echo "  composer, nodejs, none"
                echo ""
                echo "Development Tools:"
                echo "  git, github-cli, claude, none"
                echo ""
                echo "Usage Examples:"
                echo "  --preset=lamp                     (recommended for beginners)"
                echo "  --webserver=nginx"
                echo "  --database=mysql,postgresql       (multiple allowed)"
                echo "  --php=8.2,8.3,8.4                (multiple allowed)"
                echo "  --php-default=8.3                 (must be in selected versions)"
                echo "  --package-managers=composer,nodejs"
                echo "  --dev-tools=git,claude"
                echo ""
                exit 0
                ;;
            --preset=*)
                # Handle preset configurations
                PRESET="${1#*=}"
                case "$PRESET" in
                    lamp)
                        SELECTED_WEBSERVER="apache"
                        SELECTED_DATABASES=("mysql")
                        SELECTED_PHP_VERSIONS=("8.3")
                        DEFAULT_PHP_VERSION="8.3"
                        SELECTED_PACKAGE_MANAGERS=("composer")
                        SELECTED_DEVELOPMENT_TOOLS=("git")
                        PRESET_MODE=true
                        # Initialize required setup steps (preset mode)
                        check_root
                        detect_os_preset
                        get_user_ip_preset
                        # Show preset installation summary
                        show_preset_installation_summary "LAMP"
                        # Run installations directly
                        run_installations
                        # Run validations
                        run_validations
                        exit 0
                        ;;
                    lemp)
                        SELECTED_WEBSERVER="nginx"
                        SELECTED_DATABASES=("mysql")
                        SELECTED_PHP_VERSIONS=("8.3")
                        DEFAULT_PHP_VERSION="8.3"
                        SELECTED_PACKAGE_MANAGERS=("composer")
                        SELECTED_DEVELOPMENT_TOOLS=("git")
                        PRESET_MODE=true
                        # Initialize required setup steps (preset mode)
                        check_root
                        detect_os_preset
                        get_user_ip_preset
                        # Show preset installation summary
                        show_preset_installation_summary "LEMP"
                        # Run installations directly
                        run_installations
                        # Run validations
                        run_validations
                        exit 0
                        ;;
                    minimal)
                        SELECTED_WEBSERVER="apache"
                        SELECTED_DATABASES=("mysql")
                        SELECTED_PHP_VERSIONS=("none")
                        SELECTED_PACKAGE_MANAGERS=("none")
                        SELECTED_DEVELOPMENT_TOOLS=("none")
                        PRESET_MODE=true
                        # Initialize required setup steps (preset mode)
                        check_root
                        detect_os_preset
                        get_user_ip_preset
                        # Show preset installation summary
                        show_preset_installation_summary "Minimal"
                        # Run installations directly
                        run_installations
                        # Run validations
                        run_validations
                        exit 0
                        ;;
                    full)
                        SELECTED_WEBSERVER="nginx"
                        SELECTED_DATABASES=("mysql" "postgresql")
                        SELECTED_PHP_VERSIONS=("8.2" "8.3")
                        DEFAULT_PHP_VERSION="8.3"
                        SELECTED_PACKAGE_MANAGERS=("composer" "nodejs")
                        SELECTED_DEVELOPMENT_TOOLS=("git" "claude")
                        PRESET_MODE=true
                        # Initialize required setup steps (preset mode)
                        check_root
                        detect_os_preset
                        get_user_ip_preset
                        # Show preset installation summary
                        show_preset_installation_summary "Full"
                        # Run installations directly
                        run_installations
                        # Run validations
                        run_validations
                        exit 0
                        ;;
                    *)
                        print_error "Unknown preset: $PRESET"
                        echo "Available presets: lamp, lemp, minimal, full"
                        echo "Use --help for details"
                        exit 1
                        ;;
                esac
                ;;
            --non-interactive|--skip|--list-options|--webserver=*|--database=*|--php=*|--php-default=*|--package-managers=*|--dev-tools=*|--domain=*|--username=*)
                # Non-interactive arguments are handled earlier, just shift here
                shift
                ;;
            *)
                print_error "Unknown option: $1"
                echo "Use --help for usage information"
                exit 1
                ;;
        esac
    done
    
    # Initialize log file only for installation (not removal)
    if [[ -z "$LOG_FILE" ]]; then
        # Clean up old install log files before creating new one
        rm -f "${SCRIPT_DIR}"/install-log-*.log 2>/dev/null || true
        LOG_FILE="${SCRIPT_DIR}/install-log-$(date +%Y%m%d-%H%M%S).log"
        touch "$LOG_FILE"
    fi
    
    # Main installation flow
    if command -v safe_welcome_user >/dev/null 2>&1; then
        safe_welcome_user
    else
        welcome_user
    fi
    check_root
    
    if command -v safe_detect_os >/dev/null 2>&1; then
        safe_detect_os
    else
        detect_os
    fi
    
    # Show non-interactive status summary with IP detection if in non-interactive mode
    if command -v show_noninteractive_status >/dev/null 2>&1; then
        show_noninteractive_status
    fi
    
    if command -v safe_check_vpn >/dev/null 2>&1; then
        safe_check_vpn
    else
        check_vpn
    fi
    
    if command -v safe_get_user_ip >/dev/null 2>&1; then
        safe_get_user_ip
    else
        get_user_ip
    fi
    
    # Use safe wrapper functions that support non-interactive mode
    if command -v safe_ask_domain_setup >/dev/null 2>&1; then
        safe_ask_domain_setup
    else
        ask_domain_setup
    fi
    
    if command -v safe_choose_webserver >/dev/null 2>&1; then
        safe_choose_webserver
    else
        choose_webserver
    fi
    
    if command -v safe_choose_database >/dev/null 2>&1; then
        safe_choose_database
    else
        choose_database
    fi
    
    if command -v safe_choose_php_versions >/dev/null 2>&1; then
        safe_choose_php_versions
    else
        choose_php_versions
    fi
    
    if command -v safe_choose_package_managers >/dev/null 2>&1; then
        safe_choose_package_managers
    else
        choose_package_managers
    fi
    
    if command -v safe_choose_development_tools >/dev/null 2>&1; then
        safe_choose_development_tools
    else
        choose_development_tools
    fi
    
    if command -v safe_show_installation_summary >/dev/null 2>&1; then
        safe_show_installation_summary
    else
        show_installation_summary
    fi
    
    # Run the actual installations
    run_installations
    
    # Validate installations
    if run_validations; then
        echo ""
        echo -e "${BLUE}===========================================================================${NC}"
        echo -e "${WHITE}                  INSTALLATION COMPLETED SUCCESSFULLY${NC}"
        echo -e "${BLUE}===========================================================================${NC}"
        echo ""
        
        log "COMPLETION" "Installation completed successfully"
        
        if [[ "$CREATE_USER" == true ]]; then
            echo -e "   ${LIGHT_GREY}[INFO]${NC} Domain Setup:"
            echo "     • Domain: $DOMAIN_NAME"
            echo "     • User: $USERNAME"
            echo "     • Web Directory: /home/$USERNAME/public_html"
            echo "     • Test Page: http://$DOMAIN_NAME or http://$(hostname -I | awk '{print $1}')"
            echo ""
            log "COMPLETION" "Domain setup - Domain: $DOMAIN_NAME, User: $USERNAME"
        fi
        
        echo -e "   ${BLUE}Service Status:${NC}"
        echo -e "   ${BLUE}--------------${NC}"
        if [[ "$SELECTED_WEBSERVER" == "apache" ]]; then
            local apache_service="httpd"
            [[ "$PACKAGE_MANAGER" == "apt" ]] && apache_service="apache2"
            local apache_status=$(systemctl is-active $apache_service)
            echo "  • Apache: $apache_status"
            log "COMPLETION" "Apache service status: $apache_status"
        elif [[ "$SELECTED_WEBSERVER" == "nginx" ]]; then
            local nginx_status=$(systemctl is-active nginx)
            echo "  • Nginx: $nginx_status"
            log "COMPLETION" "Nginx service status: $nginx_status"
        fi
        
        if [[ "${SELECTED_DATABASES[0]}" == "none" ]]; then
            echo "  • Database: None installed (as requested)"
            log "COMPLETION" "Database: None installed by user choice"
        else
            for database in "${SELECTED_DATABASES[@]}"; do
                case "$database" in
                    mysql)
                        local mysql_service="mysqld"
                        [[ "$PACKAGE_MANAGER" == "apt" ]] && mysql_service="mysql"
                        local mysql_status=$(systemctl is-active $mysql_service)
                        echo "  • MySQL: $mysql_status"
                        log "COMPLETION" "MySQL service status: $mysql_status"
                        ;;
                    mariadb)
                        local mariadb_status=$(systemctl is-active mariadb)
                        echo "  • MariaDB: $mariadb_status"
                        log "COMPLETION" "MariaDB service status: $mariadb_status"
                        ;;
                    postgresql)
                        local postgresql_status=$(systemctl is-active postgresql)
                        echo "  • PostgreSQL: $postgresql_status"
                        log "COMPLETION" "PostgreSQL service status: $postgresql_status"
                        ;;
                    sqlite)
                        echo "  • SQLite: installed (file-based)"
                        log "COMPLETION" "SQLite: installed as file-based database"
                        ;;
                esac
            done
        fi
        
        if [[ "${SELECTED_PHP_VERSIONS[0]}" != "none" ]]; then
            if [[ ${#SELECTED_PHP_VERSIONS[@]} -gt 1 ]]; then
                echo "  • PHP: [${SELECTED_PHP_VERSIONS[*]// /][}] installed. $DEFAULT_PHP_VERSION set as default"
                log "COMPLETION" "PHP versions: ${SELECTED_PHP_VERSIONS[*]}, default: $DEFAULT_PHP_VERSION"
            else
                echo "  • PHP: ${SELECTED_PHP_VERSIONS[0]} installed. ${SELECTED_PHP_VERSIONS[0]} set as default"
                log "COMPLETION" "PHP version: ${SELECTED_PHP_VERSIONS[0]}"
            fi
        else
            echo "  • PHP: None installed (as requested)"
            log "COMPLETION" "PHP: None installed by user choice"
        fi
        
        # Package managers status
        if [[ "${SELECTED_PACKAGE_MANAGERS[0]}" != "none" ]]; then
            for package_manager in "${SELECTED_PACKAGE_MANAGERS[@]}"; do
                case "$package_manager" in
                    composer)
                        if command -v composer >/dev/null 2>&1; then
                            local composer_version=$(composer --version --no-ansi 2>/dev/null | head -n 1)
                            echo "  • Composer: $composer_version"
                            log "COMPLETION" "Composer status: $composer_version"
                        else
                            echo "  • Composer: Not available"
                            log "COMPLETION" "Composer status: Not available"
                        fi
                        ;;
                    nodejs)
                        if command -v node >/dev/null 2>&1 && command -v npm >/dev/null 2>&1; then
                            local node_version=$(node --version)
                            local npm_version=$(npm --version)
                            echo "  • Node.js: $node_version"
                            echo "  • npm: $npm_version"
                            log "COMPLETION" "Node.js status: $node_version"
                            log "COMPLETION" "npm status: $npm_version"
                        else
                            echo "  • Node.js/npm: Not available"
                            log "COMPLETION" "Node.js/npm status: Not available"
                        fi
                        ;;
                esac
            done
        else
            echo "  • Package Managers: None installed (as requested)"
            log "COMPLETION" "Package Managers: None installed by user choice"
        fi
        
        # Development tools status
        if [[ "${SELECTED_DEVELOPMENT_TOOLS[0]}" != "none" ]]; then
            for dev_tool in "${SELECTED_DEVELOPMENT_TOOLS[@]}"; do
                case "$dev_tool" in
                    git)
                        if command -v git >/dev/null 2>&1; then
                            local git_version=$(git --version)
                            echo "  • Git: $git_version"
                            log "COMPLETION" "Git status: $git_version"
                        else
                            echo "  • Git: Not available"
                            log "COMPLETION" "Git status: Not available"
                        fi
                        ;;
                    github-cli)
                        if command -v gh >/dev/null 2>&1; then
                            local gh_version=$(gh --version | head -n 1)
                            echo "  • GitHub CLI: $gh_version"
                            log "COMPLETION" "GitHub CLI status: $gh_version"
                        else
                            echo "  • GitHub CLI: Not available"
                            log "COMPLETION" "GitHub CLI status: Not available"
                        fi
                        ;;
                    claude-ai)
                        if command -v claude >/dev/null 2>&1; then
                            echo "  • Claude AI Code: installed and available"
                            log "COMPLETION" "Claude AI Code status: installed and available"
                        else
                            echo "  • Claude AI Code: Not available"
                            log "COMPLETION" "Claude AI Code status: Not available"
                        fi
                        ;;
                esac
            done
        else
            echo "  • Development Tools: None installed (as requested)"
            log "COMPLETION" "Development Tools: None installed by user choice"
        fi
        
        local fail2ban_status=$(systemctl is-active fail2ban)
        echo "  • Fail2ban: $fail2ban_status"
        log "COMPLETION" "Fail2ban service status: $fail2ban_status"
        
        echo ""
        echo -e "   ${BLUE}Next Steps:${NC}"
        echo -e "   ${BLUE}----------${NC}"
        echo -e "  • Visit ${BLUE}http://$(hostname -I | awk '{print $1}')${NC} to test installation"
        echo "  • Default index page shows Hello World and server info"
        echo "  • Configure your domain DNS to point to this server"
        echo "  • Consider setting up SSL certificates"
        echo "  • Review security settings"
        if [[ "${SELECTED_DATABASES[0]}" != "none" ]]; then
            for database in "${SELECTED_DATABASES[@]}"; do
                case "$database" in
                    mysql)
                        echo "  • MySQL root credentials are in /root/.my.cnf"
                        ;;
                    mariadb)
                        echo "  • MariaDB root credentials are in /root/.my.cnf"
                        ;;
                    postgresql)
                        echo "  • PostgreSQL dev credentials are in /root/postgresql-info.txt"
                        echo "  • Delete this file after retrieving the credentials for security"
                        ;;
                    sqlite)
                        echo "  • SQLite info and sample database in /root/sqlite-info.txt"
                        ;;
                esac
            done
        fi
        
        # PHP versions location information
        if [[ "${SELECTED_PHP_VERSIONS[0]}" != "none" && "$PACKAGE_MANAGER" =~ ^(dnf|yum)$ ]]; then
            # Show individual PHP version locations for RHEL-based systems
            for version in "${SELECTED_PHP_VERSIONS[@]}"; do
                local version_nodot="${version//./}"
                echo "  • PHP location: /opt/remi/php$version_nodot/root/usr/bin/php"
            done
            
            # Show default version info if multiple versions are installed
            if [[ ${#SELECTED_PHP_VERSIONS[@]} -gt 1 ]]; then
                echo "  • Default PHP version: ${SELECTED_PHP_VERSIONS[0]} (accessible via 'php' command)"
            fi
        fi
        
        if [[ "$SELECTED_WEBSERVER" == "nginx" ]]; then
            echo ""
            echo -e "${BLUE}Advanced Options:${NC}"
            echo -e "${BLUE}----------------${NC}"
            echo "  • Current: Unix socket (fastest, most secure for single server)"
            echo "  • To switch to TCP for load balancing/containers, run:"
            case "$PACKAGE_MANAGER" in
                dnf|yum)
                    echo "    • Switch PHP-FPM to TCP:"
                    echo "      sed -i 's|listen = /run/php-fpm/www.sock|listen = 127.0.0.1:9000|' /etc/php-fpm.d/www.conf"
                    echo "    • Switch Nginx to TCP:"
                    echo "      sed -i 's|fastcgi_pass unix:/run/php-fpm/www.sock|fastcgi_pass 127.0.0.1:9000|' /etc/nginx/conf.d/default.conf"
                    echo "    • Open firewall port (if needed for remote PHP-FPM):"
                    echo "      firewall-cmd --permanent --add-port=9000/tcp && firewall-cmd --reload"
                    ;;
                apt)
                    echo "    • Switch PHP-FPM to TCP:"
                    echo "      sed -i 's|listen = /var/run/php/.*\\.sock|listen = 127.0.0.1:9000|' /etc/php/*/fpm/pool.d/www.conf"
                    echo "    • Switch Nginx to TCP:"
                    echo "      sed -i 's|fastcgi_pass unix:/var/run/php/.*\\.sock|fastcgi_pass 127.0.0.1:9000|' /etc/nginx/sites-available/default"
                    echo "    • Open firewall port (if UFW is enabled):"
                    echo "      ufw allow 9000/tcp"
                    ;;
            esac
            echo "    • Restart services:"
            echo "      systemctl restart php-fpm nginx"
            echo ""
            echo "  • Benefits of TCP: Load balancing, containers, remote PHP-FPM servers"
            echo "  • Benefits of Unix socket: 10-30% faster, more secure, simpler setup"
        fi
        
        echo ""
        echo -e "   ${BLUE}Important to do items:${NC}"
        echo -e "   ${BLUE}---------------------${NC}"
        echo "  • Read the README.md - /root/README.md"
        echo "  • Remove any database setup information for security"
        echo "  • Enjoy your new development server!"
        
        log "COMPLETION" "Next steps provided to user"
        
        # Clear bash command cache to ensure newly installed commands are accessible
        hash -r 2>/dev/null || true
        log "INFO" "Bash command cache cleared for immediate CLI access to installed programs"
        
    else
        print_error "Installation completed but some validations failed"
        print_error "Check the log file for details: $LOG_FILE"
        log "ERROR" "Installation completed with validation failures"
        
        # Clear bash command cache even on validation failures
        hash -r 2>/dev/null || true
        log "INFO" "Bash command cache cleared despite validation failures"
    fi
    
    log "COMPLETION" "Script execution completed"
    echo "  • Install log: $LOG_FILE"
    echo -e "  • 🔄 Important: run: ${BLUE}hash -r${NC} (clears bash command cache)"
    echo -e "  • Use '${BLUE}$0 --verbose${NC}' for detailed installation logs."
    
    echo ""
    echo -e "${BLUE}===========================================================================${NC}"
    echo ""
}

# Run main function
main "$@"

