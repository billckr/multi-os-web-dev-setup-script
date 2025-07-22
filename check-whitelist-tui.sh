#!/bin/bash

# Whitelisted IPs Check Script - TUI Version
# Description: Interactive TUI for comprehensive whitelist analysis in fail2ban and firewall
# Compatible with: RHEL, Debian, SUSE, Arch Linux families
# Author: Web Development Setup Script Project
# Version: 2.0 (TUI Edition)

set -euo pipefail

# Global variables
VERBOSE=false
OUTPUT_FILE=""
TEMP_DIR="/tmp/whitelist-tui-$$"
FORCE_NO_COLOR=false

# Parse command line arguments
parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --no-color|--no-colour)
                FORCE_NO_COLOR=true
                shift
                ;;
            --help|-h)
                show_usage
                exit 0
                ;;
            *)
                echo "Unknown option: $1"
                show_usage
                exit 1
                ;;
        esac
    done
}

show_usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --no-color     Disable color output"
    echo "  --help, -h     Show this help message"
    echo ""
}

# Check if terminal supports colors
check_color_support() {
    # If colors are force disabled, return false
    if [[ "$FORCE_NO_COLOR" == true ]]; then
        return 1
    fi
    
    # Force disable colors in Windows PowerShell/CMD if ANSI not working
    if [[ "$TERM" == "dumb" ]] || [[ -z "$TERM" ]]; then
        return 1
    fi
    
    # Check if stdout is a terminal and we have tput
    if [[ -t 1 ]] && command -v tput >/dev/null 2>&1; then
        local colors=$(tput colors 2>/dev/null || echo 0)
        if [[ $colors -ge 8 ]]; then
            # Test if colors actually work by trying to output one
            if printf '\033[0m' 2>/dev/null; then
                return 0
            fi
        fi
    fi
    
    # Alternative check for ANSI support
    if [[ -n "${COLORTERM:-}" ]] || [[ "$TERM" == *"color"* ]] || [[ "$TERM" == *"256"* ]]; then
        return 0
    fi
    
    return 1
}

# Set colors based on terminal support
if check_color_support; then
    # Colors for output
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    BLUE='\033[0;34m'
    CYAN='\033[0;36m'
    MAGENTA='\033[0;35m'
    WHITE='\033[1;37m'
    NC='\033[0m' # No Color

    # TUI Colors
    MENU_HEADER='\033[1;36m'
    MENU_OPTION='\033[1;33m'
    MENU_SELECTED='\033[1;32m'
    BORDER='\033[0;36m'
else
    # Fallback - no colors
    RED=''
    GREEN=''
    YELLOW=''
    BLUE=''
    CYAN=''
    MAGENTA=''
    WHITE=''
    NC=''
    MENU_HEADER=''
    MENU_OPTION=''
    MENU_SELECTED=''
    BORDER=''
fi

# Safe color printing function
print_colored() {
    local color="$1"
    local text="$2"
    local reset="$3"
    
    if check_color_support; then
        printf "%s%s%s" "$color" "$text" "${reset:-$NC}"
    else
        printf "%s" "$text"
    fi
}

# Print functions
print_header() {
    clear
    echo -e "${BORDER}╔════════════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BORDER}║${MENU_HEADER}                        WHITELIST ANALYZER TUI                              ${BORDER}║${NC}"
    echo -e "${BORDER}║${WHITE}                   Comprehensive IP Whitelist Analysis                      ${BORDER}║${NC}"
    echo -e "${BORDER}╚════════════════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
}

print_section() {
    echo -e "\n${BORDER}┌─ ${CYAN}$1${BORDER} ────────────────────────────────────────────────────────────────${NC}"
}

print_section_end() {
    echo -e "${BORDER}└──────────────────────────────────────────────────────────────────────────────${NC}\n"
}

print_info() {
    echo -e "  ${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "  ${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "  ${RED}[ERROR]${NC} $1"
}

print_success() {
    echo -e "  ${GREEN}[SUCCESS]${NC} $1"
}

# Pause function for TUI
pause() {
    echo ""
    echo -e "${YELLOW}Press Enter to continue...${NC}"
    read -r
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_error "This script must be run as root or with sudo"
        print_info "Usage: sudo $0"
        exit 1
    fi
}

# Initialize temp directory
init_temp() {
    mkdir -p "$TEMP_DIR"
    trap 'rm -rf "$TEMP_DIR"' EXIT
}

# Graceful exit function
graceful_exit() {
    print_header
    echo -e "${GREEN}Thank you for using Whitelist Analyzer TUI!${NC}"
    echo ""
    echo "Exiting..."
    exit 0
}

# Setup signal handlers
setup_signals() {
    trap graceful_exit SIGINT
    trap graceful_exit SIGTERM
}

# Check if fail2ban is installed and running
check_fail2ban() {
    if ! command -v fail2ban-client >/dev/null 2>&1; then
        return 1
    fi
    
    if ! systemctl is-active --quiet fail2ban; then
        return 1
    fi
    
    return 0
}

# Get all active fail2ban jails
get_active_jails() {
    local jails
    jails=$(fail2ban-client status 2>/dev/null | grep "Jail list:" | cut -d: -f2 | tr ',' '\n' | xargs)
    echo "$jails"
}

# Check fail2ban whitelisted IPs
check_fail2ban_whitelist() {
    print_header
    print_section "Fail2ban Whitelist Analysis"
    
    if ! check_fail2ban; then
        print_error "Cannot analyze fail2ban (not installed or not running)"
        print_section_end
        pause
        return 1
    fi
    
    # Get fail2ban status
    print_info "Fail2ban service status:"
    echo ""
    systemctl status fail2ban --no-pager -l | head -5
    
    echo ""
    print_info "Active jails:"
    fail2ban-client status
    
    # Get active jails
    local jails
    jails=$(get_active_jails)
    
    if [[ -z "$jails" ]]; then
        print_warning "No active fail2ban jails found"
        print_section_end
        pause
        return 1
    fi
    
    echo ""
    print_info "Checking ignoreip settings for each jail:"
    
    for jail in $jails; do
        echo -e "\n    ${CYAN}[$jail]${NC}"
        local ignoreip
        ignoreip=$(fail2ban-client get "$jail" ignoreip 2>/dev/null || echo "Unable to retrieve")
        
        if [[ "$ignoreip" == "Unable to retrieve" ]]; then
            echo "      Status: Unable to get ignoreip settings"
        elif [[ -z "$ignoreip" || "$ignoreip" == "[]" || "$ignoreip" == "" ]]; then
            echo "      Whitelisted IPs: ${YELLOW}None${NC}"
        else
            echo "      Whitelisted IPs: ${GREEN}$ignoreip${NC}"
        fi
        
        # Get current banned IPs for context
        local banned
        banned=$(fail2ban-client get "$jail" banip 2>/dev/null || echo "Unable to retrieve")
        if [[ "$banned" != "Unable to retrieve" ]] && [[ -n "$banned" ]] && [[ "$banned" != "[]" ]]; then
            echo "      Currently banned: ${RED}$banned${NC}"
        else
            echo "      Currently banned: ${GREEN}None${NC}"
        fi
    done
    
    print_section_end
    pause
}

# Check fail2ban configuration files
check_fail2ban_config() {
    print_header
    print_section "Fail2ban Configuration Files"
    
    print_info "Global ignoreip settings:"
    
    # Check main configuration files
    local config_files=("/etc/fail2ban/jail.conf" "/etc/fail2ban/jail.local")
    local found_config=false
    
    for config_file in "${config_files[@]}"; do
        if [[ -f "$config_file" ]]; then
            echo -e "\n    ${CYAN}From $config_file:${NC}"
            grep -n "^ignoreip\|^#ignoreip" "$config_file" 2>/dev/null | head -10 | while read -r line; do
                echo "      $line"
            done || echo "      No ignoreip settings found"
            found_config=true
        fi
    done
    
    # Check jail.d directory
    if [[ -d "/etc/fail2ban/jail.d" ]]; then
        echo -e "\n    ${CYAN}From /etc/fail2ban/jail.d/:${NC}"
        find /etc/fail2ban/jail.d/ -name "*.conf" -exec grep -Hn "ignoreip" {} \; 2>/dev/null | while read -r line; do
            echo "      $line"
        done || echo "      No ignoreip settings found in jail.d"
    fi
    
    if [[ "$found_config" == false ]]; then
        print_warning "No fail2ban configuration files found"
    fi
    
    print_section_end
    pause
}

# Check firewall rules
check_firewall_rules() {
    print_header
    print_section "Firewall Whitelist Rules"
    
    # Check for different firewall systems
    if command -v firewall-cmd >/dev/null 2>&1; then
        print_info "Checking firewalld rules:"
        
        # Check rich rules (specific IP allows)
        echo -e "\n    ${CYAN}Rich rules with source addresses:${NC}"
        firewall-cmd --list-rich-rules | grep "source address" | while read -r rule; do
            echo "      ${GREEN}$rule${NC}"
        done || echo "      No rich rules with source addresses found"
        
        # Check zones and their sources
        echo -e "\n    ${CYAN}Zones and their sources:${NC}"
        for zone in $(firewall-cmd --get-zones); do
            local sources
            sources=$(firewall-cmd --zone="$zone" --list-sources 2>/dev/null)
            if [[ -n "$sources" ]]; then
                echo "      Zone '${YELLOW}$zone${NC}': ${GREEN}$sources${NC}"
            fi
        done
        
        # Check trusted zone specifically
        echo -e "\n    ${CYAN}Trusted zone details:${NC}"
        firewall-cmd --zone=trusted --list-all | while read -r line; do
            echo "      $line"
        done || echo "      Trusted zone not configured"
        
    elif command -v ufw >/dev/null 2>&1; then
        print_info "Checking UFW rules:"
        
        echo -e "\n    ${CYAN}UFW status and rules:${NC}"
        ufw status numbered | grep -E "ALLOW|DENY" | while read -r rule; do
            echo "      $rule"
        done || echo "      No UFW rules found"
        
        echo -e "\n    ${CYAN}UFW rules allowing specific IPs:${NC}"
        ufw status | grep "ALLOW IN" | grep -v "Anywhere" | grep -E "[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+" | while read -r rule; do
            echo "      ${GREEN}$rule${NC}"
        done || echo "      No specific IP rules found"
        
    else
        print_info "Checking iptables rules:"
        
        echo -e "\n    ${CYAN}INPUT chain rules:${NC}"
        iptables -L INPUT -n --line-numbers | grep -E "ACCEPT.*[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+" | while read -r rule; do
            echo "      ${GREEN}$rule${NC}"
        done || echo "      No specific IP ACCEPT rules found"
        
        echo -e "\n    ${CYAN}All ACCEPT rules with source IPs:${NC}"
        iptables -L -n | grep -E "ACCEPT.*[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+" | while read -r rule; do
            echo "      ${GREEN}$rule${NC}"
        done || echo "      No ACCEPT rules with source IPs found"
    fi
    
    print_section_end
    pause
}

# Check system logs for recent whitelist activity
check_recent_activity() {
    print_header
    print_section "Recent Whitelist Activity"
    
    print_info "Recent fail2ban log entries mentioning 'ignore':"
    if [[ -f "/var/log/fail2ban.log" ]]; then
        echo -e "\n    ${CYAN}Last 10 ignore-related entries:${NC}"
        grep -i "ignore" /var/log/fail2ban.log | tail -10 | while read -r line; do
            echo "      $line"
        done || echo "      No ignore-related entries found"
    else
        print_warning "/var/log/fail2ban.log not found"
    fi
    
    print_info "Recent systemd journal entries for fail2ban:"
    echo -e "\n    ${CYAN}Last 5 fail2ban journal entries:${NC}"
    journalctl -u fail2ban --no-pager -n 5 -o short 2>/dev/null | while read -r line; do
        echo "      $line"
    done || echo "      Unable to retrieve journal entries"
    
    print_section_end
    pause
}

# View all active jails with detailed information
view_all_jails() {
    print_header
    print_section "All Active Jails Overview"
    
    if ! check_fail2ban; then
        print_error "Cannot view jails (fail2ban not installed or not running)"
        print_section_end
        pause
        return 1
    fi
    
    # Get active jails
    local jails
    jails=$(get_active_jails)
    
    if [[ -z "$jails" ]]; then
        print_warning "No active fail2ban jails found"
        print_section_end
        pause
        return 1
    fi
    
    print_info "Found $(echo $jails | wc -w) active jail(s)"
    echo ""
    
    # Display detailed information for each jail
    for jail in $jails; do
        echo -e "${BORDER}┌─ ${CYAN}Jail: $jail${BORDER} ───────────────────────────────────────────────${NC}"
        
        # Get jail statistics
        local jail_status=$(fail2ban-client status "$jail" 2>/dev/null)
        if [[ $? -eq 0 ]]; then
            # Parse jail status information
            local currently_failed=$(echo "$jail_status" | grep "Currently failed:" | awk -F: '{print $2}' | xargs)
            local total_failed=$(echo "$jail_status" | grep "Total failed:" | awk -F: '{print $2}' | xargs)
            local currently_banned=$(echo "$jail_status" | grep "Currently banned:" | awk -F: '{print $2}' | xargs)
            local total_banned=$(echo "$jail_status" | grep "Total banned:" | awk -F: '{print $2}' | xargs)
            
            # Get whitelist info
            local ignoreip=$(fail2ban-client get "$jail" ignoreip 2>/dev/null || echo "Unable to retrieve")
            
            # Display formatted information
            echo "  Status: $(print_colored "$GREEN" "Active" "$NC")"
            echo "  Currently failed IPs: $(print_colored "$YELLOW" "${currently_failed:-0}" "$NC")"
            echo "  Total failed attempts: $(print_colored "$YELLOW" "${total_failed:-0}" "$NC")"
            echo "  Currently banned IPs: $(print_colored "$RED" "${currently_banned:-0}" "$NC")"
            echo "  Total banned count: $(print_colored "$RED" "${total_banned:-0}" "$NC")"
            
            if [[ -z "$ignoreip" || "$ignoreip" == "[]" || "$ignoreip" == "Unable to retrieve" ]]; then
                echo "  Whitelisted IPs: $(print_colored "$YELLOW" "None" "$NC")"
            else
                echo "  Whitelisted IPs: $(print_colored "$GREEN" "$ignoreip" "$NC")"
            fi
            
            # Get filter and action info
            local filter=$(fail2ban-client get "$jail" filter 2>/dev/null || echo "Unknown")
            local action=$(fail2ban-client get "$jail" action 2>/dev/null || echo "Unknown")
            
            echo "  Filter: $(print_colored "$CYAN" "$filter" "$NC")"
            echo "  Actions: $(print_colored "$CYAN" "$action" "$NC")"
            
        else
            echo "  Status: ${RED}Error retrieving jail information${NC}"
        fi
        
        echo -e "${BORDER}└────────────────────────────────────────────────────────────────────────${NC}"
        echo ""
    done
    
    # Show summary
    echo -e "$(print_colored "$CYAN" "=== Summary ===" "$NC")"
    local jail_count=$(echo $jails | wc -w)
    echo "Total active jails: $(print_colored "$GREEN" "$jail_count" "$NC")"
    
    # Calculate totals
    local total_banned_all=0
    local total_failed_all=0
    for jail in $jails; do
        local jail_status=$(fail2ban-client status "$jail" 2>/dev/null)
        if [[ $? -eq 0 ]]; then
            local banned=$(echo "$jail_status" | grep "Currently banned:" | awk -F: '{print $2}' | xargs)
            local failed=$(echo "$jail_status" | grep "Currently failed:" | awk -F: '{print $2}' | xargs)
            total_banned_all=$((total_banned_all + ${banned:-0}))
            total_failed_all=$((total_failed_all + ${failed:-0}))
        fi
    done
    
    echo "Total currently banned IPs: $(print_colored "$RED" "$total_banned_all" "$NC")"
    echo "Total currently failed IPs: $(print_colored "$YELLOW" "$total_failed_all" "$NC")"
    
    print_section_end
    pause
}

# Interactive jail management
manage_jails() {
    while true; do
        print_header
        print_section "Jail Management"
        
        if ! check_fail2ban; then
            print_error "fail2ban is not installed or not running"
            print_section_end
            pause
            return
        fi
        
        local jails
        jails=$(get_active_jails)
        
        if [[ -z "$jails" ]]; then
            print_warning "No active jails found"
            print_section_end
            pause
            return
        fi
        
        echo "Select a jail to manage:"
        echo ""
        
        local jail_array=($jails)
        local options=()
        
        for i in "${!jail_array[@]}"; do
            local jail="${jail_array[$i]}"
            local ignoreip=$(fail2ban-client get "$jail" ignoreip 2>/dev/null || echo "Error")
            options+=("$jail (ignoreip: $ignoreip)")
        done
        options+=("Back to Main Menu")
        
        select opt in "${options[@]}"; do
            if [[ "$opt" == "Back to Main Menu" ]]; then
                return
            elif [[ -n "$opt" ]]; then
                local selected_jail=$(echo "$opt" | cut -d' ' -f1)
                manage_single_jail "$selected_jail"
                break
            else
                print_error "Invalid option"
            fi
        done
        print_section_end
    done
}

# Manage a single jail
manage_single_jail() {
    local jail="$1"
    
    while true; do
        print_header
        print_section "Managing Jail: $jail"
        
        # Show current status
        local ignoreip=$(fail2ban-client get "$jail" ignoreip 2>/dev/null || echo "Error")
        local banned=$(fail2ban-client get "$jail" banip 2>/dev/null || echo "Error")
        
        echo "Current Status:"
        echo "  Whitelisted IPs: ${GREEN}$ignoreip${NC}"
        echo "  Banned IPs: ${RED}$banned${NC}"
        echo ""
        
        local options=(
            "Add IP to whitelist"
            "Remove IP from whitelist"
            "View detailed jail status"
            "Back to jail selection"
        )
        
        echo "What would you like to do?"
        select opt in "${options[@]}"; do
            case $opt in
                "Add IP to whitelist")
                    add_ip_to_whitelist "$jail"
                    break
                    ;;
                "Remove IP from whitelist")
                    remove_ip_from_whitelist "$jail"
                    break
                    ;;
                "View detailed jail status")
                    show_jail_details "$jail"
                    break
                    ;;
                "Back to jail selection")
                    return
                    ;;
                *)
                    print_error "Invalid option"
                    ;;
            esac
        done
        print_section_end
    done
}

# Add IP to whitelist
add_ip_to_whitelist() {
    local jail="$1"
    
    echo ""
    echo -e "${YELLOW}Enter IP address to whitelist:${NC}"
    read -r ip_address
    
    if [[ -z "$ip_address" ]]; then
        print_error "No IP address provided"
        pause
        return
    fi
    
    # Basic IP validation
    if [[ ! $ip_address =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        print_error "Invalid IP address format"
        pause
        return
    fi
    
    echo ""
    print_info "Adding $ip_address to jail $jail whitelist..."
    
    if fail2ban-client set "$jail" addignoreip "$ip_address" 2>/dev/null; then
        print_success "Successfully added $ip_address to whitelist"
    else
        print_error "Failed to add $ip_address to whitelist"
    fi
    
    pause
}

# Remove IP from whitelist
remove_ip_from_whitelist() {
    local jail="$1"
    
    # Get current whitelist
    local ignoreip=$(fail2ban-client get "$jail" ignoreip 2>/dev/null || echo "Error")
    
    if [[ "$ignoreip" == "Error" || -z "$ignoreip" || "$ignoreip" == "[]" ]]; then
        print_warning "No IPs currently whitelisted in this jail"
        pause
        return
    fi
    
    echo ""
    echo -e "${YELLOW}Current whitelisted IPs: $ignoreip${NC}"
    echo -e "${YELLOW}Enter IP address to remove from whitelist:${NC}"
    read -r ip_address
    
    if [[ -z "$ip_address" ]]; then
        print_error "No IP address provided"
        pause
        return
    fi
    
    echo ""
    print_info "Removing $ip_address from jail $jail whitelist..."
    
    if fail2ban-client set "$jail" delignoreip "$ip_address" 2>/dev/null; then
        print_success "Successfully removed $ip_address from whitelist"
    else
        print_error "Failed to remove $ip_address from whitelist"
    fi
    
    pause
}

# Show detailed jail information
show_jail_details() {
    local jail="$1"
    
    print_header
    print_section "Detailed Status for Jail: $jail"
    
    echo "Full jail status:"
    fail2ban-client status "$jail"
    
    print_section_end
    pause
}

# Generate and save report
generate_report() {
    print_header
    print_section "Generate Report"
    
    echo -e "${YELLOW}Enter output filename (or press Enter for default):${NC}"
    read -r filename
    
    if [[ -z "$filename" ]]; then
        filename="whitelist-report-$(date +%Y%m%d-%H%M%S).txt"
    fi
    
    print_info "Generating comprehensive report..."
    
    {
        echo "=========================================="
        echo "WHITELIST ANALYSIS REPORT"
        echo "Generated: $(date '+%Y-%m-%d %H:%M:%S')"
        echo "Hostname: $(hostname)"
        echo "User: $(whoami)"
        echo "=========================================="
        echo ""
        
        # Fail2ban analysis
        echo "=== FAIL2BAN WHITELIST ANALYSIS ==="
        if check_fail2ban; then
            echo "Fail2ban Status: Running"
            echo ""
            
            fail2ban-client status
            echo ""
            
            local jails
            jails=$(get_active_jails)
            
            if [[ -n "$jails" ]]; then
                for jail in $jails; do
                    echo "[$jail]"
                    local ignoreip=$(fail2ban-client get "$jail" ignoreip 2>/dev/null || echo "Unable to retrieve")
                    local banned=$(fail2ban-client get "$jail" banip 2>/dev/null || echo "Unable to retrieve")
                    echo "  Whitelisted IPs: $ignoreip"
                    echo "  Currently banned: $banned"
                    echo ""
                done
            fi
        else
            echo "Fail2ban Status: Not running or not installed"
        fi
        
        echo ""
        echo "=== FIREWALL ANALYSIS ==="
        
        if command -v firewall-cmd >/dev/null 2>&1; then
            echo "Firewall Type: firewalld"
            echo ""
            echo "Rich rules with source addresses:"
            firewall-cmd --list-rich-rules | grep "source address" || echo "None found"
            echo ""
            
            echo "Zones and sources:"
            for zone in $(firewall-cmd --get-zones); do
                local sources=$(firewall-cmd --zone="$zone" --list-sources 2>/dev/null)
                if [[ -n "$sources" ]]; then
                    echo "  Zone '$zone': $sources"
                fi
            done
            
        elif command -v ufw >/dev/null 2>&1; then
            echo "Firewall Type: UFW"
            echo ""
            ufw status
            
        else
            echo "Firewall Type: iptables"
            echo ""
            iptables -L INPUT -n --line-numbers | grep -E "ACCEPT.*[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+" || echo "No specific IP rules found"
        fi
        
    } > "$filename"
    
    if [[ -f "$filename" ]]; then
        print_success "Report saved to: $filename"
    else
        print_error "Failed to save report"
    fi
    
    print_section_end
    pause
}

# Diagnostics and troubleshooting
run_diagnostics() {
    print_header
    print_section "System Diagnostics & Troubleshooting"
    
    print_info "Running comprehensive diagnostics..."
    echo ""
    
    # Check for common issues
    echo -e "${CYAN}=== Checking for Common Issues ===${NC}"
    
    # 1. Check jail name consistency
    print_info "Checking jail name consistency:"
    if check_fail2ban; then
        local jails=$(get_active_jails)
        if [[ -n "$jails" ]]; then
            echo "  Active jails: ${GREEN}$jails${NC}"
            
            # Check for common jail name variants
            if echo "$jails" | grep -q "ssh"; then
                print_warning "Found 'ssh' jail - should probably be 'sshd'"
            fi
            if echo "$jails" | grep -q "apache"; then
                print_info "Found 'apache' jail - verify correct service name"
            fi
        else
            print_warning "No active jails found"
        fi
    else
        print_error "fail2ban not running - cannot check jails"
    fi
    
    echo ""
    
    # 2. Test jail commands
    print_info "Testing jail command syntax:"
    if check_fail2ban; then
        local jails=$(get_active_jails)
        for jail in $jails; do
            echo "  Testing jail '$jail':"
            
            # Test ignoreip command
            local ignoreip_result=$(fail2ban-client get "$jail" ignoreip 2>&1)
            if [[ $? -eq 0 ]]; then
                echo "    ✓ ignoreip command works: $ignoreip_result"
            else
                echo "    ✗ ignoreip command failed: $ignoreip_result"
            fi
            
            # Test status command
            local status_result=$(fail2ban-client status "$jail" 2>&1)
            if [[ $? -eq 0 ]]; then
                echo "    ✓ status command works"
            else
                echo "    ✗ status command failed: $status_result"
            fi
        done
    fi
    
    echo ""
    
    # 3. Check recent errors in logs
    print_info "Analyzing recent errors in fail2ban logs:"
    if [[ -f "/var/log/fail2ban.log" ]]; then
        echo "  Recent ERROR entries (last 5):"
        grep "ERROR" /var/log/fail2ban.log | tail -5 | while read -r line; do
            echo "    ${RED}$line${NC}"
        done
        
        echo ""
        echo "  Error summary (last 24 hours):"
        
        # Count different types of errors
        local index_errors=$(grep "IndexError" /var/log/fail2ban.log | wc -l)
        local unknown_jail_errors=$(grep "UnknownJailException" /var/log/fail2ban.log | wc -l)
        local value_errors=$(grep "ValueError.*not in list" /var/log/fail2ban.log | wc -l)
        
        echo "    IndexError (wrong command syntax): ${RED}$index_errors${NC}"
        echo "    UnknownJailException (wrong jail name): ${RED}$unknown_jail_errors${NC}"
        echo "    ValueError (IP not in list): ${RED}$value_errors${NC}"
        
    else
        print_warning "/var/log/fail2ban.log not found"
    fi
    
    echo ""
    
    # 4. Configuration validation
    print_info "Validating configuration files:"
    
    # Check for syntax errors in config files
    local config_files=("/etc/fail2ban/jail.conf" "/etc/fail2ban/jail.local")
    for config_file in "${config_files[@]}"; do
        if [[ -f "$config_file" ]]; then
            echo "  Checking $config_file:"
            
            # Look for potential syntax issues
            local duplicate_sections=$(grep "^\[" "$config_file" | sort | uniq -d)
            if [[ -n "$duplicate_sections" ]]; then
                echo "    ${YELLOW}Warning: Duplicate sections found:${NC}"
                echo "$duplicate_sections" | while read -r section; do
                    echo "      $section"
                done
            else
                echo "    ✓ No duplicate sections found"
            fi
            
            # Check for malformed ignoreip lines
            local malformed_ignoreip=$(grep -n "ignoreip.*=" "$config_file" | grep -v "^#" | grep -E "(,\s*,|^\s*ignoreip\s*=\s*$)")
            if [[ -n "$malformed_ignoreip" ]]; then
                echo "    ${YELLOW}Warning: Potentially malformed ignoreip lines:${NC}"
                echo "$malformed_ignoreip" | while read -r line; do
                    echo "      $line"
                done
            else
                echo "    ✓ No malformed ignoreip lines found"
            fi
        fi
    done
    
    echo ""
    
    # 5. Service status check
    print_info "Service status verification:"
    echo "  fail2ban service:"
    if systemctl is-active --quiet fail2ban; then
        echo "    Status: ${GREEN}Active${NC}"
        local uptime=$(systemctl show fail2ban --property=ActiveEnterTimestamp --value)
        echo "    Started: $uptime"
    else
        echo "    Status: ${RED}Inactive${NC}"
    fi
    
    echo "  fail2ban socket:"
    if systemctl is-active --quiet fail2ban.socket 2>/dev/null; then
        echo "    Status: ${GREEN}Active${NC}"
    else
        echo "    Status: ${YELLOW}Not available or inactive${NC}"
    fi
    
    echo ""
    
    # 6. Common solutions
    print_info "Common solutions for the errors you saw:"
    echo -e "  ${CYAN}For IndexError 'list index out of range':${NC}"
    echo "    • Check command syntax - use: fail2ban-client get [jail] ignoreip"
    echo "    • Don't use: fail2ban-client get ignoreip (missing jail name)"
    echo ""
    echo -e "  ${CYAN}For UnknownJailException:${NC}"
    echo "    • Verify jail names with: fail2ban-client status"
    echo "    • Use correct jail name (e.g., 'sshd' not 'ssh')"
    echo ""
    echo -e "  ${CYAN}For ValueError 'x not in list':${NC}"
    echo "    • Check current whitelist before removing IP"
    echo "    • Use: fail2ban-client get [jail] ignoreip first"
    echo ""
    
    print_section_end
    pause
}

# Settings menu
settings_menu() {
    while true; do
        print_header
        print_section "Settings"
        
        echo "Current Settings:"
        echo "  Verbose mode: ${VERBOSE}"
        echo "  Output file: ${OUTPUT_FILE:-"Not set"}"
        echo ""
        
        local options=(
            "Toggle verbose mode"
            "Set default output file"
            "Clear output file setting"
            "Back to Main Menu"
        )
        
        echo "Settings Options:"
        select opt in "${options[@]}"; do
            case $opt in
                "Toggle verbose mode")
                    if [[ "$VERBOSE" == true ]]; then
                        VERBOSE=false
                        print_info "Verbose mode disabled"
                    else
                        VERBOSE=true
                        print_info "Verbose mode enabled"
                    fi
                    pause
                    break
                    ;;
                "Set default output file")
                    echo -e "${YELLOW}Enter default output filename:${NC}"
                    read -r OUTPUT_FILE
                    print_info "Default output file set to: $OUTPUT_FILE"
                    pause
                    break
                    ;;
                "Clear output file setting")
                    OUTPUT_FILE=""
                    print_info "Output file setting cleared"
                    pause
                    break
                    ;;
                "Back to Main Menu")
                    return
                    ;;
                *)
                    print_error "Invalid option"
                    ;;
            esac
        done
        print_section_end
    done
}

# Quick reference guide
show_help() {
    print_header
    print_section "Quick Reference Guide"
    
    echo -e "${CYAN}Common fail2ban Commands:${NC}"
    echo "• Check all jails:           fail2ban-client status"
    echo "• Get jail status:           fail2ban-client status [jail]"
    echo "• Get jail ignoreip:         fail2ban-client get [jail] ignoreip"
    echo "• Add IP to ignore:          fail2ban-client set [jail] addignoreip [IP]"
    echo "• Remove IP from ignore:     fail2ban-client set [jail] delignoreip [IP]"
    echo "• Unban IP:                  fail2ban-client set [jail] unbanip [IP]"
    echo "• Restart fail2ban:          systemctl restart fail2ban"
    echo ""
    
    if command -v firewall-cmd >/dev/null 2>&1; then
        echo -e "${CYAN}Common firewalld Commands:${NC}"
        echo "• List zones:                firewall-cmd --get-zones"
        echo "• List zone rules:           firewall-cmd --zone=[zone] --list-all"
        echo "• Add rich rule:             firewall-cmd --permanent --add-rich-rule='rule family=\"ipv4\" source address=\"[IP]\" accept'"
        echo "• Remove rich rule:          firewall-cmd --permanent --remove-rich-rule='rule family=\"ipv4\" source address=\"[IP]\" accept'"
        echo "• Reload firewall:           firewall-cmd --reload"
    elif command -v ufw >/dev/null 2>&1; then
        echo -e "${CYAN}Common UFW Commands:${NC}"
        echo "• UFW status:                ufw status numbered"
        echo "• Allow IP:                  ufw allow from [IP]"
        echo "• Delete rule:               ufw delete [number]"
        echo "• Enable UFW:                ufw enable"
        echo "• Disable UFW:               ufw disable"
    fi
    
    echo ""
    echo -e "${CYAN}Log Files:${NC}"
    echo "• fail2ban log:              /var/log/fail2ban.log"
    echo "• System journal:            journalctl -u fail2ban"
    echo "• Firewall logs:             /var/log/firewalld or /var/log/ufw.log"
    echo ""
    
    echo -e "${CYAN}Configuration Files:${NC}"
    echo "• fail2ban main config:      /etc/fail2ban/jail.conf"
    echo "• fail2ban local config:     /etc/fail2ban/jail.local"
    echo "• fail2ban jail configs:     /etc/fail2ban/jail.d/"
    
    print_section_end
    pause
}

# Block a port from outside access
block_port_from_outside() {
    print_header
    print_section "Block Port From Outside Access"
    echo -e "${YELLOW}Enter the port number to block (e.g., 3306):${NC}"
    read -r port
    if [[ -z "$port" || ! "$port" =~ ^[0-9]+$ ]]; then
        print_error "Invalid port number."
        pause
        return
    fi

    # Confirm
    echo -e "${YELLOW}Are you sure you want to block port $port from outside access? (y/n)${NC}"
    read -r confirm
    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        print_info "Operation cancelled."
        pause
        return
    fi

    # Try firewalld
    if command -v firewall-cmd >/dev/null 2>&1; then
        print_info "Blocking port $port with firewalld..."
        # Remove from all zones except trusted/internal
        for zone in $(firewall-cmd --get-zones); do
            if [[ "$zone" != "trusted" && "$zone" != "internal" ]]; then
                firewall-cmd --zone="$zone" --remove-port="$port"/tcp --permanent 2>/dev/null
                firewall-cmd --zone="$zone" --remove-port="$port"/udp --permanent 2>/dev/null
            fi
        done
        firewall-cmd --reload
        print_success "Port $port blocked from outside (firewalld)."
        pause
        return
    fi

    # Try UFW
    if command -v ufw >/dev/null 2>&1; then
        print_info "Blocking port $port with UFW..."
        ufw deny $port/tcp
        ufw deny $port/udp
        print_success "Port $port blocked from outside (UFW)."
        pause
        return
    fi

    # Try iptables
    if command -v iptables >/dev/null 2>&1; then
        print_info "Blocking port $port with iptables..."
        iptables -A INPUT -p tcp --dport $port -j DROP
        iptables -A INPUT -p udp --dport $port -j DROP
        print_success "Port $port blocked from outside (iptables)."
        print_warning "Note: iptables changes are not persistent after reboot unless saved."
        pause
        return
    fi

    print_error "No supported firewall system found."
    pause
}

# Main menu
main_menu() {
    while true; do
        print_header
        print_section "Main Menu"
        
        # Show system status
        echo "System Status:"
        if check_fail2ban; then
            echo -e "  fail2ban: ${GREEN}Running${NC}"
        else
            echo -e "  fail2ban: ${RED}Not running${NC}"
        fi
        
        if command -v firewall-cmd >/dev/null 2>&1; then
            echo -e "  Firewall: ${GREEN}firewalld${NC}"
        elif command -v ufw >/dev/null 2>&1; then
            echo -e "  Firewall: ${GREEN}UFW${NC}"
        else
            echo -e "  Firewall: ${GREEN}iptables${NC}"
        fi
        echo ""
        
        local options=(
            "Analyze fail2ban Whitelist"
            "Check fail2ban Configuration"
            "Analyze Firewall Rules"
            "Check Recent Activity"
            "View All Active Jails"
            "Interactive Jail Management"
            "Block Port From Outside"
            "Generate Full Report"
            "Run System Diagnostics"
            "Settings"
            "Quick Reference Guide"
            "Exit (or press Ctrl+C)"
        )
        
        echo "Select an option:"
        select opt in "${options[@]}"; do
            case $opt in
                "Analyze fail2ban Whitelist")
                    check_fail2ban_whitelist
                    break
                    ;;
                "Check fail2ban Configuration")
                    check_fail2ban_config
                    break
                    ;;
                "Analyze Firewall Rules")
                    check_firewall_rules
                    break
                    ;;
                "Check Recent Activity")
                    check_recent_activity
                    break
                    ;;
                "View All Active Jails")
                    view_all_jails
                    break
                    ;;
                "Interactive Jail Management")
                    manage_jails
                    break
                    ;;
                "Block Port From Outside")
                    block_port_from_outside
                    break
                    ;;
                "Generate Full Report")
                    generate_report
                    break
                    ;;
                "Run System Diagnostics")
                    run_diagnostics
                    break
                    ;;
                "Settings")
                    settings_menu
                    break
                    ;;
                "Quick Reference Guide")
                    show_help
                    break
                    ;;
                "Exit (or press Ctrl+C)")
                    graceful_exit
                    ;;
                *)
                    print_error "Invalid option. Please try again."
                    ;;
            esac
        done
        print_section_end
    done
}

# Initialize and run
main() {
    # Parse command line arguments
    parse_args "$@"
    
    # Check if running as root
    check_root
    
    # Initialize temporary directory
    init_temp
    
    # Setup signal handlers
    setup_signals
    
    # Show welcome message
    print_header
    echo -e "$(print_colored "$GREEN" "Welcome to Whitelist Analyzer TUI!" "$NC")"
    echo ""
    echo "This interactive tool helps you analyze and manage IP whitelists"
    echo "in fail2ban and firewall configurations."
    echo ""
    echo -e "$(print_colored "$CYAN" "Tip: Press Ctrl+C at any time to exit" "$NC")"
    if [[ "$FORCE_NO_COLOR" == true ]]; then
        echo "(Colors disabled)"
    fi
    echo ""
    pause
    
    # Start main menu
    main_menu
}

# Run main function
main "$@"

