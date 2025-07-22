#!/bin/bash

# Whitelisted IPs Check Script
# Description: Comprehensive script to find all whitelisted IPs in fail2ban and firewall
# Compatible with: RHEL, Debian, SUSE, Arch Linux families
# Author: Web Development Setup Script Project
# Version: 1.0

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Print functions
print_header() {
    echo -e "${CYAN}================================================${NC}"
    echo -e "${CYAN}$1${NC}"
    echo -e "${CYAN}================================================${NC}"
}

print_section() {
    echo -e "\n${BLUE}--- $1 ---${NC}"
}

print_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_error "This script must be run as root or with sudo"
        print_info "Usage: sudo $0"
        exit 1
    fi
}

# Check if fail2ban is installed and running
check_fail2ban() {
    if ! command -v fail2ban-client >/dev/null 2>&1; then
        print_warning "fail2ban is not installed"
        return 1
    fi
    
    if ! systemctl is-active --quiet fail2ban; then
        print_warning "fail2ban service is not running"
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
    print_section "Fail2ban Whitelist Analysis"
    
    if ! check_fail2ban; then
        print_error "Cannot analyze fail2ban (not installed or not running)"
        return 1
    fi
    
    # Get fail2ban status
    print_info "Fail2ban service status:"
    systemctl status fail2ban --no-pager -l | head -5
    
    echo ""
    print_info "Active jails:"
    fail2ban-client status
    
    # Get active jails
    local jails
    jails=$(get_active_jails)
    
    if [[ -z "$jails" ]]; then
        print_warning "No active fail2ban jails found"
        return 1
    fi
    
    echo ""
    print_info "Checking ignoreip settings for each jail:"
    
    for jail in $jails; do
        echo -e "\n  ${CYAN}[$jail]${NC}"
        local ignoreip
        ignoreip=$(fail2ban-client get "$jail" ignoreip 2>/dev/null || echo "Unable to retrieve")
        
        if [[ "$ignoreip" == "Unable to retrieve" ]]; then
            echo "    Status: Unable to get ignoreip settings"
        elif [[ -z "$ignoreip" || "$ignoreip" == "[]" || "$ignoreip" == "" ]]; then
            echo "    Whitelisted IPs: None"
        else
            echo "    Whitelisted IPs: $ignoreip"
        fi
        
        # Get current banned IPs for context
        local banned
        banned=$(fail2ban-client get "$jail" banip 2>/dev/null || echo "Unable to retrieve")
        if [[ "$banned" != "Unable to retrieve" ]] && [[ -n "$banned" ]] && [[ "$banned" != "[]" ]]; then
            echo "    Currently banned: $banned"
        else
            echo "    Currently banned: None"
        fi
    done
}

# Check fail2ban configuration files
check_fail2ban_config() {
    print_section "Fail2ban Configuration Files"
    
    print_info "Global ignoreip settings:"
    
    # Check main configuration files
    local config_files=("/etc/fail2ban/jail.conf" "/etc/fail2ban/jail.local")
    local found_config=false
    
    for config_file in "${config_files[@]}"; do
        if [[ -f "$config_file" ]]; then
            echo -e "\n  ${CYAN}From $config_file:${NC}"
            grep -n "^ignoreip\|^#ignoreip" "$config_file" 2>/dev/null | head -10 || echo "    No ignoreip settings found"
            found_config=true
        fi
    done
    
    # Check jail.d directory
    if [[ -d "/etc/fail2ban/jail.d" ]]; then
        echo -e "\n  ${CYAN}From /etc/fail2ban/jail.d/:${NC}"
        find /etc/fail2ban/jail.d/ -name "*.conf" -exec grep -Hn "ignoreip" {} \; 2>/dev/null || echo "    No ignoreip settings found in jail.d"
    fi
    
    if [[ "$found_config" == false ]]; then
        print_warning "No fail2ban configuration files found"
    fi
}

# Check firewall rules
check_firewall_rules() {
    print_section "Firewall Whitelist Rules"
    
    # Check for different firewall systems
    if command -v firewall-cmd >/dev/null 2>&1; then
        print_info "Checking firewalld rules:"
        
        # Check rich rules (specific IP allows)
        echo -e "\n  ${CYAN}Rich rules with source addresses:${NC}"
        firewall-cmd --list-rich-rules | grep "source address" || echo "    No rich rules with source addresses found"
        
        # Check zones and their sources
        echo -e "\n  ${CYAN}Zones and their sources:${NC}"
        for zone in $(firewall-cmd --get-zones); do
            local sources
            sources=$(firewall-cmd --zone="$zone" --list-sources 2>/dev/null)
            if [[ -n "$sources" ]]; then
                echo "    Zone '$zone': $sources"
            fi
        done
        
        # Check trusted zone specifically
        echo -e "\n  ${CYAN}Trusted zone details:${NC}"
        firewall-cmd --zone=trusted --list-all || echo "    Trusted zone not configured"
        
    elif command -v ufw >/dev/null 2>&1; then
        print_info "Checking UFW rules:"
        
        echo -e "\n  ${CYAN}UFW status and rules:${NC}"
        ufw status numbered | grep -E "ALLOW|DENY" || echo "    No UFW rules found"
        
        echo -e "\n  ${CYAN}UFW rules allowing specific IPs:${NC}"
        ufw status | grep "ALLOW IN" | grep -v "Anywhere" | grep -E "[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+" || echo "    No specific IP rules found"
        
    else
        print_info "Checking iptables rules:"
        
        echo -e "\n  ${CYAN}INPUT chain rules:${NC}"
        iptables -L INPUT -n --line-numbers | grep -E "ACCEPT.*[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+" || echo "    No specific IP ACCEPT rules found"
        
        echo -e "\n  ${CYAN}All ACCEPT rules with source IPs:${NC}"
        iptables -L -n | grep -E "ACCEPT.*[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+" || echo "    No ACCEPT rules with source IPs found"
    fi
}

# Check system logs for recent whitelist activity
check_recent_activity() {
    print_section "Recent Whitelist Activity"
    
    print_info "Recent fail2ban log entries mentioning 'ignore':"
    if [[ -f "/var/log/fail2ban.log" ]]; then
        echo -e "\n  ${CYAN}Last 10 ignore-related entries:${NC}"
        grep -i "ignore" /var/log/fail2ban.log | tail -10 || echo "    No ignore-related entries found"
    else
        print_warning "/var/log/fail2ban.log not found"
    fi
    
    print_info "Recent systemd journal entries for fail2ban:"
    echo -e "\n  ${CYAN}Last 5 fail2ban journal entries:${NC}"
    journalctl -u fail2ban --no-pager -n 5 -o short 2>/dev/null || echo "    Unable to retrieve journal entries"
}

# Generate summary report
generate_summary() {
    print_section "Summary Report"
    
    local current_time
    current_time=$(date '+%Y-%m-%d %H:%M:%S')
    
    echo -e "${CYAN}Whitelist Analysis Summary${NC}"
    echo "Generated: $current_time"
    echo "Hostname: $(hostname)"
    echo "User: $(whoami)"
    
    echo -e "\n${CYAN}Quick Reference Commands:${NC}"
    echo "• Check all jails: fail2ban-client status"
    echo "• Get jail ignoreip: fail2ban-client get [jail] ignoreip"
    echo "• Add IP to ignore: fail2ban-client set [jail] addignoreip [IP]"
    echo "• Remove IP from ignore: fail2ban-client set [jail] delignoreip [IP]"
    echo "• Restart fail2ban: systemctl restart fail2ban"
    
    if command -v firewall-cmd >/dev/null 2>&1; then
        echo "• Add firewall rich rule: firewall-cmd --permanent --add-rich-rule='rule family=\"ipv4\" source address=\"IP\" accept'"
        echo "• Reload firewall: firewall-cmd --reload"
    elif command -v ufw >/dev/null 2>&1; then
        echo "• Allow IP in UFW: ufw allow from [IP]"
        echo "• UFW status: ufw status numbered"
    fi
}

# Main function
main() {
    # Parse command line arguments
    local verbose=false
    local output_file=""
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            -v|--verbose)
                verbose=true
                shift
                ;;
            -o|--output)
                output_file="$2"
                shift 2
                ;;
            -h|--help)
                echo "Usage: $0 [options]"
                echo ""
                echo "Options:"
                echo "  -v, --verbose    Show detailed output"
                echo "  -o, --output     Save output to file"
                echo "  -h, --help       Show this help message"
                echo ""
                echo "Examples:"
                echo "  sudo $0                    # Basic analysis"
                echo "  sudo $0 -v                # Verbose analysis"
                echo "  sudo $0 -o report.txt     # Save to file"
                exit 0
                ;;
            *)
                print_error "Unknown option: $1"
                print_info "Use -h or --help for usage information"
                exit 1
                ;;
        esac
    done
    
    # Redirect output to file if specified
    if [[ -n "$output_file" ]]; then
        exec > >(tee "$output_file")
        print_info "Output will be saved to: $output_file"
    fi
    
    print_header "WHITELIST IP ANALYSIS REPORT"
    
    # Check if running as root
    check_root
    
    # Run analysis functions
    check_fail2ban_whitelist
    check_fail2ban_config
    check_firewall_rules
    
    if [[ "$verbose" == true ]]; then
        check_recent_activity
    fi
    
    generate_summary
    
    echo ""
    print_info "Analysis complete!"
    
    if [[ -n "$output_file" ]]; then
        print_info "Report saved to: $output_file"
    fi
}

# Run main function
main "$@"

