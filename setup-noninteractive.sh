#!/bin/bash

# setup-noninteractive.sh
# Non-interactive mode functionality for setup.sh
# This file is sourced by setup.sh when --non-interactive flag is used

# Non-interactive mode global variables
NON_INTERACTIVE=false
SKIP_UNSPECIFIED=false
CLI_WEBSERVER=""
CLI_DATABASE=""
CLI_PHP_VERSIONS=""
CLI_PHP_DEFAULT=""
CLI_PACKAGE_MANAGERS=""
CLI_DEV_TOOLS=""
CLI_DOMAIN=""
CLI_USERNAME=""

# Parse non-interactive command line arguments
parse_noninteractive_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --non-interactive)
                NON_INTERACTIVE=true
                ;;
            --skip)
                SKIP_UNSPECIFIED=true
                ;;
            --webserver=*)
                CLI_WEBSERVER="${1#*=}"
                ;;
            --database=*)
                CLI_DATABASE="${1#*=}"
                ;;
            --php=*)
                CLI_PHP_VERSIONS="${1#*=}"
                ;;
            --php-default=*)
                CLI_PHP_DEFAULT="${1#*=}"
                ;;
            --package-managers=*)
                CLI_PACKAGE_MANAGERS="${1#*=}"
                ;;
            --dev-tools=*)
                CLI_DEV_TOOLS="${1#*=}"
                ;;
            --domain=*)
                CLI_DOMAIN="${1#*=}"
                ;;
            --username=*)
                CLI_USERNAME="${1#*=}"
                ;;
        esac
        shift
    done
}

# Early detection for "nothing to install" scenario
check_early_nothing_to_install() {
    if [[ "$NON_INTERACTIVE" == "true" && "$SKIP_UNSPECIFIED" == "true" ]]; then
        # Check if ALL component arguments are empty (which means --skip will set everything to none)
        if [[ -z "$CLI_WEBSERVER" && -z "$CLI_DATABASE" && -z "$CLI_PHP_VERSIONS" && \
              -z "$CLI_PACKAGE_MANAGERS" && -z "$CLI_DEV_TOOLS" ]]; then
            
            echo ""
            print_error "ERROR: No components selected for installation"
            echo ""
            echo "This configuration would install nothing. Did you mean:"
            echo "  sudo $0 --preset=lamp              # Apache + MySQL + PHP"
            echo "  sudo $0 --preset=lemp              # Nginx + MySQL + PHP"
            echo "  sudo $0 --preset=minimal           # Just Apache"
            echo "  sudo $0 --non-interactive --webserver=apache --skip  # Just Apache"
            echo "  sudo $0 --help                     # Show all options"
            echo ""
            log "ERROR" "No components selected for installation - exiting early"
            exit 1
        fi
    fi
}

# Validation functions
validate_webserver_choice() {
    local choice="$1"
    case "$choice" in
        apache|nginx|none)
            return 0
            ;;
        *)
            return 1
            ;;
    esac
}

validate_database_choice() {
    local choices="$1"
    IFS=',' read -ra DATABASES <<< "$choices"
    for db in "${DATABASES[@]}"; do
        case "$db" in
            mysql|mariadb|postgresql|sqlite|mongodb|redis|none)
                ;;
            *)
                return 1
                ;;
        esac
    done
    return 0
}

validate_php_versions() {
    local versions="$1"
    IFS=',' read -ra PHP_VERS <<< "$versions"
    for version in "${PHP_VERS[@]}"; do
        case "$version" in
            8.2|8.3|8.4)
                ;;
            *)
                return 1
                ;;
        esac
    done
    return 0
}

validate_php_default() {
    local default="$1"
    case "$default" in
        8.2|8.3|8.4)
            return 0
            ;;
        *)
            return 1
            ;;
    esac
}

# Safe wrapper functions that fallback to interactive mode on any error
safe_choose_webserver() {
    if [[ "$NON_INTERACTIVE" == "true" ]]; then
        if [[ -n "$CLI_WEBSERVER" ]]; then
            if validate_webserver_choice "$CLI_WEBSERVER"; then
                SELECTED_WEBSERVER="$CLI_WEBSERVER"
                print_info "Web server selected (non-interactive): $CLI_WEBSERVER"
                log "INFO" "Web server selected (non-interactive): $CLI_WEBSERVER"
                return 0
            else
                print_warning "Invalid webserver choice '$CLI_WEBSERVER', falling back to interactive"
                log "WARNING" "Invalid webserver choice '$CLI_WEBSERVER', falling back to interactive"
                NON_INTERACTIVE=false
            fi
        elif [[ "$SKIP_UNSPECIFIED" == "true" ]]; then
            # Use --skip flag to default to none
            SELECTED_WEBSERVER="none"
            print_info "Web server: none (--skip flag)"
            log "INFO" "Web server set to none (--skip flag)"
            return 0
        else
            # No specification and no --skip, fall back to interactive
            print_warning "No web server specified in non-interactive mode, falling back to interactive"
            log "WARNING" "No web server specified in non-interactive mode"
            NON_INTERACTIVE=false
        fi
    fi
    
    # Fallback to original interactive function
    choose_webserver
}

safe_choose_database() {
    if [[ "$NON_INTERACTIVE" == "true" ]]; then
        if [[ -n "$CLI_DATABASE" ]]; then
            if validate_database_choice "$CLI_DATABASE"; then
                # Parse comma-separated databases
                IFS=',' read -ra SELECTED_DATABASES <<< "$CLI_DATABASE"
                print_info "Databases selected (non-interactive): ${SELECTED_DATABASES[*]}"
                log "INFO" "Databases selected (non-interactive): ${SELECTED_DATABASES[*]}"
                return 0
            else
                print_warning "Invalid database choice '$CLI_DATABASE', falling back to interactive"
                log "WARNING" "Invalid database choice '$CLI_DATABASE', falling back to interactive"
                NON_INTERACTIVE=false
            fi
        elif [[ "$SKIP_UNSPECIFIED" == "true" ]]; then
            # Use --skip flag to default to none
            SELECTED_DATABASES=("none")
            print_info "Databases: none (--skip flag)"
            log "INFO" "Databases set to none (--skip flag)"
            return 0
        else
            # No specification and no --skip, fall back to interactive
            print_warning "No databases specified in non-interactive mode, falling back to interactive"
            log "WARNING" "No databases specified in non-interactive mode"
            NON_INTERACTIVE=false
        fi
    fi
    
    # Fallback to original interactive function
    choose_database
}

safe_choose_php_versions() {
    if [[ "$NON_INTERACTIVE" == "true" ]]; then
        if [[ -n "$CLI_PHP_VERSIONS" ]]; then
            if validate_php_versions "$CLI_PHP_VERSIONS"; then
                # Parse comma-separated PHP versions
                IFS=',' read -ra SELECTED_PHP_VERSIONS <<< "$CLI_PHP_VERSIONS"
                
                # Set default PHP version
                if [[ -n "$CLI_PHP_DEFAULT" ]]; then
                    if validate_php_default "$CLI_PHP_DEFAULT"; then
                        # Check if default is in selected versions
                        local found_default=false
                        for version in "${SELECTED_PHP_VERSIONS[@]}"; do
                            if [[ "$version" == "$CLI_PHP_DEFAULT" ]]; then
                                found_default=true
                                break
                            fi
                        done
                        
                        if [[ "$found_default" == "true" ]]; then
                            DEFAULT_PHP_VERSION="$CLI_PHP_DEFAULT"
                        else
                            print_warning "Default PHP version '$CLI_PHP_DEFAULT' not in selected versions, using first selected"
                            DEFAULT_PHP_VERSION="${SELECTED_PHP_VERSIONS[0]}"
                        fi
                    else
                        print_warning "Invalid default PHP version '$CLI_PHP_DEFAULT', using first selected"
                        DEFAULT_PHP_VERSION="${SELECTED_PHP_VERSIONS[0]}"
                    fi
                else
                    DEFAULT_PHP_VERSION="${SELECTED_PHP_VERSIONS[0]}"
                fi
                
                print_info "PHP versions selected (non-interactive): ${SELECTED_PHP_VERSIONS[*]}"
                print_info "Default PHP version (non-interactive): $DEFAULT_PHP_VERSION"
                log "INFO" "PHP versions selected (non-interactive): ${SELECTED_PHP_VERSIONS[*]}"
                log "INFO" "Default PHP version (non-interactive): $DEFAULT_PHP_VERSION"
                return 0
            else
                print_warning "Invalid PHP versions '$CLI_PHP_VERSIONS', falling back to interactive"
                log "WARNING" "Invalid PHP versions '$CLI_PHP_VERSIONS', falling back to interactive"
                NON_INTERACTIVE=false
            fi
        elif [[ "$SKIP_UNSPECIFIED" == "true" ]]; then
            # Use --skip flag to default to none (skip PHP installation)
            SELECTED_PHP_VERSIONS=("none")
            DEFAULT_PHP_VERSION=""
            print_info "PHP versions: none (--skip flag)"
            log "INFO" "PHP versions set to none (--skip flag)"
            return 0
        else
            # No specification and no --skip, fall back to interactive
            print_warning "No PHP versions specified in non-interactive mode, falling back to interactive"
            log "WARNING" "No PHP versions specified in non-interactive mode"
            NON_INTERACTIVE=false
        fi
    fi
    
    # Fallback to original interactive function
    choose_php_versions
}

safe_choose_package_managers() {
    if [[ "$NON_INTERACTIVE" == "true" ]]; then
        if [[ -n "$CLI_PACKAGE_MANAGERS" ]]; then
            # Parse comma-separated package managers
            IFS=',' read -ra SELECTED_PACKAGE_MANAGERS <<< "$CLI_PACKAGE_MANAGERS"
            
            # Validate each selection
            local valid=true
            for pm in "${SELECTED_PACKAGE_MANAGERS[@]}"; do
                case "$pm" in
                    composer|nodejs|none)
                        ;;
                    *)
                        valid=false
                        break
                        ;;
                esac
            done
            
            if [[ "$valid" == "true" ]]; then
                print_info "Package managers selected (non-interactive): ${SELECTED_PACKAGE_MANAGERS[*]}"
                log "INFO" "Package managers selected (non-interactive): ${SELECTED_PACKAGE_MANAGERS[*]}"
                return 0
            else
                print_warning "Invalid package manager choice '$CLI_PACKAGE_MANAGERS', falling back to interactive"
                log "WARNING" "Invalid package manager choice '$CLI_PACKAGE_MANAGERS', falling back to interactive"
                NON_INTERACTIVE=false
            fi
        elif [[ "$SKIP_UNSPECIFIED" == "true" ]]; then
            # Use --skip flag to default to none
            SELECTED_PACKAGE_MANAGERS=("none")
            print_info "Package managers: none (--skip flag)"
            log "INFO" "Package managers set to none (--skip flag)"
            return 0
        else
            # No specification and no --skip, fall back to interactive
            print_warning "No package managers specified in non-interactive mode, falling back to interactive"
            log "WARNING" "No package managers specified in non-interactive mode"
            NON_INTERACTIVE=false
        fi
    fi
    
    # Fallback to original interactive function
    choose_package_managers
}

safe_choose_development_tools() {
    if [[ "$NON_INTERACTIVE" == "true" ]]; then
        if [[ -n "$CLI_DEV_TOOLS" ]]; then
            # Parse comma-separated development tools
            IFS=',' read -ra SELECTED_DEVELOPMENT_TOOLS <<< "$CLI_DEV_TOOLS"
            
            # Validate each selection
            local valid=true
            for tool in "${SELECTED_DEVELOPMENT_TOOLS[@]}"; do
                case "$tool" in
                    git|github-cli|claude|none)
                        ;;
                    *)
                        valid=false
                        break
                        ;;
                esac
            done
            
            if [[ "$valid" == "true" ]]; then
                print_info "Development tools selected (non-interactive): ${SELECTED_DEVELOPMENT_TOOLS[*]}"
                log "INFO" "Development tools selected (non-interactive): ${SELECTED_DEVELOPMENT_TOOLS[*]}"
                return 0
            else
                print_warning "Invalid development tool choice '$CLI_DEV_TOOLS', falling back to interactive"
                log "WARNING" "Invalid development tool choice '$CLI_DEV_TOOLS', falling back to interactive"
                NON_INTERACTIVE=false
            fi
        elif [[ "$SKIP_UNSPECIFIED" == "true" ]]; then
            # Use --skip flag to default to none
            SELECTED_DEVELOPMENT_TOOLS=("none")
            print_info "Development tools: none (--skip flag)"
            log "INFO" "Development tools set to none (--skip flag)"
            return 0
        else
            # No specification and no --skip, fall back to interactive
            print_warning "No development tools specified in non-interactive mode, falling back to interactive"
            log "WARNING" "No development tools specified in non-interactive mode"
            NON_INTERACTIVE=false
        fi
    fi
    
    # Fallback to original interactive function
    choose_development_tools
}

safe_welcome_user() {
    if [[ "$NON_INTERACTIVE" == "true" ]]; then
        # In non-interactive mode, show banner but skip confirmation
        echo -e "\033[H\033[2J\033[3J"
        echo -e "${BLUE}===========================================================================${NC}"
        echo -e "${WHITE}                        Multi-OS Web Stack Builder${NC}"
        echo -e "${BLUE}===========================================================================${NC}"
        echo ""
        echo "This script will install and configure a complete web development stack"
        echo "including web server, PHP, database, and security tools."
        echo ""
        print_info "Running in non-interactive mode - proceeding automatically"
        
        # Add skip flag status if enabled
        if [[ "$SKIP_UNSPECIFIED" == "true" ]]; then
            print_info "Skip flag enabled - unspecified components will default to 'none'"
        fi
        
        log "INFO" "Running in non-interactive mode"
        return 0
    fi
    
    # Fallback to original interactive function
    welcome_user
}

# Function to show non-interactive status after IP detection  
show_noninteractive_status() {
    if [[ "$NON_INTERACTIVE" == "true" ]]; then
        # Detect IP early for status display
        local current_ip=""
        
        # Try to get IP from SSH_CLIENT environment variable
        if [[ -n "${SSH_CLIENT:-}" ]]; then
            current_ip=$(echo "$SSH_CLIENT" | awk '{print $1}')
        # Try to get IP from SSH_CONNECTION environment variable  
        elif [[ -n "${SSH_CONNECTION:-}" ]]; then
            current_ip=$(echo "$SSH_CONNECTION" | awk '{print $1}')
        # Try to get IP from WHO command
        elif command -v who >/dev/null 2>&1; then
            current_ip=$(who am i | awk '{print $5}' | sed 's/[()]//g')
        fi
        
        # Set USER_IP for later use and display in status
        if [[ -n "$current_ip" && "$current_ip" != "127.0.0.1" ]] && validate_ip_address "$current_ip"; then
            USER_IP="$current_ip"
            print_info "Auto-detected IP: $USER_IP"
        else
            USER_IP=""
            print_info "IP auto-detection: Failed (firewall may block access)"
        fi
    fi
}

safe_detect_os() {
    if [[ "$NON_INTERACTIVE" == "true" ]]; then
        # Call original detect_os function but set environment variable to skip confirmation
        SKIP_CONFIRMATION=true detect_os
    else
        # Call original interactive function
        detect_os
    fi
}

safe_check_vpn() {
    if [[ "$NON_INTERACTIVE" == "true" ]]; then
        # Skip VPN check in non-interactive mode
        print_info "Skipping VPN check (non-interactive mode)"
        log "INFO" "Skipping VPN check (non-interactive mode)"
        return 0
    else
        # Call original interactive function
        check_vpn
    fi
}

safe_get_user_ip() {
    if [[ "$NON_INTERACTIVE" == "true" ]]; then
        # IP detection already done in show_noninteractive_status, just log it
        if [[ -n "$USER_IP" ]]; then
            print_info "Using auto-detected IP for firewall whitelist: $USER_IP"
            log "INFO" "Using auto-detected IP for firewall whitelist: $USER_IP"
        else
            print_warning "No IP detected - firewall may block access"
            log "WARNING" "No IP detected for firewall whitelist"
        fi
        return 0
    else
        # Call original interactive function
        get_user_ip
    fi
}

safe_ask_domain_setup() {
    if [[ "$NON_INTERACTIVE" == "true" ]]; then
        if [[ -n "$CLI_DOMAIN" && -n "$CLI_USERNAME" ]]; then
            # Validate domain and username before accepting
            if validate_domain_name "$CLI_DOMAIN" && validate_username "$CLI_USERNAME"; then
                DOMAIN_NAME="$CLI_DOMAIN"
                USERNAME="$CLI_USERNAME"
                CREATE_USER=true
                print_info "Domain setup (non-interactive): $CLI_DOMAIN with user $CLI_USERNAME"
                log "INFO" "Domain setup (non-interactive): $CLI_DOMAIN with user $CLI_USERNAME"
                return 0
            else
                print_warning "Invalid domain '$CLI_DOMAIN' or username '$CLI_USERNAME' in non-interactive mode"
                log "WARNING" "Invalid domain '$CLI_DOMAIN' or username '$CLI_USERNAME', falling back to interactive"
                print_warning "Username requirements: lowercase letters/numbers/underscore/dash, start with letter/underscore, 3-32 chars, cannot be existing user"
                NON_INTERACTIVE=false
            fi
        else
            print_info "No domain/username specified in non-interactive mode, skipping domain setup"
            log "INFO" "No domain/username specified in non-interactive mode, skipping domain setup"
            DOMAIN_NAME=""
            USERNAME=""
            return 0
        fi
    fi
    
    # Fallback to original interactive function
    ask_domain_setup
}

# Display non-interactive help
safe_show_installation_summary() {
    if [[ "$NON_INTERACTIVE" == "true" ]]; then
        # Display summary WITHOUT calling original function (to avoid built-in prompt)
        echo ""
        echo -e "${BLUE}===========================================================================${NC}"
        echo -e "${WHITE}                           INSTALLATION SUMMARY${NC}"
        echo -e "${BLUE}===========================================================================${NC}"
        echo -e "${BLUE}Setup Options:${NC}"
        echo "  • Operating System: $OS_NAME $OS_VERSION"
        echo "  • Package Manager: $PACKAGE_MANAGER"
        echo "  • Web Server: $SELECTED_WEBSERVER"
        
        if [[ "${SELECTED_DATABASES[0]}" != "none" ]]; then
            echo "  • Databases: ${SELECTED_DATABASES[*]}"
        else
            echo "  • Database: none"
        fi
        
        if [[ "${SELECTED_PHP_VERSIONS[0]}" != "none" && -n "${SELECTED_PHP_VERSIONS[0]}" ]]; then
            echo "  • PHP Versions: ${SELECTED_PHP_VERSIONS[*]}"
            echo "  • Default PHP: $DEFAULT_PHP_VERSION"
        else
            echo "  • PHP Versions: None (skipped)"
        fi
        
        if [[ "${SELECTED_PACKAGE_MANAGERS[0]}" != "none" ]]; then
            echo "  • Package Managers: ${SELECTED_PACKAGE_MANAGERS[*]}"
        else
            echo "  • Package Managers: None (skipped)"
        fi
        
        if [[ "${SELECTED_DEVELOPMENT_TOOLS[0]}" != "none" ]]; then
            echo "  • Development Tools: ${SELECTED_DEVELOPMENT_TOOLS[*]}"
        else
            echo "  • Development Tools: None (skipped)"
        fi
        
        if [[ -n "$USER_IP" ]]; then
            echo "  • Firewall Whitelist IP: $USER_IP"
        fi
        
        echo ""
        echo -e "${BLUE}Components to install:${NC}"
        echo "  • $SELECTED_WEBSERVER web server"
        if [[ "${SELECTED_PHP_VERSIONS[0]}" != "none" && -n "${SELECTED_PHP_VERSIONS[0]}" ]]; then
            echo "  • PHP: ${SELECTED_PHP_VERSIONS[*]}"
        else
            echo "  • PHP: None (skipped)"
        fi
        echo "  • Fail2ban security service"
        echo "  • Firewall configuration"
        
        if [[ "$CREATE_USER" == true ]]; then
            echo "  • User account: $USERNAME"
            echo "  • Virtual host for: $DOMAIN_NAME"
        fi
        
        # Show resource usage
        local cpu_cores=$(nproc 2>/dev/null || echo "Unknown")
        local total_ram_gb=$(($(awk '/MemTotal/ {print int($2/1024/1024)}' /proc/meminfo 2>/dev/null || echo 0)))
        local available_disk_gb=$(($(df / | awk 'NR==2 {print int($4/1024/1024)}' 2>/dev/null || echo 0)))
        
        echo ""
        echo -e "${BLUE}System Resources:${NC}"
        echo "  • CPU Cores: $cpu_cores"
        echo "  • Total RAM: ${total_ram_gb}GB"
        echo "  • Available Disk Space: ${available_disk_gb}GB"
        
        echo ""
        echo -e "${BLUE}Resource Requirements ${WHITE}(Based on Selected)${BLUE}:${NC}"
        echo -e "${WHITE}Minimum Requirements (Basic LAMP/LEMP):${NC}"
        echo "  • 1 CPU core"
        echo "  • 1GB RAM"
        echo "  • 5GB disk space"
        
        echo ""
        echo -e "${BLUE}Recommended ${WHITE}(Full Development)${BLUE}:${NC}"
        echo "  • 2+ CPU cores"
        echo "  • 2GB+ RAM"
        echo "  • 10GB+ disk space"
        echo "  • Components: All web servers, multiple databases, multiple PHP versions"
        
        echo ""
        echo -e "${BLUE}Heavy Development Usage:${NC}"
        echo "  • 4+ CPU cores"
        echo "  • 4GB+ RAM"  
        echo "  • 20GB+ disk space"
        echo "  • Components: Multiple databases + Multiple PHP versions + All tools"
        
        echo ""
        echo -e "${BLUE}===========================================================================${NC}"
        echo ""
        
        # Auto-proceed only if explicitly in non-interactive mode or using --skip
        if [[ "$NON_INTERACTIVE" == "true" ]]; then
            if [[ "$SKIP_UNSPECIFIED" == "true" ]]; then
                print_info "Auto-proceeding with installation (--skip flag)"
                log "INFO" "Auto-proceeding with installation (--skip flag)"
            else
                print_info "Auto-proceeding with installation (non-interactive mode)"
                log "INFO" "Auto-proceeding with installation (non-interactive mode)"
            fi
            return 0
        else
            # Show confirmation prompt for interactive mode and presets (default behavior)
            read -p "Proceed with installation? (y/N): " -r
            if [[ ! $REPLY =~ ^[Yy]$ ]]; then
                print_info "Installation cancelled by user"
                log "INFO" "Installation cancelled by user at summary"
                exit 0
            fi
            log "INFO" "User confirmed installation"
            return 0
        fi
    else
        # Call original interactive function
        show_installation_summary
    fi
}

show_noninteractive_help() {
    echo ""
    echo "Non-Interactive Mode Options:"
    echo "  --non-interactive                 Enable non-interactive mode"
    echo "  --skip                            Skip unspecified components (default to 'none')"
    echo "  --webserver=apache|nginx|none     Select web server"
    echo "  --database=mysql,mariadb,postgresql,sqlite,mongodb,redis,none"
    echo "                                    Select databases (comma-separated)"
    echo "  --php=8.2,8.3,8.4                Select PHP versions (comma-separated, can install multiple)"  
    echo "  --php-default=8.2                 optional. If used sets default PHP version. If not, first PHP version installed is default"
    echo "  --package-managers=composer,nodejs,none"
    echo "                                    Select package managers (comma-separated)"
    echo "  --dev-tools=git,github-cli,claude,none"
    echo "                                    Select development tools (comma-separated)"
    echo "  --domain=example.com              Domain name for virtual host"
    echo "  --username=webuser                Username for domain setup: start with letter/underscore,"
    echo "                                    lowercase letters/numbers/underscore/dash only, 3-32 chars, cannot be existing user"
    echo ""
    echo "Examples:"
    echo "  # Single PHP version (becomes default automatically)"
    echo "  sudo $0 --non-interactive --webserver=apache --database=mysql --php=8.2"
    echo ""
    echo "  # Multiple PHP versions, explicit default (8.3 becomes default)"
    echo "  sudo $0 --non-interactive --webserver=nginx --database=postgresql,sqlite \\"
    echo "    --php=8.2,8.3,8.4 --php-default=8.3"
    echo ""
    echo "  # Multiple PHP versions, first becomes default (8.2 becomes default)"
    echo "  sudo $0 --non-interactive --webserver=apache --database=mysql \\"
    echo "    --php=8.2,8.3"
    echo ""
    echo "  # Minimal installation, skip unspecified components"
    echo "  sudo $0 --non-interactive --webserver=nginx --skip"
    echo ""
    echo "  # Development environment with domain"
    echo "  sudo $0 --non-interactive --webserver=nginx --database=mysql --php=8.3 \\"
    echo "    --package-managers=composer,nodejs --dev-tools=git,claude \\"
    echo "    --domain=dev.local --username=developer"
}

print_info "Non-interactive module loaded successfully"
log "INFO" "Non-interactive module loaded successfully"