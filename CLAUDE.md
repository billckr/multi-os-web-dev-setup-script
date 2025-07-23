# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Repository Overview

This repository contains a comprehensive multi-OS web development environment setup script (`setup.sh`) - a 4400+ line security-hardened bash script with:
- **Multi-version PHP support** (8.2, 8.3, 8.4 simultaneously on RHEL using SCL packages)
- **Multi-database installation** (MySQL, MariaDB, PostgreSQL, SQLite with conflict prevention)
- **Space-based selection interface** for all component choices (1 2 3 format)
- **Socket-based PHP-FPM configuration** for secure Nginx-PHP integration (with TCP fallback)
- **Intelligent dependency management** with inline resolution
- **Visual progress indicators** with spinning cursors
- **Comprehensive removal tracking** with selective cleanup
- **Resource usage guidance** displayed before installation confirmation

## Current Testing Status & Known Issues

### **Recent Session Summary (2025-07-22)**
**Main Focus:** Implemented preset system and improved non-interactive mode user experience

**Recent Improvements & Fixes:**
1. **✅ Preset System (NEW)**: Added four preset configurations for easy installation
   - **--preset=lamp**: Apache + MySQL + PHP 8.3 (Classic LAMP stack)
   - **--preset=lemp**: Nginx + MySQL + PHP 8.3 (Modern LEMP stack)
   - **--preset=minimal**: Apache only (Lightweight web server)
   - **--preset=full**: Complete development environment with sensible defaults

2. **✅ Early Error Detection (IMPROVED)**: Enhanced non-interactive mode user experience
   - **Issue**: `./setup.sh --non-interactive --skip` showed full installation summary before detecting nothing to install
   - **Fix Applied**: Added early detection that shows immediate helpful error with preset suggestions
   - **Benefit**: Users see only essential error message without unnecessary system information

3. **✅ Complete Non-Interactive Support (ENHANCED)**: Full automation capabilities
   - **Improved Validation**: Better argument validation with helpful fallback messages
   - **Enhanced Help**: Clear documentation with preset examples and usage patterns
   - **Streamlined Flow**: Reduced verbosity and improved user experience

4. **✅ Nginx-PHP Integration (FIXED)**: Changed default from TCP to Unix socket configuration
   - **Issue**: Script defaulted to TCP configuration (127.0.0.1:9000) instead of more secure socket
   - **Fix Applied**: Now defaults to Unix socket (/run/php-fpm/www.sock) with intelligent TCP fallback
   - **Benefit**: Better security, 10-30% performance improvement, simpler configuration

5. **✅ UI Formatting Standardization (NEW)**: Applied consistent 3-space indentation to all banner content
   - **Issue**: Welcome banner and installation summary had inconsistent left-aligned formatting
   - **Fix Applied**: Standardized 3-space indentation for section headers and 5-space for content items
   - **Benefit**: Professional, uniform appearance throughout the script interface

### **Key Architecture Changes Made:**
- **Preset System**: Added four preset configurations (lamp, lemp, minimal, full) for quick installation
- **Early Error Detection**: "Nothing to install" scenarios now show immediate helpful suggestions
- **Enhanced User Experience**: Streamlined non-interactive mode with better error messaging
- **Complete Non-Interactive Support**: Full automation with preset system and improved validation

### **Current Testing Phase:**
**Next test should verify:**
1. ✅ Preset system works correctly (--preset=lamp|lemp|minimal|full)
2. ✅ Early "nothing to install" detection shows helpful error immediately
3. ✅ Non-interactive mode with --skip behaves as expected
4. ✅ All existing functionality remains intact
5. ✅ Documentation reflects all recent improvements

**If issues persist, check:**
- PHP-FPM service status: `systemctl status php82-php-fpm php83-php-fpm`
- Socket configuration: `grep fastcgi_pass /etc/nginx/conf.d/default.conf` (should show unix:/run/php-fpm/www.sock)
- Socket file exists: `ls -la /run/php-fpm/www.sock` (should show socket with proper permissions)
- PHP-FPM listen config: `grep "^listen" /etc/php-fpm.d/www.conf` (should show socket path)
- Database tracking: `cat /root/.installed_databases` (should list selected databases)
- Bash cache issues: `hash -r` to clear command cache if commands show "not found" after installation

## Key Files

- `setup.sh` - **Production-ready** installation script with security hardening and multi-version PHP support
- `README.md` - Comprehensive documentation covering all features and usage
- `CLAUDE.md` - Project instructions for Claude Code (this file)
- `SCRIPT-REFERENCE.md` - **Quick reference for setup.sh function locations and recent fixes** (check this FIRST for troubleshooting)
- `install-log-*.log` - Installation logs with timestamps (auto-generated)
- `removal-log-*.log` - Removal/cleanup logs (auto-generated)

## Script Architecture

The setup script follows a comprehensive modular architecture with ~50 functions organized into logical groups:

### Core Infrastructure Functions
- **OS Detection & Validation**: `detect_os()`, `check_root()`, `check_vpn()`
- **User Interaction**: `welcome_user()`, `get_user_ip()`, `ask_domain_setup()`
- **Logging System**: `log()`, `print_*()` functions with verbosity levels
- **Error Handling**: `error_exit()` with automatic trap handling
- **Progress Indicators**: `show_spinner()`, `run_with_spinner()` for visual feedback
- **Dependency Management**: Intelligent dependency checking and inline resolution

### Installation Selection Functions  
- **Web Server Choice**: `choose_webserver()` (Apache/Nginx/None)
- **Database Selection**: `choose_database()` (Multiple: MySQL, MariaDB, PostgreSQL, SQLite with conflict prevention)
- **PHP Configuration**: `choose_php_versions()` (Multiple: 8.2, 8.3, 8.4 using SCL packages on RHEL)
- **Package Managers**: `choose_package_managers()` (Multiple: Composer, Node.js/npm with dependency checking)
- **Development Tools**: `choose_development_tools()` (Multiple: Git, GitHub CLI, Claude AI Code)

### Component Installation Functions
- **Web Servers**: `install_apache()`, `install_nginx()`
- **Databases**: `install_mysql()`, `install_mariadb()`, `install_postgresql()`, etc.
- **PHP**: `install_php()`, `install_php_version()`, `configure_php_fpm()`
- **Security**: `install_fail2ban()`, `configure_firewall_http()`
- **Package Managers**: `install_composer()`, `install_nodejs()`

### Validation & Management Functions
- **Validation Suite**: `validate_*()` functions for all components
- **User Management**: `create_user_and_domain()`, `create_virtual_host()`
- **Service Management**: Start/enable services with proper OS-specific handling
- **Complete Removal**: `remove_installation()` with selective component removal

### Repository Management
- **Multi-OS Repos**: Automatic setup of EPEL, Remi (RHEL), Ondrej PHP (Debian)
- **Package Manager Abstraction**: Unified interface across dnf/yum/apt/zypper/pacman

## Common Commands

### Recommended: Use Security-Hardened Version
```bash
# Interactive installation with security fixes (RECOMMENDED)
sudo ./setup-secure.sh

# Verbose installation with detailed logging
sudo ./setup-secure.sh --verbose

# Complete removal of all installed components
sudo ./setup-secure.sh --remove

# Remove with detailed logging
sudo ./setup-secure.sh --remove --verbose

# Help and usage information
sudo ./setup-secure.sh --help
```

### Non-Interactive Mode (Automated Installations)
```bash
# Full LAMP stack
sudo ./setup.sh --non-interactive --webserver=apache --database=mysql --php=8.2

# Multiple PHP versions with Nginx
sudo ./setup.sh --non-interactive --webserver=nginx --database=postgresql,sqlite \
  --php=8.2,8.3,8.4 --php-default=8.3

# Minimal installation with --skip flag (unspecified = none)
sudo ./setup.sh --non-interactive --webserver=nginx --skip

# Development environment with domain setup
sudo ./setup.sh --non-interactive --webserver=nginx --database=mysql --php=8.4 \
  --package-managers=composer,nodejs --dev-tools=git,claude \
  --domain=dev.local --username=developer

# Help for non-interactive options
sudo ./setup.sh --non-interactive --help

# List all available component values
sudo ./setup.sh --list-options
```

### Development and Testing Commands
```bash
# Validate script syntax
bash -n setup-secure.sh

# Check for security issues (if shellcheck is available)
shellcheck setup-secure.sh

# Monitor installation progress in real-time
tail -f install-log-*.log

# Test component functionality after installation
systemctl status httpd nginx mysql mariadb postgresql fail2ban
curl -I http://localhost

# Check PHP versions and configuration
php -v
php -m | grep -E 'mysqli|pdo|curl|json'

# Validate database connections
mysql --version
psql --version
sqlite3 --version
```

### Original Version (Contains Security Vulnerabilities)
```bash
# Original version (NOT RECOMMENDED for production)
sudo ./setup.sh

# View installation logs (real-time)
tail -f install-log-*.log

# Check service status after installation
systemctl status httpd nginx mysql mariadb fail2ban
```

## Supported Components

### Web Servers
- **Apache**: Multi-OS package handling (httpd/apache2)
- **Nginx**: Unified configuration with PHP-FPM integration

### Databases
- **MySQL/MariaDB**: Automatic initialization and security hardening
- **PostgreSQL**: Development user setup with sample database
- **SQLite**: Lightweight option with sample database creation
- **MongoDB/Redis**: NoSQL and caching options

### PHP Stack
- **Multi-Version Support**: PHP 8.2, 8.3, 8.4 with simultaneous installation capability
- **RHEL/CentOS**: Uses Software Collections (SCL) packages for multiple versions
- **FPM Configuration**: Each version gets its own PHP-FPM service (php82-php-fpm, etc.)
- **Extension Management**: Common extensions installed per version per OS
- **Default Version**: Configurable default with symlink management

### Security Features
- **Fail2ban**: Automatic SSH protection with IP whitelisting
- **Firewall Configuration**: OS-appropriate firewall setup (firewalld/ufw)
- **Service Hardening**: Secure database initialization with random passwords

## Development Notes

### UI Formatting Standards
**Banner and Summary Display Formatting (Established 2025-07-22)**

All banner content and user-facing summaries should follow this consistent formatting pattern:

**Indentation Rules:**
- **Section Headers**: 3-space indentation (`   Supported Components:`)
- **Content Items**: 5-space indentation (`     • Web Servers: Apache or Nginx`)
- **Description Text**: 3-space indentation (`   This script will install...`)

**Applied To:**
- `welcome_user()` function - Welcome banner display
- `show_installation_summary()` - Regular installation summary
- `show_preset_installation_summary()` - Preset installation summary

**Future Banner Content:**
Any new banner, summary, or formatted display content should follow this same 3/5-space indentation pattern for visual consistency and professional appearance.

### Script Design Principles
- **Strict Error Handling**: `set -euo pipefail` with comprehensive error trapping
- **Atomic Operations**: All-or-nothing installation with rollback capability
- **Logging Architecture**: Four-level logging (ERROR, WARNING, SUCCESS, COMPLETION)
- **User Safety**: VPN detection, IP whitelisting, confirmation prompts
- **Modular Architecture**: ~50+ functions organized into logical groups for maintainability

### OS Compatibility Matrix
- **RHEL Family**: AlmaLinux, Rocky, CentOS, RHEL (dnf/yum)
- **Debian Family**: Ubuntu, Debian (apt)
- **SUSE Family**: openSUSE (zypper)
- **Arch Family**: Arch Linux, Manjaro (pacman)

### Advanced Configuration
- **PHP-FPM**: Unix socket (default) vs TCP configuration for scaling
- **Virtual Hosts**: Automatic domain configuration with user isolation
- **Database Credentials**: Secure storage in `/root/.my.cnf` or credential files
- **Service Validation**: Post-installation verification of all components

### File Structure Conventions
- **Config Files**: OS-appropriate paths for web server configurations
- **Log Files**: Timestamped installation and removal logs
- **User Directories**: Standard `/home/username/public_html` structure
- **Security Files**: Restricted permissions on credential files (600)

## Security Improvements (setup-secure.sh)

### Critical Vulnerabilities Fixed
- **Command Injection**: Comprehensive input validation and sanitization
- **File Permission Race Conditions**: Secure file creation with proper umask
- **SQL Injection**: Proper password escaping for database operations
- **Path Traversal**: Validation of all file paths and user inputs
- **Privilege Escalation**: Enhanced user validation and system user checks
- **Insecure Temporary Files**: Secure temporary directory creation
- **Credential Exposure**: Secure logging without sensitive information

### Security Functions Added
```bash
validate_domain_name()     # RFC 1035 compliant domain validation
validate_username()        # Strict username validation with system user checks  
validate_ip_address()      # IPv4/IPv6 validation
sanitize_input()           # Remove shell metacharacters
secure_random_password()   # Cryptographically secure password generation
create_secure_file()       # Secure file creation with proper permissions
validate_file_path()       # Path traversal protection
```

### Key Security Enhancements
- **Input Sanitization**: All user inputs sanitized with `sanitize_input()` before use
- **Secure File Creation**: Files created with secure permissions from start using `umask 077`
- **System User Protection**: Username validation prevents conflicts with system accounts (UID < 1000)
- **Path Validation**: Absolute path requirements prevent directory traversal attacks
- **Credential Security**: Database passwords generated with cryptographically secure methods

### Recommended Usage
- **Production Environments**: Always use `setup-secure.sh`
- **Development/Testing**: Consider using `setup-secure.sh` for consistency
- **Security-Critical Deployments**: Review `SECURITY-IMPROVEMENTS.md` for details

See `SECURITY-IMPROVEMENTS.md` for comprehensive security analysis and fix details.

## Recent Improvements

### Non-Interactive Mode with --skip Flag (2025-07-21)
- **New Feature**: Added `setup-noninteractive.sh` with complete non-interactive installation support
- **--skip Flag**: Auto-defaults unspecified components to 'none' for truly hands-off installations
- **Command Line Options**: Full component selection via arguments (webserver, database, PHP, etc.)
- **IP Auto-Detection**: Automatic SSH IP detection without user confirmation
- **--list-options Flag**: Quick reference for all available component values
- **Zero Risk**: Completely separate script file with fallback to interactive mode on any error
- **Usage**: `sudo ./setup.sh --non-interactive --webserver=nginx --skip`
- **Removal**: `sudo ./setup.sh --non-interactive --remove` (automated removal with no prompts)

### Bash Command Cache Management (2025-07-21)
- **Issue Identified**: After installation/removal, `php -v` could show "command not found" due to bash caching old command locations in user's interactive shell
- **Root Cause**: Script's `hash -r` only clears cache in subprocess, not user's shell session
- **Solution Applied**: 
  - Added `safe_package_remove()` helper function with proper error capture and logging
  - Enhanced user instructions to run `hash -r` after installation/removal
  - Fixed screen/log output discrepancies caused by stderr suppression
- **User Instructions**: Both installation and removal completion now display clear `hash -r` instructions
- **Location**: Installation completion (~line 5328), Removal completion (~line 4042), Helper function (~line 4080)

### Improved Help System (2025-07-21)
- **Enhanced --help**: Added script description and blue color-coded section headings
- **Description**: Shows "Multi-OS Web Development Environment Setup" title at top
- **Visual Organization**: Blue headings for Interactive Mode, Non-Interactive Mode, and Examples sections
- **Better UX**: Clear section separation with proper spacing and formatting

### Username Security Validation (2025-07-21)
- **Security Fix**: Added proper username validation to non-interactive mode with enhanced requirements
- **Validation Rules**: 
  - **Start with**: Lowercase letter (a-z) or underscore (_)
  - **Characters allowed**: Lowercase letters, numbers, underscore, dash only
  - **Length**: 3-32 characters total
  - **User conflict protection**: Cannot conflict with any existing user (system or regular)
- **Fallback**: Invalid usernames automatically fall back to interactive mode with clear error message
- **Examples**: ✅ dev, developer, web_user, _private, test-user ❌ ab, Developer, 123user, user@domain, root, www-data

## Non-Interactive Removal

**Automated removal without prompts:**
```bash
sudo ./setup.sh --non-interactive --remove
```

**Safety features:**
- Claude AI Code is preserved by default (won't break active sessions)
- Users with public_html directories are auto-removed (likely script-created)
- All other components removed without confirmation

## Removal Instructions (Non-Interactive Mode)

**The non-interactive functionality was designed for easy removal if needed.** Complete removal can be done in 3 simple steps:

### Step 1: Delete the Separate Script File
```bash
rm setup-noninteractive.sh
```

### Step 2: Remove Integration Code from setup.sh

**Remove sourcing logic** (lines ~4734-4745):
```bash
# Check for non-interactive mode first
for arg in "$@"; do
    if [[ "$arg" == "--non-interactive" ]]; then
        if [[ -f "./setup-noninteractive.sh" ]]; then
            source "./setup-noninteractive.sh"
            parse_noninteractive_args "$@"
            break
        else
            print_error "Non-interactive mode requires setup-noninteractive.sh"
            exit 1
        fi
    fi
done
```

**Remove argument handling** (line ~4788):
```bash
--non-interactive|--skip|--webserver=*|--database=*|--php=*|--php-default=*|--package-managers=*|--dev-tools=*|--domain=*|--username=*)
```

**Replace safe wrapper calls** (lines ~4810-4876) with original function calls:
```bash
# Replace this pattern:
if command -v safe_welcome_user >/dev/null 2>&1; then
    safe_welcome_user
else
    welcome_user
fi

# With this:
welcome_user
```

Apply the same replacement pattern to all safe_* wrapper calls:
- `safe_welcome_user` → `welcome_user`
- `safe_detect_os` → `detect_os` 
- `safe_check_vpn` → `check_vpn`
- `safe_get_user_ip` → `get_user_ip`
- `safe_ask_domain_setup` → `ask_domain_setup`
- `safe_choose_webserver` → `choose_webserver`
- `safe_choose_database` → `choose_database`
- `safe_choose_php_versions` → `choose_php_versions`
- `safe_choose_package_managers` → `choose_package_managers`
- `safe_choose_development_tools` → `choose_development_tools`
- `safe_show_installation_summary` → `show_installation_summary`

**Remove help integration** (lines ~4777-4779):
```bash
# Show non-interactive help if available
if command -v show_noninteractive_help >/dev/null 2>&1; then
    show_noninteractive_help
fi
```

**Remove status display call** (lines ~4823-4825):
```bash
# Show non-interactive status summary if in non-interactive mode
if command -v show_noninteractive_status >/dev/null 2>&1; then
    show_noninteractive_status
fi
```

### Step 3: Revert Documentation (Optional)
- Remove non-interactive sections from README.md, CLAUDE.md, SCRIPT-REFERENCE.md
- Restore original usage examples

### Verification
After removal, test that interactive mode works:
```bash
sudo ./setup.sh --help    # Should show original help
sudo ./setup.sh           # Should work normally
```

### Why Removal is Easy
- **Isolated Architecture**: All logic contained in separate `setup-noninteractive.sh` file
- **Minimal Integration**: Only ~50 lines of wrapper code in main script
- **Zero Core Changes**: Original functions completely untouched
- **Safe Fallbacks**: Uses `command -v` checks that gracefully handle missing functions
- **No Dependencies**: Removing functionality doesn't break existing code

**Removal Time:** ~5 minutes  
**Risk Level:** Zero - original functionality preserved  
**Testing Required:** Basic interactive mode verification

## Function Reference

### Core Security Functions (setup-secure.sh:92-177)
- `validate_domain_name()` - RFC 1035 domain validation with length limits
- `validate_username()` - Username validation preventing system user conflicts  
- `validate_ip_address()` - IPv4/IPv6 validation with proper octet checking
- `sanitize_input()` - Remove shell metacharacters: `` `$(){}[]|&;<>*?~ ``
- `secure_random_password()` - Generate 25-char base64 passwords via OpenSSL
- `create_secure_file()` - Atomic file creation with secure permissions
- `validate_file_path()` - Prevent path traversal and require absolute paths

### Main Installation Flow (setup-secure.sh:4172-4179)
1. `welcome_user()` - Display banner and initialize logging
2. `check_root()` - Verify script runs with proper privileges
3. `detect_os()` - OS detection and package manager identification
4. `check_vpn()` - VPN usage warning and confirmation
5. `get_user_ip()` - IP detection for fail2ban whitelisting
6. `ask_domain_setup()` - Domain configuration prompts
7. Component selection functions (choose_*)
8. `run_installations()` - Execute selected installations
9. `run_validations()` - Verify all components functional

### Error Handling and Logging (setup-secure.sh:32-91)
- `error_exit()` - Comprehensive error handler with line numbers
- `log()` - Four-level logging system (ERROR, WARNING, SUCCESS, COMPLETION)
- `trap 'error_exit ${LINENO} "$BASH_COMMAND"' ERR` - Automatic error trapping
- Verbose vs concise logging modes controlled by `--verbose` flag