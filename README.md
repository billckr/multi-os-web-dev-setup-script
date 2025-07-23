# Multi-OS Web Stack Builder Setup

A comprehensive, security-hardened bash script for installing complete web development stacks across multiple Linux distributions.

## Overview

This script provides bulletproof installation of web development environments with enterprise-grade security features. It supports RHEL-based, Debian-based, SUSE-based, and Arch-based Linux distributions with automatic OS detection and package manager selection.

## Features

- **Multi-OS Support**: Works across RHEL, Debian, SUSE, and Arch Linux families
- **Security Hardened**: Comprehensive input validation, secure file operations, and cryptographic password generation
- **Modular Architecture**: ~50 functions organized into logical groups for maintainability
- **Atomic Operations**: All-or-nothing installation with rollback capability
- **Comprehensive Logging**: Four-level logging system with verbose and concise modes
- **Easy Removal**: Complete uninstallation with `--remove` flag
- **Visual Progress Indicators**: Spinning cursors during long-running operations
- **Intelligent Dependency Management**: Automatic dependency checking and resolution
- **Multi-Version PHP Support**: Install multiple PHP versions simultaneously (8.2, 8.3, 8.4)
- **Non-Interactive Mode**: Command-line automation with --skip flag and --list-options for unattended installations

## Requirements

- **Root/sudo access**: Script must be run with root privileges
- **Supported OS**: RHEL/CentOS/AlmaLinux/Rocky, Ubuntu/Debian, openSUSE, Arch/Manjaro
- **Internet connection**: Required for package downloads
- **Minimum 1GB RAM**: Recommended for database installations
- **5GB+ free disk space**: Varies by selected components

## Usage

### Interactive Mode (Default)
```bash
# Basic installation (recommended)
sudo ./setup.sh

# Verbose installation with detailed logging  
sudo ./setup.sh --verbose

# Complete removal of all installed components
sudo ./setup.sh --remove

# Remove with detailed logging
sudo ./setup.sh --remove --verbose

# Show help (with color-coded sections and description)
sudo ./setup.sh --help
```

### Quick Preset Mode (Easiest)
```bash
# LAMP stack (Apache + MySQL + PHP 8.4 + Composer + Git)
sudo ./setup.sh --preset=lamp                # Shows confirmation prompt
sudo ./setup.sh --preset=lamp --auto         # Auto-proceeds without prompt

# LEMP stack (Nginx + MySQL + PHP 8.4 + Composer + Git)  
sudo ./setup.sh --preset=lemp                # Shows confirmation prompt
sudo ./setup.sh --preset=lemp --auto         # Auto-proceeds without prompt

# Minimal installation (Apache only)
sudo ./setup.sh --preset=minimal             # Shows confirmation prompt

# Full development environment (everything with sensible defaults)
sudo ./setup.sh --preset=full                # Shows confirmation prompt
```

### Non-Interactive Mode (Advanced)
```bash
# Single PHP version (becomes default automatically)
sudo ./setup.sh --non-interactive --webserver=apache --database=mysql --php=8.2

# Multiple PHP versions, explicit default (8.3 becomes default)
sudo ./setup.sh --non-interactive --webserver=nginx --database=postgresql,sqlite \
  --php=8.2,8.3,8.4 --php-default=8.3

# Multiple PHP versions, first becomes default (8.2 becomes default)
sudo ./setup.sh --non-interactive --webserver=apache --database=mysql \
  --php=8.2,8.3

# Development environment with domain
sudo ./setup.sh --non-interactive --webserver=nginx --database=mysql --php=8.4 \
  --package-managers=composer,nodejs --dev-tools=git,github-cli \
  --domain=dev.local --username=developer

# All non-interactive options
sudo ./setup.sh --non-interactive --help

# List available component values
sudo ./setup.sh --list-options

# Non-interactive removal (no prompts)
sudo ./setup.sh --non-interactive --remove
```

## Supported Components

### Web Servers
- **Apache**: Multi-OS package handling (httpd/apache2) with automatic configuration
- **Nginx**: Unified configuration with PHP-FPM integration (Unix socket or TCP)

### Databases
- **MySQL**: Enhanced installation with OS-specific authentication, pre-installation cleanup, and automatic initialization with secure random passwords
- **MariaDB**: Improved security setup with multiple authentication methods, automatic remnant cleanup, and development-ready credential management
- **PostgreSQL**: Robust installation with version-aware cleanup, OS-specific user creation, and sample database setup
- **SQLite**: Lightweight option with sample database creation
- **MongoDB**: NoSQL document database
- **Redis**: In-memory data structure store

**New (2025-07-23)**: All database installations now include comprehensive error handling, pre-installation cleanup of conflicting remnants, and OS-specific authentication methods for reliable installation on "dirty" systems.

### PHP Stack
- **Multi-Version Support**: PHP 8.2, 8.3, 8.4 (install multiple simultaneously)
- **RHEL/CentOS**: Uses Software Collections (SCL) packages for multiple versions
- **Debian/Ubuntu**: Native multi-version packages with update-alternatives
- **FPM Configuration**: Each version gets its own PHP-FPM service
- **Extension Management**: Common extensions installed per version per OS
- **Version Access**: Direct paths to specific versions (e.g., `/opt/remi/php82/root/usr/bin/php`)

### Package Managers
- **Composer**: PHP dependency management
- **Node.js + npm**: JavaScript package management and runtime

### Development Tools
- **Git**: Version control system
- **GitHub CLI**: Command-line interface for GitHub
- **Claude AI Code**: AI-powered coding assistant

### Security Features
- **Fail2ban**: Automatic SSH protection with IP whitelisting
- **Firewall Configuration**: OS-appropriate setup (firewalld/ufw)
- **Service Hardening**: Secure database initialization
- **Input Validation**: Comprehensive sanitization and validation
- **Secure File Operations**: Protected credential storage

### Essential System Tools (Always Installed)
These networking and monitoring tools are automatically installed and verified:
- **curl**: Command-line tool for transferring data with URLs
- **wget**: Command-line tool for downloading files from web servers
- **net-tools**: Collection of networking utilities (netstat, ifconfig, etc.)
- **netcat**: Network utility for reading/writing network connections
- **atop**: Advanced system and process monitor for performance analysis

### Dependency Management
- **Intelligent Checking**: Automatic dependency validation during component selection
- **Inline Resolution**: Prompts user to resolve dependencies without restarting
- **Example**: Selecting Composer without PHP prompts immediate PHP version selection
- **Auto-Dependencies**: Claude AI Code automatically includes Node.js requirement

## Installation Process

1. **System Detection**: Automatic OS and package manager identification
2. **User Configuration**: Domain setup, IP whitelisting, component selection
3. **Dependency Resolution**: Intelligent dependency checking with inline resolution
4. **Repository Setup**: Automatic configuration of required repositories
5. **Component Installation**: Modular installation with visual progress indicators
6. **Security Configuration**: Fail2ban, firewall, and service hardening
7. **Validation**: Post-installation verification of all components
8. **Summary**: Complete status report and next steps

## Security Enhancements

### Input Validation
- **Domain Validation**: RFC 1035 compliant with length limits
- **Username Validation**: System user conflict prevention (UID < 1000)
- **IP Validation**: IPv4/IPv6 with proper octet checking
- **Path Validation**: Prevention of directory traversal attacks

### Secure Operations
- **Password Generation**: Cryptographically secure 25-character passwords
- **File Creation**: Atomic operations with secure permissions (umask 077)
- **Credential Storage**: Protected files with 600 permissions
- **Input Sanitization**: Removal of shell metacharacters

### Vulnerability Mitigation
- **Command Injection**: Comprehensive input sanitization
- **SQL Injection**: Proper password escaping for database operations
- **Path Traversal**: Absolute path requirements and validation
- **Privilege Escalation**: Enhanced user validation
- **Credential Exposure**: Secure logging without sensitive information

## File Structure

```
/root/
├── setup.sh                    # Main installation script
├── setup-noninteractive.sh     # Non-interactive mode functionality
├── README.md                   # This documentation
├── CLAUDE.md                   # Project instructions for Claude Code
├── SCRIPT-REFERENCE.md          # Quick function reference
├── install-log-YYYYMMDD-HHMMSS.log  # Installation logs (auto-generated)
└── removal-log-YYYYMMDD-HHMMSS.log  # Removal logs (auto-generated)
```

### Generated Files (Database Credentials)
- **MySQL/MariaDB**: `/root/.my.cnf` (600 permissions)
- **PostgreSQL**: `/root/postgresql-info.txt` (600 permissions) - Delete after use
- **SQLite**: `/root/sqlite-info.txt` (600 permissions)

## Advanced Configuration

### PHP-FPM Socket vs TCP
- **Unix Socket** (default): 10-30% faster, more secure, simpler setup
- **TCP Configuration**: Better for load balancing, containers, remote PHP-FPM

### Domain and User Setup
- **Virtual Host Creation**: Automatic domain configuration
- **User Isolation**: Home directory structure `/home/username/public_html`
- **Test Pages**: Automatic creation of Hello World pages

### Multi-Version PHP Management
- **RHEL/CentOS Systems**: Uses SCL packages (`php82`, `php83`, `php84`)
- **Service Management**: Each version has its own PHP-FPM service
- **Version Access**: 
  - Default: `php` command (symlinked to selected default version)
  - Specific: `/opt/remi/php82/root/usr/bin/php`, `/opt/remi/php83/root/usr/bin/php`
- **Composer Integration**: Works with default PHP version
- **Complete Removal**: All versions and services cleaned up with `--remove`

### Firewall Configuration
- **Automatic Rules**: HTTP/HTTPS service configuration
- **IP Whitelisting**: SSH connection IP detection and whitelisting
- **VPN Detection**: Warning system for VPN usage during installation

## Troubleshooting

### Common Issues
- **Permission Denied**: Ensure script is run with sudo/root
- **Package Not Found**: Verify internet connection and repository setup
- **Service Failed**: Check system logs and firewall configuration
- **Database Connection**: Verify credentials in generated credential files
- **Command Not Found After Install**: Run `hash -r` to clear bash command cache and access newly installed commands immediately
- **Non-Interactive Fallback**: If non-interactive mode encounters invalid arguments, it falls back to interactive mode automatically
- **Unknown Component Values**: Use `sudo ./setup.sh --list-options` to see all available values for non-interactive mode
- **Non-Interactive Removal**: Use `sudo ./setup.sh --non-interactive --remove` for automated removal without prompts (preserves Claude AI Code for safety)
- **Invalid Username**: Non-interactive mode validates usernames with strict requirements: start with letter/underscore, lowercase letters/numbers/underscore/dash only, 3-32 chars, cannot be existing user. Invalid usernames fall back to interactive mode.
- **Nothing to Install**: If `--skip` is used with no components specified, shows immediate helpful error with preset suggestions instead of full installation summary

### Logs and Debugging
- **Installation Logs**: Detailed logs in `install-log-*.log`
- **Verbose Mode**: Use `--verbose` flag for detailed output
- **Visual Progress**: Spinning cursors show real-time progress during installations
- **Service Status**: Check with `systemctl status <service>`
- **Firewall Status**: Check with `firewall-cmd --list-all` or `ufw status`
- **Bash Cache Issues**: If commands show "not found" after installation/removal, run `hash -r` to clear command cache

### Database Installation Troubleshooting
- **Authentication Failed**: Database security setup now uses OS-specific methods. Check `/root/install-log-*.log` for specific authentication method used
- **Service Not Running**: Enhanced error diagnosis shows service status when database setup fails
- **Dirty System Issues**: Script now automatically cleans up:
  - Conflicting database services before installation
  - Corrupted/empty data directories (preserves valid databases)
  - Configuration files, socket files, and log files during removal
- **Previous Installation Remnants**: Use `sudo ./setup.sh --remove` for comprehensive cleanup before reinstalling
- **MySQL/MariaDB Access**: Credentials saved in `/root/.my.cnf` with 600 permissions
- **PostgreSQL Access**: Development credentials saved in `/root/postgresql-info.txt`

### Multiple PHP Versions Troubleshooting
- **Check installed versions**: `dnf list installed | grep php` (RHEL) or `dpkg -l | grep php` (Debian)
- **Service status**: `systemctl status php82-php-fpm php83-php-fpm php84-php-fpm`
- **Version testing**:
  ```bash
  php -v                                    # Default version
  /opt/remi/php82/root/usr/bin/php -v      # PHP 8.2
  /opt/remi/php83/root/usr/bin/php -v      # PHP 8.3  
  /opt/remi/php84/root/usr/bin/php -v      # PHP 8.4
  ```

## Quick Preset Options

| Preset | Components | Description |
|--------|------------|-------------|
| `--preset=lamp` | Apache + MySQL + PHP 8.3 + Composer + Git | Classic LAMP stack (shows confirmation) |
| `--preset=lemp` | Nginx + MySQL + PHP 8.3 + Composer + Git | Modern LEMP stack (shows confirmation) |
| `--preset=minimal` | Apache only | Lightweight web server (shows confirmation) |
| `--preset=full` | Nginx + MySQL + PostgreSQL + PHP 8.2,8.3 + Composer + Node.js + Git + Claude | Complete development environment (shows confirmation) |

**Auto-Proceed Option:** Add `--auto` flag to any preset to skip the confirmation prompt:
- `sudo ./setup.sh --preset=lamp --auto` (auto-proceeds without prompt)

## Supported Operating Systems

| Family | Distributions | Package Manager | Tested Versions |
|--------|---------------|-----------------|-----------------|
| RHEL | AlmaLinux, Rocky, CentOS, RHEL | dnf/yum | 8, 9 |
| Debian | Ubuntu, Debian | apt | 20.04+, 11+ |
| SUSE | openSUSE | zypper | Leap 15+ |
| Arch | Arch Linux, Manjaro | pacman | Rolling |

## Non-Interactive Mode Options

| Option | Description | Example |
|--------|-------------|---------|
| `--non-interactive` | Enable non-interactive mode | Required for automation |
| `--skip` | Default unspecified components to 'none' | Minimal installations |
| `--webserver=` | apache\|nginx\|none | `--webserver=nginx` |
| `--database=` | mysql,mariadb,postgresql,sqlite,none | `--database=mysql,postgresql` |
| `--php=` | 8.2,8.3,8.4 (comma-separated, multiple allowed) | `--php=8.2,8.3` |
| `--php-default=` | 8.2 (optional, sets default PHP version, uses first installed if not specified) | `--php-default=8.3` |
| `--package-managers=` | composer,nodejs,none | `--package-managers=composer` |
| `--dev-tools=` | git,github-cli,claude,none | `--dev-tools=git,claude` |
| `--domain=` | Domain for virtual host | `--domain=example.com` |
| `--username=` | Username for domain setup: start with letter/underscore, lowercase letters/numbers/underscore/dash only, 3-32 chars, cannot be existing user | `--username=webuser` |

**Note:** If `--php-default` is not specified or invalid, the first selected PHP version becomes the default.

## Contributing

This script follows strict security practices and comprehensive error handling. When modifying:

1. **Test thoroughly** across multiple OS distributions
2. **Maintain security standards** - validate all inputs
3. **Follow existing patterns** - use established functions and conventions
4. **Update documentation** - reflect changes in README and comments
5. **Preserve atomicity** - ensure rollback capability for failed installations
6. **Test non-interactive mode** - ensure fallback to interactive works properly

## License

This project is designed for defensive security purposes only. Use responsibly and in compliance with your organization's security policies.# Test push verification - Tue Jul 22 11:30:57 PM UTC 2025
