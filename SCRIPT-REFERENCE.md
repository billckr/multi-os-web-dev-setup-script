# Setup Script Quick Reference

## Key Function Locations

### Core Functions
- `welcome_user()` - Line ~450
- `detect_os()` - Line ~350
- `check_root()` - Line ~320
- `error_exit()` - Line ~32

### Non-Interactive Functions (setup-noninteractive.sh)
- `parse_noninteractive_args()` - Line 20
- `check_early_nothing_to_install()` - Line 59 (NEW: Early detection for empty --skip scenarios)
- `safe_welcome_user()` - Line 354
- `safe_choose_webserver()` - Line 137
- `safe_choose_database()` - Line 168
- `safe_choose_php_versions()` - Line 200
- `safe_choose_package_managers()` - Line 262
- `safe_choose_development_tools()` - Line 308
- `safe_show_installation_summary()` - Line 477
- `show_noninteractive_status()` - Line 381

### Installation Functions
- `install_mysql()` - Line 1178
- `install_php()` - Line 1603
- `configure_apache_php()` - Line 1817
- `configure_nginx_php()` - Line 1854
- `set_default_php_version()` - Line 1789

### Package Management Functions
- `safe_package_remove()` - Line 4080 (Package existence validation, error capture, consistent logging)

### Validation Functions
- `validate_php()` - Line 3439
- `run_validations()` - Line ~3800

### Repository Setup
- `setup_repositories()` - Line 1043
- Remi repo installation - Lines 1085-1087
- Ondrej PHP repo setup - Lines 1096-1098

### Removal/Cleanup
- Claude Code removal warning - Line 3920
- Main removal function - Line ~3800
- Removal completion message - Line 4002

### Output and Logging
- Install log display - Line 4998
- Service status display - Line 4759
- PHP version display in completion - Lines 4804-4819

## Recent Issue Locations

### Verbose Output Suppression (Fixed)
- PHP module commands - Lines 1667-1668
- Remi repo install - Lines 1085-1087  
- Ondrej repo setup - Lines 1096-1098

### PHP Version Issues
- Apache PHP config - Lines 1821-1851
- Default PHP selection - Lines 703-714
- PHP-FPM service names - Lines 1860-1870

### Text Formatting
- Resource usage headers - Lines 488, 495
- Log message formatting - Line 4998

## Configuration Files Created
- Apache: varies by OS
- Nginx: `/etc/nginx/conf.d/default.conf` (RHEL)
- PHP-FPM: Multiple services (php82-php-fpm, php83-php-fpm, etc.)

## Common Variables

### Interactive Mode Variables
- `DEFAULT_PHP_VERSION` - User-selected default PHP version
- `SELECTED_PHP_VERSIONS[]` - Array of selected PHP versions
- `PACKAGE_MANAGER` - Detected package manager (dnf/yum/apt/etc)
- `OS_NAME` - Detected OS name
- `LOG_FILE` - Installation log file path

### Non-Interactive Mode Variables (setup-noninteractive.sh)
- `NON_INTERACTIVE` - Boolean flag for non-interactive mode
- `SKIP_UNSPECIFIED` - Boolean flag for --skip functionality
- `CLI_WEBSERVER` - Command line webserver selection
- `CLI_DATABASE` - Command line database selection
- `CLI_PHP_VERSIONS` - Command line PHP versions
- `CLI_PHP_DEFAULT` - Command line default PHP version
- `CLI_PACKAGE_MANAGERS` - Command line package managers
- `CLI_DEV_TOOLS` - Command line development tools
- `CLI_DOMAIN` - Command line domain name
- `CLI_USERNAME` - Command line username (validated: start with letter/underscore, lowercase letters/numbers/underscore/dash only, 3-32 chars, cannot be existing user)

## Quick Fixes Applied
1. MySQL corruption fix - Lines 1210-1237
2. Claude Code process detection - Lines 3927-3962
3. PHP version display cleanup - Lines 4806-4814
4. Verbose output suppression - Multiple locations above
5. Bash command cache clearing - Lines 4857 (removal), 5309, 5318 (installation completion)
6. Non-interactive mode implementation - setup-noninteractive.sh (complete automation support)
7. --skip flag functionality - Auto-defaults unspecified components to 'none'
8. --list-options flag - Quick reference for all available component values (Line ~4815)
9. Non-interactive removal - Lines 3920-3930, 3947-3977, 4164-4176 (automated removal without prompts)
10. Improved help system - Lines 4795-4797 (script description and blue color-coded headings)
11. **Package removal improvements (2025-07-21)**: Added `safe_package_remove()` helper function (Line 4080) with proper error capture, package existence validation, and consistent screen/log output
12. **Preset system implementation (2025-07-22)**: Added four preset configurations (--preset=lamp|lemp|minimal|full) for quick installation - Lines 4989-5037
13. **Early error detection (2025-07-22)**: Added `check_early_nothing_to_install()` function to show immediate helpful error for empty --skip scenarios - setup-noninteractive.sh Lines 59-79, setup.sh Line 4870

## Non-Interactive Mode Usage

### Preset Examples (Easiest)
```bash
# Quick preset installations
sudo ./setup.sh --preset=lamp              # Apache + MySQL + PHP + Composer + Git
sudo ./setup.sh --preset=lemp              # Nginx + MySQL + PHP + Composer + Git
sudo ./setup.sh --preset=minimal           # Just Apache
sudo ./setup.sh --preset=full              # Everything with sensible defaults
```

### Advanced Non-Interactive Examples
```bash
# Minimal installation
sudo ./setup.sh --non-interactive --webserver=nginx --skip

# Full LAMP stack
sudo ./setup.sh --non-interactive --webserver=apache --database=mysql --php=8.2

# Multiple components
sudo ./setup.sh --non-interactive --webserver=nginx --database=mysql,postgresql \
  --php=8.2,8.3 --php-default=8.3 --package-managers=composer,nodejs

# List available values
sudo ./setup.sh --list-options

# Automated removal (no prompts)
sudo ./setup.sh --non-interactive --remove
```

### Key Features
- **Zero Risk**: Separate script file (setup-noninteractive.sh) with fallback
- **IP Auto-Detection**: No prompts for SSH IP confirmation
- **--skip Flag**: Defaults unspecified components to 'none'
- **--list-options**: Quick reference for all available component values
- **Validation**: All inputs validated with fallback to interactive mode
- **Help System**: Extended help with `--non-interactive --help`
- **Automated Removal**: Complete removal without prompts (preserves Claude AI Code for safety)
- **Improved Package Removal**: Uses `safe_package_remove()` for better error handling and logging consistency