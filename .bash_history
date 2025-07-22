echo "<p>Welcome to $DOMAIN_NAME</p>";
echo "<p>Server: " . \$_SERVER['HTTP_HOST'] . "</p>";
echo "<p>PHP Version: " . phpversion() . "</p>";
echo "<p>Current Time: " . date('Y-m-d H:i:s') . "</p>";
phpinfo();
?>
EOF
         chown "$USERNAME:$USERNAME" "$web_dir/index.php"    
    create_virtual_host         print_success "User and domain setup completed";     log "INFO" "User and domain setup completed"; }
# Create virtual host
create_virtual_host() {     print_info "Creating virtual host for $DOMAIN_NAME...";     log "INFO" "Creating virtual host for domain: $DOMAIN_NAME"         local vhost_config="";     local web_dir="/home/$USERNAME/public_html"         case "$SELECTED_WEBSERVER" in         apache)             case "$PACKAGE_MANAGER" in                 dnf|yum)                     vhost_config="/etc/httpd/conf.d/${DOMAIN_NAME}.conf";                     ;;                 apt)                     vhost_config="/etc/apache2/sites-available/${DOMAIN_NAME}.conf";                     ;;                 zypper)                     vhost_config="/etc/apache2/vhosts.d/${DOMAIN_NAME}.conf";                     ;;             esac            
            cat > "$vhost_config" <<EOF<VirtualHost *:80>
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
            
            if [[ "$PACKAGE_MANAGER" == "apt" ]]; then                 a2ensite "$DOMAIN_NAME";                 systemctl reload apache2;             else                 systemctl reload httpd;             fi;             ;;     esac         print_success "Virtual host created for $DOMAIN_NAME";     log "INFO" "Virtual host configuration completed"; }
# Install Fail2ban
install_fail2ban() {     print_info "Installing Fail2ban security service...";     log "INFO" "Starting Fail2ban installation"    
    install_package "fail2ban" "Fail2ban Security Service"    
    local ssh_logpath="";     local apache_error_logpath="";     local apache_access_logpath=""         case "$PACKAGE_MANAGER" in         dnf|yum)             ssh_logpath="/var/log/secure";             apache_error_logpath="/var/log/httpd/error_log";             apache_access_logpath="/var/log/httpd/access_log";             ;;         apt)             ssh_logpath="/var/log/auth.log";             apache_error_logpath="/var/log/apache2/error.log";             apache_access_logpath="/var/log/apache2/access.log";             ;;         zypper)             ssh_logpath="/var/log/messages";             apache_error_logpath="/var/log/apache2/error_log";             apache_access_logpath="/var/log/apache2/access_log";             ;;         pacman)             ssh_logpath="/var/log/auth.log";             apache_error_logpath="/var/log/httpd/error_log";             apache_access_logpath="/var/log/httpd/access_log";             ;;     esac    
    cat > /etc/fail2ban/jail.local <<EOF[DEFAULT]
# Ban time in seconds (1 hour)
bantime = 3600

# Find time window (10 minutes)
findtime = 600

# Number of failures before ban
maxretry = 5

# Ignore IP addresses (add user IP if provided)
ignoreip = 127.0.0.1/8 ::1
EOF

    if [[ -n "$USER_IP" ]]; then         sed -i "s/ignoreip = 127.0.0.1\/8 ::1/ignoreip = 127.0.0.1\/8 ::1 $USER_IP/" /etc/fail2ban/jail.local;         print_success "User IP $USER_IP added to Fail2ban ignore list";         log "INFO" "User IP $USER_IP added to Fail2ban ignore list";     fi    
    cat >> /etc/fail2ban/jail.local <<EOF
[sshd]
enabled = true
port = ssh
logpath = $ssh_logpath
maxretry = 3
EOF

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
    touch "$ssh_logpath" 2>/dev/null || true;     if [[ "$SELECTED_WEBSERVER" == "apache" ]]; then         touch "$apache_error_logpath" 2>/dev/null || true;         touch "$apache_access_logpath" 2>/dev/null || true;     fi    
    print_info "Starting Fail2ban service...";     if ! systemctl start fail2ban; then         print_warning "Fail2ban failed to start, checking configuration..."        
        if command -v fail2ban-client >/dev/null 2>&1; then             fail2ban-client -t;         fi        
        systemctl status fail2ban --no-pager || true        
        systemctl restart fail2ban || {             print_error "Failed to start Fail2ban service";             log "ERROR" "Fail2ban service failed to start";             return 1;         };     fi         systemctl enable fail2ban;     INSTALLED_SERVICES+=("fail2ban")         print_success "Fail2ban installed and configured successfully";     log "INFO" "Fail2ban installation completed"; }
# Validate Fail2ban
validate_fail2ban() {     print_info "Validating Fail2ban installation...";     log "INFO" "Validating Fail2ban service"    
    if systemctl is-active --quiet fail2ban; then         print_success "Fail2ban service is running";         log "INFO" "Fail2ban service validation: PASSED";     else         print_error "Fail2ban service is not running";         log "ERROR" "Fail2ban service validation: FAILED"        
        print_info "Debugging Fail2ban service status...";         systemctl status fail2ban --no-pager | head -10 | while read line; do             log "DEBUG" "Fail2ban status: $line";         done        
        if command -v fail2ban-client >/dev/null 2>&1; then             print_info "Testing Fail2ban configuration...";             if fail2ban-client -t 2>/dev/null; then                 print_info "Fail2ban configuration is valid";                 log "INFO" "Fail2ban configuration test: PASSED"                
                print_info "Attempting to restart Fail2ban service...";                 if systemctl restart fail2ban; then                     print_success "Fail2ban service restarted successfully";                     log "INFO" "Fail2ban service restart: SUCCESS";                 else                     print_error "Failed to restart Fail2ban service";                     log "ERROR" "Fail2ban service restart: FAILED";                     return 1;                 fi;             else                 print_error "Fail2ban configuration is invalid";                 log "ERROR" "Fail2ban configuration test: FAILED"                
                fail2ban-client -t 2>&1 | head -5 | while read line; do                     log "ERROR" "Fail2ban config error: $line";                 done;                 return 1;             fi;         fi        
        if ! systemctl is-active --quiet fail2ban; then             return 1;         fi;     fi    
    if command -v fail2ban-client >/dev/null 2>&1; then         local jail_status=$(fail2ban-client status 2>/dev/null | grep "Jail list:" | cut -d: -f2 | xargs);         if [[ -n "$jail_status" ]]; then             print_success "Active Fail2ban jails: $jail_status";             log "INFO" "Fail2ban jails validation: PASSED - $jail_status"            
            for jail in $jail_status; do                 local jail_info=$(fail2ban-client status "$jail" 2>/dev/null | grep -E "Currently failed|Currently banned" | xargs);                 if [[ -n "$jail_info" ]]; then                     print_info "Jail '$jail': $jail_info";                     log "INFO" "Fail2ban jail '$jail': $jail_info";                 fi;             done;         else             print_warning "No active Fail2ban jails found";             log "WARNING" "Fail2ban jails validation: WARNING";         fi;     fi         return 0; }
# Validation functions
validate_apache() {     print_info "Validating Apache installation...";     log "INFO" "Validating Apache service"         local service_name="";     case "$PACKAGE_MANAGER" in         dnf|yum)             service_name="httpd";             ;;         *)             service_name="apache2";             ;;     esac    
    if systemctl is-active --quiet "$service_name"; then         print_success "Apache service is running";         log "INFO" "Apache service validation: PASSED";     else         print_error "Apache service is not running";         log "ERROR" "Apache service validation: FAILED";         return 1;     fi    
    if netstat -tlnp 2>/dev/null | grep -q ":80 " || ss -tlnp 2>/dev/null | grep -q ":80 "; then         print_success "Apache is listening on port 80";         log "INFO" "Apache port 80 validation: PASSED";     else         print_error "Apache is not listening on port 80";         log "ERROR" "Apache port 80 validation: FAILED";         return 1;     fi    
    if command -v curl >/dev/null 2>&1; then         if curl -s -o /dev/null -w "%{http_code}" http://localhost | grep -q "200\|403"; then             print_success "Apache HTTP response test passed";             log "INFO" "Apache HTTP response validation: PASSED";         else             print_warning "Apache HTTP response test failed (this may be normal)";             log "WARNING" "Apache HTTP response validation: WARNING";         fi        
        local php_response=$(curl -s http://localhost/index.php 2>/dev/null | head -1);         if [[ "$php_response" == *"DOCTYPE html"* ]]; then             print_success "Apache PHP index.php test passed";             log "INFO" "Apache PHP index.php validation: PASSED";         else             print_warning "Apache PHP index.php test failed";             log "WARNING" "Apache PHP index.php validation: WARNING";         fi;     fi    
    local web_root="/var/www/html";     [[ "$PACKAGE_MANAGER" == "zypper" ]] && web_root="/srv/www/htdocs";     [[ "$PACKAGE_MANAGER" == "pacman" ]] && web_root="/srv/http"         if [[ -f "$web_root/index.php" ]]; then         print_success "Default index.php file exists at $web_root/index.php";         log "INFO" "Apache index.php file validation: PASSED";     else         print_error "Default index.php file missing at $web_root/index.php";         log "ERROR" "Apache index.php file validation: FAILED";         return 1;     fi         return 0; }
validate_nginx() {     print_info "Validating Nginx installation...";     log "INFO" "Validating Nginx service"         local service_name="nginx"    
    if systemctl is-active --quiet "$service_name"; then         print_success "Nginx service is running";         log "INFO" "Nginx service validation: PASSED";     else         print_error "Nginx service is not running";         log "ERROR" "Nginx service validation: FAILED";         return 1;     fi    
    if netstat -tlnp 2>/dev/null | grep -q ":80 " || ss -tlnp 2>/dev/null | grep -q ":80 "; then         print_success "Nginx is listening on port 80";         log "INFO" "Nginx port 80 validation: PASSED";     else         print_error "Nginx is not listening on port 80";         log "ERROR" "Nginx port 80 validation: FAILED";         return 1;     fi    
    if command -v curl >/dev/null 2>&1; then         if curl -s -o /dev/null -w "%{http_code}" http://localhost | grep -q "200\|403"; then             print_success "Nginx HTTP response test passed";             log "INFO" "Nginx HTTP response validation: PASSED";         else             print_warning "Nginx HTTP response test failed (this may be normal)";             log "WARNING" "Nginx HTTP response validation: WARNING";         fi        
        local php_response=$(curl -s http://localhost/index.php 2>/dev/null | head -1);         if [[ "$php_response" == *"DOCTYPE html"* ]]; then             print_success "Nginx PHP index.php test passed";             log "INFO" "Nginx PHP index.php validation: PASSED";         else             print_warning "Nginx PHP index.php test failed";             log "WARNING" "Nginx PHP index.php validation: WARNING";         fi;     fi    
    local web_root="/var/www/html";     case "$PACKAGE_MANAGER" in         dnf|yum)             web_root="/usr/share/nginx/html";             ;;         zypper)             web_root="/srv/www/htdocs";             ;;         pacman)             web_root="/usr/share/nginx/html";             ;;     esac         if [[ -f "$web_root/index.php" ]]; then         print_success "Default index.php file exists at $web_root/index.php";         log "INFO" "Nginx index.php file validation: PASSED";     else         print_error "Default index.php file missing at $web_root/index.php";         log "ERROR" "Nginx index.php file validation: FAILED";         return 1;     fi         return 0; }
validate_mysql() {     print_info "Validating MySQL installation...";     log "INFO" "Validating MySQL service"         local service_name="";     case "$PACKAGE_MANAGER" in         apt)             service_name="mysql";             ;;         *)             service_name="mysqld";             ;;     esac    
    if systemctl is-active --quiet "$service_name"; then         print_success "MySQL service is running";         log "INFO" "MySQL service validation: PASSED";     else         print_error "MySQL service is not running";         log "ERROR" "MySQL service validation: FAILED";         return 1;     fi    
    if netstat -tlnp 2>/dev/null | grep -q ":3306 " || ss -tlnp 2>/dev/null | grep -q ":3306 "; then         print_success "MySQL is listening on port 3306";         log "INFO" "MySQL port 3306 validation: PASSED";     else         print_error "MySQL is not listening on port 3306";         log "ERROR" "MySQL port 3306 validation: FAILED";         return 1;     fi    
    if mysql -e "SELECT 1;" >/dev/null 2>&1; then         print_success "MySQL connection test passed";         log "INFO" "MySQL connection validation: PASSED";     else         print_error "MySQL connection test failed";         log "ERROR" "MySQL connection validation: FAILED";         return 1;     fi         return 0; }
# Validate MariaDB installation
validate_mariadb() {     print_info "Validating MariaDB installation...";     log "INFO" "Validating MariaDB service"         local service_name="mariadb"    
    if systemctl is-active --quiet "$service_name"; then         print_success "MariaDB service is running";         log "INFO" "MariaDB service validation: PASSED";     else         print_error "MariaDB service is not running";         log "ERROR" "MariaDB service validation: FAILED";         return 1;     fi    
    if netstat -tlnp 2>/dev/null | grep -q ":3306 " || ss -tlnp 2>/dev/null | grep -q ":3306 "; then         print_success "MariaDB is listening on port 3306";         log "INFO" "MariaDB port 3306 validation: PASSED";     else         print_error "MariaDB is not listening on port 3306";         log "ERROR" "MariaDB port 3306 validation: FAILED";         return 1;     fi    
    if mysql -e "SELECT 1;" >/dev/null 2>&1; then         print_success "MariaDB connection test passed";         log "INFO" "MariaDB connection validation: PASSED";     else         print_error "MariaDB connection test failed";         log "ERROR" "MariaDB connection validation: FAILED";         return 1;     fi         return 0; }
validate_php() {     print_info "Validating PHP installation...";     log "INFO" "Validating PHP installation"    
    if command -v php >/dev/null 2>&1; then         local php_version=$(php -v | head -n 1);         print_success "PHP CLI available: $php_version";         log "INFO" "PHP CLI validation: PASSED - $php_version";     else         print_error "PHP CLI not available";         log "ERROR" "PHP CLI validation: FAILED";         return 1;     fi    
    if [[ "$CREATE_USER" == true ]]; then         local web_dir="/home/$USERNAME/public_html";         if [[ -f "$web_dir/index.php" ]]; then             print_success "PHP test page created at $web_dir/index.php";             log "INFO" "PHP test page validation: PASSED";         else             print_error "PHP test page not found";             log "ERROR" "PHP test page validation: FAILED";             return 1;         fi;     fi         return 0; }
# Run all installations
run_installations() {     print_info "Starting installation process...";     log "INFO" "Beginning installation phase"    
    update_system    
    setup_repositories    
    if [[ "$SELECTED_WEBSERVER" == "apache" ]]; then         install_apache;     elif [[ "$SELECTED_WEBSERVER" == "nginx" ]]; then         install_nginx;     fi    
    if [[ "$SELECTED_DATABASE" == "mysql" ]]; then         install_mysql;     elif [[ "$SELECTED_DATABASE" == "mariadb" ]]; then         install_mariadb;     elif [[ "$SELECTED_DATABASE" == "none" ]]; then         print_info "Skipping database installation as requested";         log "INFO" "Database installation skipped by user choice";     fi    
    install_php    
    if [[ "${SELECTED_PHP_VERSIONS[0]}" != "none" ]]; then         if [[ "$SELECTED_WEBSERVER" == "apache" ]]; then             configure_apache_php;         elif [[ "$SELECTED_WEBSERVER" == "nginx" ]]; then             configure_nginx_php;         fi;     else         print_info "Skipping web server PHP configuration (PHP not installed)";         log "INFO" "Web server PHP configuration skipped - PHP not installed";     fi    
    create_user_and_domain    
    install_fail2ban         print_success "Installation phase completed";     log "INFO" "Installation phase completed successfully"; }
# Detect OS for removal (simplified version)
detect_os_for_removal() {
         local os_name="";     local package_manager=""         if [[ -f /etc/os-release ]]; then         source /etc/os-release;         os_name="$NAME";     else         print_error "Cannot detect operating system";         exit 1;     fi    
    if command -v dnf >/dev/null 2>&1; then         package_manager="dnf";     elif command -v yum >/dev/null 2>&1; then         package_manager="yum";     elif command -v apt >/dev/null 2>&1; then         package_manager="apt";     elif command -v zypper >/dev/null 2>&1; then         package_manager="zypper";     elif command -v pacman >/dev/null 2>&1; then         package_manager="pacman";     else         print_error "Unsupported package manager";         exit 1;     fi         print_info "Detected OS: $os_name";     print_info "Package Manager: $package_manager"         log "INFO" "Removal mode - Detected OS: $os_name";     log "INFO" "Removal mode - Package manager: $package_manager"    
    export OS_NAME="$os_name";     export PACKAGE_MANAGER="$package_manager"; }
# Validate all installations
run_validations() {     print_info "Starting validation phase...";     log "INFO" "Beginning validation phase"         local validation_failed=false    
    if [[ "$SELECTED_WEBSERVER" == "apache" ]]; then         if ! validate_apache; then             validation_failed=true;         fi;     fi    
    if [[ "$SELECTED_WEBSERVER" == "nginx" ]]; then         if ! validate_nginx; then             validation_failed=true;         fi;     fi    
    if [[ "$SELECTED_DATABASE" == "mysql" ]]; then         if ! validate_mysql; then             validation_failed=true;         fi;     fi    
    if [[ "$SELECTED_DATABASE" == "mariadb" ]]; then         if ! validate_mariadb; then             validation_failed=true;         fi;     fi    
    if [[ "$SELECTED_DATABASE" == "none" ]]; then         print_info "Skipping database validation (none selected)";         log "INFO" "Database validation skipped - none selected";     fi    
    if [[ "${SELECTED_PHP_VERSIONS[0]}" != "none" ]]; then         if ! validate_php; then             validation_failed=true;         fi;     else         print_info "Skipping PHP validation (none selected)";         log "INFO" "PHP validation skipped - none selected";     fi    
    if ! validate_fail2ban; then         validation_failed=true;     fi         if [[ "$validation_failed" == true ]]; then         print_error "Some validations failed. Check the log for details.";         log "ERROR" "Validation phase completed with errors";         return 1;     else         print_success "All validations passed!";         log "INFO" "Validation phase completed successfully";         return 0;     fi; }
# Removal function
remove_installation() {     echo "===========================================================================";     echo "                        REMOVAL MODE";     echo "===========================================================================";     echo "This will remove all components installed by this script.";     echo ""    
    if [[ "$VERBOSE_LOGGING" != true ]]; then         print_info "Tip: Use './setup.sh --verbose --remove' for detailed removal logs.";         echo "";     fi    
    REMOVAL_LOG_FILE="${SCRIPT_DIR}/removal-log-$(date +%Y%m%d-%H%M%S).log";     LOG_FILE="$REMOVAL_LOG_FILE"  # Redirect logging to removal log
    touch "$REMOVAL_LOG_FILE"  # Create the removal log file
    
    detect_os_for_removal         log "COMPLETION" "Removal process initiated"         read -p "Are you sure you want to remove all installed components? (y/N): " -r;     if [[ ! $REPLY =~ ^[Yy]$ ]]; then         print_info "Removal cancelled";         log "INFO" "Removal cancelled by user";         exit 0;     fi         print_info "Starting removal process...";     log "COMPLETION" "Starting removal process"    
    stop_all_services    
    remove_fail2ban    
    remove_user_and_domain    
    remove_php    
    remove_database    
    remove_webserver    
    remove_repositories    
    cleanup_firewall    
    final_cleanup         echo "";     print_success "===========================================";     print_success "   REMOVAL COMPLETED SUCCESSFULLY";     print_success "===========================================";     print_info "All components have been removed from the system.";     print_info "The server has been restored to its original state."         log "COMPLETION" "Removal process completed successfully";     log "COMPLETION" "All components removed from the system";     log "COMPLETION" "Server restored to original state"         echo "";     print_success "Removal log saved to: $REMOVAL_LOG_FILE"         if [[ "$VERBOSE_LOGGING" != true ]]; then         echo "";         print_info "Note: Only errors, warnings, and completion messages were logged.";         print_info "Use '$0 --verbose --remove' for detailed removal logs.";     fi         exit 0; }
# Stop all services
stop_all_services() {     print_info "Stopping all installed services...";     log "COMPLETION" "Stopping services"         local services_to_stop=("fail2ban" "httpd" "apache2" "nginx" "mysqld" "mysql" "php-fpm" "php8.2-fpm" "php8.3-fpm" "php8.4-fpm")         for service in "${services_to_stop[@]}"; do         if systemctl is-active --quiet "$service" 2>/dev/null; then             if [[ "$VERBOSE_LOGGING" == true ]]; then                 print_info "Stopping service: $service";             fi;             systemctl stop "$service" 2>/dev/null || true;             systemctl disable "$service" 2>/dev/null || true;             log "INFO" "Service stopped and disabled: $service";         fi;     done         print_success "Services stopped";     log "COMPLETION" "All applicable services stopped"; }
# Remove Fail2ban
remove_fail2ban() {     print_info "Removing Fail2ban...";     log "COMPLETION" "Removing Fail2ban"    
    if [[ -f /etc/fail2ban/jail.local ]]; then         rm -f /etc/fail2ban/jail.local;         log "INFO" "Removed Fail2ban configuration: jail.local";     fi    
    local removal_success=true;     case "$PACKAGE_MANAGER" in         dnf|yum)             if ! dnf remove -y fail2ban 2>/dev/null; then                 removal_success=false;             fi;             ;;         apt)             if ! apt-get remove --purge -y fail2ban 2>/dev/null || ! apt-get autoremove -y 2>/dev/null; then                 removal_success=false;             fi;             ;;         zypper)             if ! zypper remove -y fail2ban 2>/dev/null; then                 removal_success=false;             fi;             ;;         pacman)             if ! pacman -Rs --noconfirm fail2ban 2>/dev/null; then                 removal_success=false;             fi;             ;;     esac         if [[ "$removal_success" == true ]]; then         print_success "Fail2ban removed";         log "COMPLETION" "Fail2ban removal completed successfully";     else         print_warning "Fail2ban removal completed with warnings";         log "WARNING" "Fail2ban removal completed with some failures";     fi; }
# Remove user and domain setup
remove_user_and_domain() {     print_info "Removing user accounts and domain configurations...";     log "INFO" "Removing user and domain setup"    
    case "$PACKAGE_MANAGER" in         dnf|yum)             rm -f /etc/httpd/conf.d/*.conf 2>/dev/null || true;             ;;         apt)
            for site in /etc/apache2/sites-available/*.conf; do                 if [[ -f "$site" && "$site" != "/etc/apache2/sites-available/000-default.conf" && "$site" != "/etc/apache2/sites-available/default-ssl.conf" ]]; then                     sitename=$(basename "$site" .conf);                     a2dissite "$sitename" 2>/dev/null || true;                     rm -f "$site";                     log "INFO" "Removed Apache site: $sitename";                 fi;             done;             ;;         zypper)             rm -f /etc/apache2/vhosts.d/*.conf 2>/dev/null || true;             ;;     esac    
    if [[ -n "$USERNAME" ]] && id "$USERNAME" >/dev/null 2>&1; then         print_info "Removing user: $USERNAME";         userdel -r "$USERNAME" 2>/dev/null || true;         log "INFO" "User removed: $USERNAME";     fi    
    for user_home in /home/*/public_html; do         if [[ -d "$user_home" ]]; then             local username=$(basename "$(dirname "$user_home")");             if [[ "$username" != "root" && "$username" != "." && "$username" != ".." ]]; then                 print_info "Found user with public_html: $username";                 read -p "Remove user $username? (y/N): " -r;                 if [[ $REPLY =~ ^[Yy]$ ]]; then                     userdel -r "$username" 2>/dev/null || true;                     log "INFO" "User removed: $username";                 fi;             fi;         fi;     done         print_success "User and domain cleanup completed"; }
# Remove PHP
remove_php() {     print_info "Starting PHP removal...";     log "INFO" "Removing PHP"         case "$PACKAGE_MANAGER" in         dnf|yum)             print_info "Removing PHP packages via $PACKAGE_MANAGER..."
            dnf module reset php -y 2>/dev/null || true            
            local php_packages=(                 "php" "php-cli" "php-fpm" "php-common" "php-mysql" "php-xml"                  "php-json" "php-curl" "php-mbstring" "php-zip" "php-gd"                  "php-intl" "php-opcache"             )                         for package in "${php_packages[@]}"; do                 print_info "Removing package: $package";                 dnf remove -y "$package" 2>/dev/null || true;             done;             ;;         apt)             print_info "Removing PHP packages via $PACKAGE_MANAGER..."
            local php_versions=("8.2" "8.3" "8.4");             for version in "${php_versions[@]}"; do                 print_info "Removing PHP $version...";                 local php_packages=(                     "php$version" "php$version-cli" "php$version-fpm" "php$version-common"                     "php$version-mysql" "php$version-xml" "php$version-curl" "php$version-mbstring"                     "php$version-zip" "php$version-gd" "php$version-intl" "php$version-opcache"                 )                                 for package in "${php_packages[@]}"; do                     apt-get remove --purge -y "$package" 2>/dev/null || true;                 done;             done            
            apt-get remove --purge -y php-common 2>/dev/null || true;             apt-get autoremove -y 2>/dev/null || true;             ;;         zypper)             print_info "Removing PHP packages via $PACKAGE_MANAGER..."
            zypper remove -y php82* php83* php84* 2>/dev/null || true;             ;;         pacman)             print_info "Removing PHP packages via $PACKAGE_MANAGER...";             pacman -Rs --noconfirm php php-fpm 2>/dev/null || true;             ;;         *)             print_warning "Unknown package manager: $PACKAGE_MANAGER";             ;;     esac    
    rm -rf /etc/php* 2>/dev/null || true         print_success "PHP removed";     log "INFO" "PHP removal completed"; }
# Remove database
remove_database() {     print_info "Starting database removal...";     log "INFO" "Removing database"         case "$PACKAGE_MANAGER" in         dnf|yum)             print_info "Removing database packages via $PACKAGE_MANAGER..."
            dnf remove -y mysql-server mysql mariadb-server mariadb 2>/dev/null || true;             ;;         apt)             print_info "Removing database packages via $PACKAGE_MANAGER..."
            apt-get remove --purge -y mysql-server mysql-client mysql-common 2>/dev/null || true;             apt-get remove --purge -y mariadb-server mariadb-client mariadb-common 2>/dev/null || true;             apt-get autoremove -y 2>/dev/null || true;             ;;         zypper)             print_info "Removing database packages via $PACKAGE_MANAGER...";             zypper remove -y mysql mysql-server mariadb mariadb-server 2>/dev/null || true;             ;;         pacman)             print_info "Removing database packages via $PACKAGE_MANAGER...";             pacman -Rs --noconfirm mysql mariadb 2>/dev/null || true;             ;;         *)             print_warning "Unknown package manager: $PACKAGE_MANAGER";             ;;     esac    
    print_info "Removing database data directories...";     rm -rf /var/lib/mysql* 2>/dev/null || true;     rm -rf /var/lib/mariadb* 2>/dev/null || true    
    rm -f /root/.my.cnf 2>/dev/null || true;     rm -rf /etc/mysql* 2>/dev/null || true;     rm -rf /etc/mariadb* 2>/dev/null || true         print_success "Database removed";     log "INFO" "Database removal completed"; }
# Remove web server
remove_webserver() {     print_info "Starting web server removal...";     log "INFO" "Removing web server"         case "$PACKAGE_MANAGER" in         dnf|yum)             print_info "Removing web server packages via $PACKAGE_MANAGER..."
            dnf remove -y httpd httpd-tools 2>/dev/null || true
            dnf remove -y nginx 2>/dev/null || true;             ;;         apt)             print_info "Removing web server packages via $PACKAGE_MANAGER..."
            apt-get remove --purge -y apache2 apache2-utils apache2-bin apache2-data 2>/dev/null || true
            apt-get remove --purge -y nginx nginx-common nginx-core 2>/dev/null || true;             apt-get autoremove -y 2>/dev/null || true;             ;;         zypper)             print_info "Removing web server packages via $PACKAGE_MANAGER...";             zypper remove -y apache2 nginx 2>/dev/null || true;             ;;         pacman)             print_info "Removing web server packages via $PACKAGE_MANAGER...";             pacman -Rs --noconfirm apache nginx 2>/dev/null || true;             ;;         *)             print_warning "Unknown package manager: $PACKAGE_MANAGER";             ;;     esac    
    rm -rf /etc/httpd* 2>/dev/null || true;     rm -rf /etc/apache2* 2>/dev/null || true;     rm -rf /etc/nginx* 2>/dev/null || true    
    rm -rf /var/www* 2>/dev/null || true;     rm -rf /var/log/httpd* 2>/dev/null || true;     rm -rf /var/log/apache2* 2>/dev/null || true;     rm -rf /var/log/nginx* 2>/dev/null || true         print_success "Web server removed";     log "INFO" "Web server removal completed"; }
# Remove repositories
remove_repositories() {     print_info "Removing added repositories...";     log "INFO" "Removing repositories"         case "$PACKAGE_MANAGER" in         dnf|yum)
            dnf remove -y remi-release 2>/dev/null || true
            ;;         apt)
            add-apt-repository --remove -y ppa:ondrej/php 2>/dev/null || true;             apt-get update 2>/dev/null || true;             ;;         zypper)
            zypper removerepo php 2>/dev/null || true;             ;;     esac         print_success "Repositories cleaned up";     log "INFO" "Repository cleanup completed"; }
# Clean up firewall rules
cleanup_firewall() {     print_info "Cleaning up firewall rules...";     log "INFO" "Cleaning up firewall"         if command -v firewall-cmd >/dev/null 2>&1; then
        firewall-cmd --permanent --remove-service=http 2>/dev/null || true;         firewall-cmd --permanent --remove-service=https 2>/dev/null || true        
        if [[ -n "$USER_IP" ]]; then             firewall-cmd --permanent --remove-rich-rule="rule family='ipv4' source address='$USER_IP' accept" 2>/dev/null || true;         fi                 firewall-cmd --reload 2>/dev/null || true;         print_success "Firewall rules cleaned up"             elif command -v ufw >/dev/null 2>&1; then
        ufw delete allow 'Apache Full' 2>/dev/null || true;         ufw delete allow 'Apache' 2>/dev/null || true        
        if [[ -n "$USER_IP" ]]; then             ufw delete allow from "$USER_IP" 2>/dev/null || true;         fi                 print_success "UFW rules cleaned up";     fi         log "INFO" "Firewall cleanup completed"; }
# Final cleanup
final_cleanup() {     print_info "Performing final cleanup...";     log "INFO" "Final cleanup"    
    case "$PACKAGE_MANAGER" in         dnf)             dnf clean all 2>/dev/null || true;             ;;         yum)             yum clean all 2>/dev/null || true;             ;;         apt)             apt-get autoclean 2>/dev/null || true;             apt-get autoremove -y 2>/dev/null || true;             ;;         zypper)             zypper clean 2>/dev/null || true;             ;;         pacman)             pacman -Sc --noconfirm 2>/dev/null || true;             ;;     esac    
    rm -f /etc/fail2ban/jail.local 2>/dev/null || true    
    rm -f /tmp/install-* 2>/dev/null || true         print_success "Final cleanup completed";     log "INFO" "Final cleanup completed"; }
# Main function
main() {
    while [[ $# -gt 0 ]]; do         case $1 in             --remove)
                if [[ "${2:-}" == "--verbose" || "${2:-}" == "-v" ]]; then                     VERBOSE_LOGGING=true;                     shift;                 fi;                 remove_installation;                 ;;             --verbose|-v)                 VERBOSE_LOGGING=true
                if [[ "${2:-}" == "--remove" ]]; then                     shift;                     remove_installation;                 fi;                 shift;                 ;;             --help|-h)                 echo "Usage: sudo $0 [options]";                 echo "";                 echo "Options:";                 echo "  --remove              Remove all installed components";                 echo "  --verbose, -v         Enable verbose logging";                 echo "  --remove --verbose    Remove with detailed logging";                 echo "  --help, -h            Show this help message";                 echo "";                 exit 0;                 ;;             *)                 print_error "Unknown option: $1";                 echo "Use --help for usage information";                 exit 1;                 ;;         esac;     done    
    if [[ -z "$LOG_FILE" ]]; then         LOG_FILE="${SCRIPT_DIR}/install-log-$(date +%Y%m%d-%H%M%S).log";         touch "$LOG_FILE";     fi    
    welcome_user;     check_root;     detect_os;     check_vpn;     get_user_ip;     ask_domain_setup;     choose_webserver;     choose_database;     choose_php_versions;     show_installation_summary    
    run_installations    
    if run_validations; then         echo "";         print_success "==========================================";         print_success "   INSTALLATION COMPLETED SUCCESSFULLY";         print_success "=========================================="                 log "COMPLETION" "Installation completed successfully"                 if [[ "$CREATE_USER" == true ]]; then             echo "";             print_info "Domain Setup:";             print_info "  • Domain: $DOMAIN_NAME";             print_info "  • User: $USERNAME";             print_info "  • Web Directory: /home/$USERNAME/public_html";             print_info "  • Test Page: http://$DOMAIN_NAME or http://$(hostname -I | awk '{print $1}')";             log "COMPLETION" "Domain setup - Domain: $DOMAIN_NAME, User: $USERNAME";         fi                 echo "";         print_info "Service Status:";         if [[ "$SELECTED_WEBSERVER" == "apache" ]]; then             local apache_service="httpd";             [[ "$PACKAGE_MANAGER" == "apt" ]] && apache_service="apache2";             local apache_status=$(systemctl is-active $apache_service);             print_info "  • Apache: $apache_status";             log "COMPLETION" "Apache service status: $apache_status";         elif [[ "$SELECTED_WEBSERVER" == "nginx" ]]; then             local nginx_status=$(systemctl is-active nginx);             print_info "  • Nginx: $nginx_status";             log "COMPLETION" "Nginx service status: $nginx_status";         fi                 if [[ "$SELECTED_DATABASE" == "mysql" ]]; then             local mysql_service="mysqld";             [[ "$PACKAGE_MANAGER" == "apt" ]] && mysql_service="mysql";             local mysql_status=$(systemctl is-active $mysql_service);             print_info "  • MySQL: $mysql_status";             log "COMPLETION" "MySQL service status: $mysql_status";         elif [[ "$SELECTED_DATABASE" == "mariadb" ]]; then             local mariadb_status=$(systemctl is-active mariadb);             print_info "  • MariaDB: $mariadb_status";             log "COMPLETION" "MariaDB service status: $mariadb_status";         elif [[ "$SELECTED_DATABASE" == "none" ]]; then             print_info "  • Database: None installed (as requested)";             log "COMPLETION" "Database: None installed by user choice";         fi                 if [[ "${SELECTED_PHP_VERSIONS[0]}" != "none" ]]; then             local php_version=$(php -v | head -n 1);             print_info "  • PHP: $php_version";             log "COMPLETION" "PHP version: $php_version";         else             print_info "  • PHP: None installed (as requested)";             log "COMPLETION" "PHP: None installed by user choice";         fi                 local fail2ban_status=$(systemctl is-active fail2ban);         print_info "  • Fail2ban: $fail2ban_status";         log "COMPLETION" "Fail2ban service status: $fail2ban_status"                 echo "";         print_info "Next Steps:";         print_info "  1. Visit http://$(hostname -I | awk '{print $1}') to test your installation";         print_info "  2. Default index.php page shows Hello World and PHP info";         print_info "  3. Configure your domain DNS to point to this server";         print_info "  4. Consider setting up SSL certificates";         print_info "  5. Review security settings";         if [[ "$SELECTED_DATABASE" == "mysql" ]]; then             print_info "  6. MySQL root credentials are in /root/.my.cnf";         elif [[ "$SELECTED_DATABASE" == "mariadb" ]]; then             print_info "  6. MariaDB root credentials are in /root/.my.cnf";         fi                 if [[ "$SELECTED_WEBSERVER" == "nginx" ]]; then             echo "";             print_info "Advanced Configuration (Nginx + PHP):";             print_info "  Current: Unix socket (fastest, most secure for single server)";             print_info "  To switch to TCP for load balancing/containers, run:";             case "$PACKAGE_MANAGER" in                 dnf|yum)                     print_info "    # Switch PHP-FPM to TCP:";                     print_info "    sed -i 's|listen = /run/php-fpm/www.sock|listen = 127.0.0.1:9000|' /etc/php-fpm.d/www.conf";                     print_info "    # Switch Nginx to TCP:";                     print_info "    sed -i 's|fastcgi_pass unix:/run/php-fpm/www.sock|fastcgi_pass 127.0.0.1:9000|' /etc/nginx/conf.d/default.conf";                     print_info "    # Open firewall port (if needed for remote PHP-FPM):";                     print_info "    firewall-cmd --permanent --add-port=9000/tcp && firewall-cmd --reload";                     ;;                 apt)                     print_info "    # Switch PHP-FPM to TCP:";                     print_info "    sed -i 's|listen = /var/run/php/.*\\.sock|listen = 127.0.0.1:9000|' /etc/php/*/fpm/pool.d/www.conf";                     print_info "    # Switch Nginx to TCP:";                     print_info "    sed -i 's|fastcgi_pass unix:/var/run/php/.*\\.sock|fastcgi_pass 127.0.0.1:9000|' /etc/nginx/sites-available/default";                     print_info "    # Open firewall port (if UFW is enabled):";                     print_info "    ufw allow 9000/tcp";                     ;;             esac;             print_info "    # Restart services:";             print_info "    systemctl restart php-fpm nginx";             print_info "";             print_info "  Benefits of TCP: Load balancing, containers, remote PHP-FPM servers";             print_info "  Benefits of Unix socket: 10-30% faster, more secure, simpler setup";         fi                 log "COMPLETION" "Next steps provided to user"             else         print_error "Installation completed but some validations failed";         print_error "Check the log file for details: $LOG_FILE";         log "ERROR" "Installation completed with validation failures";     fi         echo "";     log "COMPLETION" "Script execution completed";     print_success "Log file saved to: $LOG_FILE"         if [[ "$VERBOSE_LOGGING" != true ]]; then         echo "";         print_info "Note: Only errors, warnings, and completion messages were logged.";         print_info "Use '$0 --verbose' for detailed installation logs.";     fi; }
# Run main function
main "$@"
vi setup.sh
clear
./setup.sh
php 0v
mysql
./setup.sh --remove
rm removal-log-20250719-144323.log install-log-20250719-14*
ls
cp setup.sh setup.sh-good
rm setup.sh-good-maria-added.sh 
ls
./setup.sh --remove
vi setup.sh
mysql
php -v
./setup.sh
./setup.sh --remove
rm install-log-20250719-144852.log removal-log-20250719-14*
ls
cp setup.sh setup.sh-good 
vi setup.sh
./setup.sh
php
mysql
./setup.sh --remove
vi setup.sh
./setup.sh
cp setup.sh setup.sh-good 
./setup.sh --remove
ls
exit
ls
rm install-log-20250719-1* removal-log-20250719-150*
vi setup.sh
./setup.sh
psql -h localhost -U webdev -d webdev_db
psql -v
./setup.sh --remove
rm install-log-20250719-165335.log removal-log-20250719-170139.log 
ls
vi setup.sh
./setup.sh
vi setup.sh
./setup.sh
cat /root/postgresql-dev-credentials.txt
systemctl status postgresql
cat /root/postgresql-dev-credentials.txt
psql -h localhost -U webdev -d webdev_db
sudo -u postgres psql -c "SELECT version();"
./setup.sh --remove
rm install-log-20250719-170359.log removal-log-20250719-171210.log 
ls
vi setup.sh
./setup.sh
grep "Password:" /root/postgresql-dev-credentials.txt
psql -h localhost -U webdev -d webdev_db
psql
./setup.sh --remove
vi setup.sh
./setup.sh
psql
grep "Password:" /root/postgresql-dev-credentials.txt
psql -h localhost -U webdev -d webdev_db
sudo cat /var/lib/pgsql/data/pg_hba.conf | head -20
sudo cp /var/lib/pgsql/data/pg_hba.conf /var/lib/pgsql/data/pg_hba.conf.backup
sudo sed -i '1i local   webdev_db    webdev                                  md5' /var/lib/pgsql/data/pg_hba.conf
sudo sed -i '2i host    webdev_db    webdev      127.0.0.1/32            md5' /var/lib/pgsql/data/pg_hba.conf
sudo systemctl restart postgresql
psql -h localhost -U webdev -d webdev_db
sudo cat /var/lib/pgsql/data/pg_hba.conf | head -10
sudo systemctl status postgresql
sudo cat /var/lib/pgsql/data/pg_hba.conf | head -20
sudo systemctl restart postgresql
sleep 3
psql -h localhost -U webdev -d webdev_db
clear
# Let's see the full pg_hba.conf file to find conflicting rules
sudo cat /var/lib/pgsql/data/pg_hba.conf | grep -n -E "(local|host).*all.*all"
# Check the entire authentication section
sudo cat /var/lib/pgsql/data/pg_hba.conf | grep -v "^#" | grep -v "^$"
# Let's see what's actually being applied
sudo -u postgres psql -c "SELECT * FROM pg_hba_file_rules WHERE database = '{webdev_db}' OR database = '{all}';"
clear
psql -h 127.0.0.1 -U webdev -d webdev_db
grep "Password:" /root/postgresql-dev-credentials.txt
psql -h 127.0.0.1 -U webdev -d webdev_db
./setup.sh --remove
rm install-log-20250719-17* removal-log-20250719-1*
ls
cp setup.sh setup.sh-good 
vi setup.sh
 ./setup.sh
cat /root/postgresql-dev-credentials.txt
psql -h 127.0.0.1 -U webdev -d webdev_db
psql -h localhost -U webdev -d webdev_db
PGPASSWORD='wqydSG/yMgw7RT65' psql -h 127.0.0.1 -U webdev -d webdev_db
./setup.sh --remove
vi setup.sh
./setup.sh
cat /root/postgresql-dev-credentials.txt
psql -h 127.0.0.1 -U webdev -d webdev_db
PGPASSWORD='Op0gaKCjeBySQWZ4' psql -h 127.0.0.1 -U webdev -d webdev_db
php -v
cp setup.sh setup.sh-good 
./setup.sh --remove
./setup.sh
ls
rm install-log-20250719-18* removal-log-20250719-18*
./setup.sh
./setup.sh --remove
clear
./setup.sh
sql
sqlite
./setup.sh --remove
cp setup.sh setup.sh-good 
rm install-log-20250719-185* removal-log-20250719-1*
vi setup.sh
./setup.sh
which sqlite3
ls -la /var/lib/sqlite/
cat /root/sqlite-info.txt
sqlite3 /var/lib/sqlite/sample.db
which sqlite3
./setup.sh --remove
cp setup.sh setup.sh-good 
vi setup.sh
./setup.sh
Composer
composer
composer -v
composer -version
composer -h
composer --help
composer -V
./setup.sh --remove
./setup.sh
node
npm
compose 
composer
php -v
./setup.sh --remove
cp setup.sh setup.sh-good 
vi setup.sh
./setup.sh
npm
composer
node
cp setup.sh setup.sh-good 
rm install-log-20250719-19* removal-log-20250719-19*
du -h --max-depth=1
ls -la
cp setup.sh setup.sh-good 
vi setup.sh
./setup.sh
./setup.sh --remove
./setup.sh
git
composer
npm
./setup.sh --remove
rm install-log-20250719-204* removal-log-20250719-20*
clear
cp setup.sh setup.sh-good 
vi setup.sh
./setup.sh
composer
node
npm
git
mysql
php -v
ls
./setup.sh --remove
rm install-log-20250719-205341.log removal-log-20250719-205903.log 
ls
cp setup.sh setup.sh-good 
vi setup.sh
./setup.sh
./setup.sh --remove
rm install-log-20250719-210054.log removal-log-20250719-210454.log 
vi setup.sh
./setup.sh
cp setup.sh setup.sh-good 
./setup.sh --remove
ls
rm install-log-20250719-210641.log  removal-log-20250719-211639.log 
vi setup.sh
sls
ks
ls
ls -a
ls -la
ls
date
./setup.sh
./setup.sh --remove
vi setup.sh
./setup.sh
cp setup.sh setup.sh-good 
rm install-log-20250719-21 removal-log-20250719-212624.log 
./setup.sh --remove
ls
rm install-log-20250719-21* removal-log-20250719-213228.log 
ls -al
cp setup.sh setup.sh-good 
ls
claude
npm install -g @anthropic-ai/claude-code
./setup.sh
npm install -g @anthropic-ai/claude-code
 Run npm install -g npm@11.4.2
npm install -g npm@11.4.2
claude
 claude
node --version
nvm install 20 && nvm use 20
dnf install nvm
dnf upgrade node
dnf node upgrade
dnf nodejs upgrade
node
dnf remove nodejs npm
dnf module enable nodejs:18
dnf install nodejs npm
claude
exit
claude
clear
ls
./setup-secure.sh 
claude
./setup.sh
claude
./setup-secure.sh 
ls
rm install-log-202507* removal-log-202507*
ls
./setup.sh --remove
ls
ls -la
ls
./setup-secure.sh --remove
rm install-log-20250720-024201.log removal-log-20250720-02*
clear
./setup-secure.sh 
git
composer
./setup-secure.sh --remove
./setup-secure.sh 
clear
./setup-secure.sh 
clear
./setup-secure.sh 
clear
./setup-secure.sh 
clear
./setup-secure.sh 
./setup-secure.sh --remove
ls
./setup-secure.sh 
ls
./setup-secure.sh --remove
ls
./setup-secure.sh 
ls
./setup-secure.sh --remove
clear
claude
ls
clear
claude
clear
reboot
ps aux | grep nginx
clear
ls
ls -la
./setup-secure.sh --remove
rm removal-log-20250720-145147.log install-log-20250720-051210.log 
ls
./setup-secure.sh 
cat /root/postgresql-dev-credentials.txt
psql -h 127.0.0.1 -U webdev -d webdev_db
php -v
conposer
composer
git
ls
./setup-secure.sh --remove
ls
rm postgresql-dev-credentials.txt install-log-20250720-145244.log  removal-log-20250720-171204.log 
ls
rm setup.sh-good setup.sh
ls
cat package.json 
ls
ls node_modules/
ls
./setup.sh 
clear
./setup.sh 
ls
cat sqlite-info.txt 
sqlite3 /var/lib/sqlite/sample.db
./setup.sh --remove
ls
./setup.sh 
ls
./setup.sh --remove
ls
clear
./setup.sh 
cd /usr/bin/
ls
cd php
find /usr -name "php*" -type f -executable 2>/dev/null | grep -E "php[0-9]"
ls /usr/bin/php*
dnf list installed | grep php
ls /opt/remi/php*/
ls /opt/remi/php*
find /usr /opt -name "php" -type f -executable 2>/dev/null
ls
cd ~
ls
./setup.sh --remove
clear
./setup.sh 
php
top
ps -asx php
ps -aux php
psaux php
ps -aux
ps -aux | grep php
sudo ./setup.sh --verbose
 grep composer install-log-20250720-183509.log 
composer
sudo ./setup.sh --remove --verbose
sudo ./setup.sh --verbose
sudo ./setup.sh --remove --verbose
composer
sudo ./setup.sh --verbose
sudo ./setup.sh --remove --verbose
cat removal-log-20250720-190625.log 
sudo ./setup.sh --verbose
sudo ./setup.sh --remove
clear
sudo ./setup.sh --remove
rm install-log-20250720-191516.log removal-log-20250720-193922.log 
clear
./setup.sh 
clear
./setup.sh 
ls
rm install-log-20250720-195440.log 
./setup.sh 
./setup.sh --verbose --remove
ls
rm install-log-20250720-201936.log removal-log-20250720-203004.log 
clear
./setup.sh --verbose
clear
./setup.sh --verbose
clear
./setup.sh --verbose
clear
tail -20 /root/install-log-20250720-204943.log
./setup.sh --remove --verbose
clear
ls
rm install-log-20250720-204943.log removal-log-20250720-205735.log 
clear
./setup.sh --verbose
ls
./setup.sh --remove --verbose
ls
./setup.sh --verbose
clear
 systemctl status php82-php-fpm php83-php-fpm
ls -la /run/php-fpm/
 ls -la /var/run/php*/
grep -A 5 -B 5 "HTTP response test failed\|PHP index.php test failed\|Unix socket not found" /root/install-log-20250720-211507.log
clear
 find /var -name "*php-fpm*" -type s 2>/dev/null
find /var -name "*.sock" 2>/dev/null | grep php
ls -la /var/opt/remi/php*/run/php-fpm/ 2>/dev/null || true
 grep -r "^listen" /etc/opt/remi/php*/php-fpm.d/ 2>/dev/null || true
 curl -I http://localhost
curl http://localhost/index.php
 ls -la /var/opt/remi/php82/run/php-fpm/www.sock
ls -la /var/opt/remi/php83/run/php-fpm/www.sock
chown nginx:nginx /var/opt/remi/php82/run/php-fpm/www.sock
 chown nginx:nginx /var/opt/remi/php83/run/php-fpm/www.sock
grep fastcgi_pass /etc/nginx/conf.d/default.conf
ls -la /var/opt/remi/php82/run/php-fpm/www.sock
ls -la /var/opt/remi/php83/run/php-fpm/www.sock
sed -i 's|fastcgi_pass 127.0.0.1:9000;|fastcgi_pass unix:/var/opt/remi/php82/run/php-fpm/www.sock;|' /etc/nginx/conf.d/default.conf
systemctl restart nginx
 curl -I http://localhost
 curl http://localhost/index.php
 curl -I http://localhost
ls
rm install-log-20250720-211507.log removal-log-20250720-211338.log 
clear
./setup.sh --verbose
ls
grep -A 5 -B 5 "HTTP response test failed\|PHP index.php test failed\|Unix socket not found" /root/install-log-20250720-214347.log
grep error /root/install-log-20250720-214347.log
tail install-log-20250720-214347.log 
claude
ls
./setup.sh --remove -verbose
kill 5320
./setup.sh --remove -verbose
top
kill 5320

./setup.sh --remove -verbose
ps -p 5320
sudo kill -9 5320
ps -p 5320
ps -eo pid,ppid,state,comm | grep 5320
sudo kill -9 5205
clear
php
php -v
php
clear
./setup.sh --remove --verbose
clear
./setup.sh --verbose
systemctl status php83-php-fpm.service
./setup.sh --remove --verbose
clear
ls
rm removal-log-20250720-221134.log 
./setup.sh --verbose
find /usr /opt -name "php" -type f -executable 2>/dev/null
cat install-log-20250720-221241.log 
what time is it UTC
clear
grep defulat install-log-20250720-221241.log 
php -v
composer
node
git
ls
cat /root/.my.cnf 
mysql
cat postgresql-info.txt 
PGPASSWORD='m+mhiq6VOr9RoivL' psql -h 127.0.0.1 -U webdev -d webdev_db
sudo fail2ban-client get <ssh> ignoreip
sudo fail2ban-client get ssh ignoreip
sudo fail2ban-client
sudo fail2ban-client banned
sudo fail2ban-client status
sudo fail2ban-client get sshd ignoreip
vi check-whitelist.sh
chmod+x check-whitelist.sh 
chmod +x check-whitelist.sh 
./check-whitelist.sh 
mv check-whitelist.sh check-whitelist.sh--back
https://github.com/billckr/check-fail2ban.git
git clone https://github.com/billckr/check-fail2ban.git
ls
rm -rf check-fail2ban/
git clone https://github.com/billckr/check-fail2ban.git
rm -rf check-fail2ban/
git clone https://github.com/billckr/check-fail2ban.git
rm -rf check-fail2ban/
ls
mv check-whitelist.sh--back check-whitelist.sh
./check-whitelist.sh 
fail2ban-client set sshd delignoreip 42.112.16.92
claude
clear
./setup.sh --remove --verbose
clear
ls
./setup.sh --verbose
./setup.sh --remove --verbose
./setup.sh --verbose
npm
php -v
./setup.sh --remove --verbose
clear
./setup.sh
php -v
./setup.sh --remove
./setup.sh
php -v
./setup.sh --remove
./setup.sh
composer
./setup.sh --remove
./setup.sh
claude
php -v
./setup.sh --remove --verbose
clear
./setup.sh
php -v
ls
ls -al
php
php -v
./setup.sh --remove
ls
rm removal-log-20250721-114019.log
./setup.sh 
ls
./check-whitelist.sh 
./setup.sh 
telnet
./setup.sh --remove
ls
./setup.sh 
dnf list installed "php*"
php -v
whoami
php -V
php
curl http://178.156.159.51
php -v
ls
php -v
hash -r
php -v
./setup.sh --remove
./setup.sh --verbose
php -v
./setup.sh --remove --verbose
rm removal-log-20250721-151644.log 
cp setup.sh  setup.sh--back-good
ls
php -v
--non-interactiveclear
clear
./setup.sh --non-interactive --webserver=apache --database=mysql --php=8.2
clear
./setup.sh --non-interactive --webserver=apache --database=mysql --php=8.2
clear
./setup.sh --non-interactive --webserver=apache --database=mysql --php=8.2
./setup.sh --help
./setup.sh --list-options

clear
ls
./setup.sh --help
./setup.sh --non-interactive --
ls
./check-whitelist.sh 
./setup.sh --help
php -v
php
type php
mysql
cat /root/.my.cnf 
type php
hash -r
php -v
./setup.sh --help
./setup.sh --non-interactive --remove
./setup.sh --non-interactive --remove --skip
./setup.sh --non-interactive --skip
./setup.sh --non-interactive --remove --skip
./setup.sh --non-interactive --remove
mysql
php -v
clear
ls
ls -la 
ls -lh
ls -l --block-size=M
ls -lh
./setup.sh --help
clear
./setup.sh --help
clear
./setup.sh --help
clear
./setup.sh --help
clear
./setup.sh --help
./setup.sh --non-interactive --webserver=apache --database=postgresql,sqlite --php=8.2,8.3 --dev-tools=git --username=newadmin
./setup.sh --non-interactive --webserver=apache --database=postgresql,sqlite --php=8.2,8.3 --dev-tools=git --username=newadmin --skip
ls
./ check-whitelist.sh 
./check-whitelist.sh 
clera
clear
claude
php -v
./setup.sh --remov
./setup.sh --remove
./setup.sh --non-interactive --remove
date
ls
php -v
hash -l
 hash -r
php -v
./setup.sh -help
setup.sh --help
ls
setup.sh -help
gep --help README.md 
grep --help README.md 
grep help README.md 
./setup.sh --help
clear
./setup.sh --help
clear
./setup.sh --help
./setup.sh --non-interactive --help
./setup.sh --help
./setup.sh --non-interactive --help
clear
./setup.sh --non-interactive --help
clear
mysql
cd /var/mail/
ls
cd /home/
ls
clear
cd ~
./setup.sh --non--interactive
./setup.sh --non-interactive
clear
./setup.sh --non-interactive --skip
clear
./setup.sh --non-interactive --skip
sudo ./setup.sh --preset=lamp
sudo ./setup.sh --preset=lamp --skip
./setup.sh --help
./setup.sh
./setup.sh --help
sudo ./setup.sh --preset=lamp
./setup.sh --preset=lamp --non-interactive
Proceed with installation? (y/N):n
date
clear
./setup.sh --hepl
./setup.sh --help
clear
./setup.sh --preset=lamp
./setup.sh --preset=lemp
./setup.sh --preset=lamp
./setup.sh
clear
sudo ./setup.sh --preset=lamp --auto
mysql
php -v
composer
git
clear
ls
./check-whitelist.sh 
ls
mkdir script-backup
cp setup.sh check-whitelist.sh setup-noninteractive.sh CLAUDE.md SCRIPT-REFERENCE.md README.md script-backup/
zip
tar
dnf install zip
zip script-backup.zip script-backup/
ls -la
cp script-backup.zip /var/www/html/
cd script-backup
ls
cd ..
zip -r script-backup.zip script-backup
cp script-backup.zip /var/www/html/
./check-whitelist.sh 
pwd
vi check-whitelist-tui.sh
chmod +x check-whitelist-tui.sh 
./check-whitelist-tui.sh 
vi check-whitelist-tui.sh 
./check-whitelist-tui.sh 
vi check-whitelist-tui.sh 
./check-whitelist-tui.sh 
vi check-whitelist-tui.sh 
./check-whitelist-tui.sh 
vi check-whitelist-tui.sh 
./check-whitelist-tui.sh 
vi check-whitelist-tui.sh 
./check-whitelist-tui.sh 
vi check-whitelist-tui.sh 
./check-whitelist-tui.sh 
vi check-whitelist-tui.sh 
sudo ./check-whitelist-tui.sh --no-color
vi check-whitelist-tui.sh 
sudo ./check-whitelist-tui.sh --no-color
sudo ./check-whitelist-tui.sh
vi check-whitelist-tui.sh 
./check-whitelist-tui.sh 
vi check-whitelist-tui.sh 
./check-whitelist-tui.sh 
vi check-whitelist-tui.sh 
./check-whitelist-tui.sh 
sudo ./check-whitelist-tui.sh --no-color
./check-whitelist-tui.sh 
vi check-whitelist-tui.sh 
./check-whitelist-tui.sh 
ls
vi test.sh
chomod +x test.sh 
chmode +x test.sh 
chmod +x test.sh 
./test.sh 
vi test.sh 
./test.sh 
fail2ban --status
php -v
systemctl status fail2ban
vi test.sh 
chmod +x test.sh 
./test.sh 
./check-whitelist-tui.sh 
sudo ./setup.sh --preset=lamp --remove
php -v
hash -r
php -v
./setup.sh --help
 sudo ./setup.sh --preset=lamp
./setup.sh --help
./setup.sh
./setup.sh --help
./setup.sh
clear
php -v
clear
./setup.sh --help
sudo ./setup.sh --preset=lamp
 sudo ./setup.sh --preset=lemp
free -m
df -h
sudo ./setup.sh --preset=minimal
./setup.sh --help
sudo ./setup.sh --preset=minimal
./setup.sh --help
sudo ./setup.sh --preset=lamp
sudo ./setup.sh --preset=lemp
sudo ./setup.sh --preset=lamp
sudo ./setup.sh --preset=minimal
./setup.sh --help
sudo ./setup.sh --preset=minimal
sudo ./setup.sh --preset=lamp
sudo ./setup.sh --preset=lemp
sudo ./setup.sh --preset=minimal
sudo ./setup.sh --preset=lamp
ls
 sudo ./setup.sh --remove
./setup.sh --verbose --remove
php -v
mysql
sudo ./setup.sh --remove
php -v
sudo ./setup.sh --preset=lamp
php -v
mysql
sudo ./setup.sh --remove
hash -r
clear
sudo ./setup.sh --preset=lamp
ls
./check-whitelist.sh 
./setup.sh --remove
fail2ban-client status sshd
sudo ./setup.sh --preset=lamp
clear
sudo ./setup.sh --preset=lamp
clear
sudo ./setup.sh --preset=lamp
exit
clear
clear
./setup.sh --help
sudo ./setup.sh --preset=lamp --auto
./check-whitelist.sh 
