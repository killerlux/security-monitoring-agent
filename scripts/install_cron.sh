#!/bin/bash
# Security Monitoring Agent - Cron Installation Script
# Installs cron job to run monitoring every 5 minutes

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
RUN_SCRIPT="$SCRIPT_DIR/run.sh"
CRON_SCHEDULE="*/5 * * * *"  # Every 5 minutes
CRON_USER="root"  # Default user, can be overridden

# Function to log messages
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1"
}

# Function to show help
show_help() {
    cat << EOF
Security Monitoring Agent - Cron Installation Script

Usage: $0 [OPTIONS]

Options:
    -h, --help          Show this help message
    -u, --user USER     Install cron job for specific user (default: root)
    -r, --remove        Remove existing cron job
    -s, --show          Show current cron jobs
    --schedule CRON     Custom cron schedule (default: */5 * * * *)

Examples:
    $0                  # Install cron job for root user
    $0 -u monitoring   # Install cron job for monitoring user
    $0 --remove        # Remove existing cron job
    $0 --show          # Show current cron jobs
    $0 --schedule "*/10 * * * *"  # Install with custom schedule

EOF
}

# Function to check if script exists
check_script() {
    if [[ ! -f "$RUN_SCRIPT" ]]; then
        log "ERROR: Run script not found: $RUN_SCRIPT"
        exit 1
    fi
    
    if [[ ! -x "$RUN_SCRIPT" ]]; then
        log "Making run script executable"
        chmod +x "$RUN_SCRIPT"
    fi
}

# Function to check dependencies
check_dependencies() {
    if ! command -v crontab &> /dev/null; then
        log "ERROR: crontab command not found"
        exit 1
    fi
    
    if ! command -v python3 &> /dev/null; then
        log "ERROR: python3 not found"
        exit 1
    fi
}

# Function to install cron job
install_cron() {
    local user="$1"
    local schedule="$2"
    
    log "Installing cron job for user: $user"
    log "Schedule: $schedule"
    
    # Create cron job entry
    local cron_entry="$schedule $RUN_SCRIPT >> /var/log/security-monitor-cron.log 2>&1"
    
    # Get current crontab
    local current_crontab=""
    if crontab -u "$user" -l 2>/dev/null; then
        current_crontab=$(crontab -u "$user" -l 2>/dev/null || true)
    fi
    
    # Check if cron job already exists
    if echo "$current_crontab" | grep -q "$RUN_SCRIPT"; then
        log "WARNING: Cron job already exists for this script"
        log "Removing existing cron job first..."
        remove_cron "$user"
    fi
    
    # Add new cron job
    local new_crontab
    if [[ -n "$current_crontab" ]]; then
        new_crontab="$current_crontab"$'\n'"$cron_entry"
    else
        new_crontab="$cron_entry"
    fi
    
    # Install new crontab
    echo "$new_crontab" | crontab -u "$user" -
    
    log "Cron job installed successfully"
    log "Job will run: $schedule"
    log "Logs will be written to: /var/log/security-monitor-cron.log"
}

# Function to remove cron job
remove_cron() {
    local user="$1"
    
    log "Removing cron job for user: $user"
    
    # Get current crontab
    local current_crontab=""
    if crontab -u "$user" -l 2>/dev/null; then
        current_crontab=$(crontab -u "$user" -l 2>/dev/null || true)
    fi
    
    if [[ -z "$current_crontab" ]]; then
        log "No crontab found for user: $user"
        return 0
    fi
    
    # Remove lines containing our script
    local new_crontab
    new_crontab=$(echo "$current_crontab" | grep -v "$RUN_SCRIPT" || true)
    
    if [[ -n "$new_crontab" ]]; then
        echo "$new_crontab" | crontab -u "$user" -
        log "Cron job removed successfully"
    else
        # Empty crontab
        crontab -u "$user" -r 2>/dev/null || true
        log "Cron job removed successfully (crontab is now empty)"
    fi
}

# Function to show cron jobs
show_cron() {
    local user="$1"
    
    log "Current cron jobs for user: $user"
    echo "----------------------------------------"
    
    if crontab -u "$user" -l 2>/dev/null; then
        echo
    else
        echo "No crontab found for user: $user"
    fi
}

# Function to create log directory
create_log_directory() {
    local log_dir="/var/log"
    if [[ ! -d "$log_dir" ]]; then
        log "Creating log directory: $log_dir"
        mkdir -p "$log_dir"
    fi
    
    # Ensure log file exists and is writable
    local log_file="$log_dir/security-monitor-cron.log"
    touch "$log_file"
    chmod 644 "$log_file"
}

# Function to validate cron schedule
validate_schedule() {
    local schedule="$1"
    
    # Basic validation - check for 5 fields
    local field_count
    field_count=$(echo "$schedule" | awk '{print NF}')
    
    if [[ "$field_count" -ne 5 ]]; then
        log "ERROR: Invalid cron schedule format: $schedule"
        log "Expected format: minute hour day month weekday"
        log "Example: */5 * * * * (every 5 minutes)"
        exit 1
    fi
}

# Main script logic
main() {
    local remove_mode=false
    local show_mode=false
    local schedule="$CRON_SCHEDULE"
    local user="$CRON_USER"
    
    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                show_help
                exit 0
                ;;
            -r|--remove)
                remove_mode=true
                shift
                ;;
            -s|--show)
                show_mode=true
                shift
                ;;
            -u|--user)
                user="$2"
                shift 2
                ;;
            --schedule)
                schedule="$2"
                shift 2
                ;;
            *)
                log "ERROR: Unknown option: $1"
                show_help
                exit 1
                ;;
        esac
    done
    
    # Check dependencies
    check_dependencies
    
    # Check script exists
    check_script
    
    # Create log directory
    create_log_directory
    
    # Run appropriate action
    if [[ "$show_mode" == true ]]; then
        show_cron "$user"
    elif [[ "$remove_mode" == true ]]; then
        remove_cron "$user"
    else
        validate_schedule "$schedule"
        install_cron "$user" "$schedule"
    fi
}

# Run main function
main "$@"
