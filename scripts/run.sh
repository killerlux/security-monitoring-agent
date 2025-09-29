#!/bin/bash
# Security Monitoring Agent - Run Script
# Executes a single monitoring collection cycle

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
PYTHON_PATH="$PROJECT_ROOT"
STATE_DIR="${STATE_DIR:-./test-output}"
CONFIG_FILE="$PROJECT_ROOT/config/policies.yaml"
LOG_FILE="${LOG_FILE:-./test-output/security-monitor.log}"

# Create state directory if it doesn't exist
mkdir -p "$STATE_DIR"

# Set Python path
export PYTHONPATH="$PYTHON_PATH:${PYTHONPATH:-}"

# Function to log messages
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

# Function to check if running as root
check_root() {
    if [[ $EUID -eq 0 ]]; then
        log "WARNING: Running as root. Consider running as non-root user."
    fi
}

# Function to check dependencies
check_dependencies() {
    local missing_deps=()
    
    # Check Python
    if ! command -v python3 &> /dev/null; then
        missing_deps+=("python3")
    fi
    
    # Check required system commands
    local required_commands=("ss" "systemctl" "ip" "ps" "free" "df")
    for cmd in "${required_commands[@]}"; do
        if ! command -v "$cmd" &> /dev/null; then
            missing_deps+=("$cmd")
        fi
    done
    
    if [[ ${#missing_deps[@]} -gt 0 ]]; then
        log "ERROR: Missing dependencies: ${missing_deps[*]}"
        exit 1
    fi
}

# Function to run monitoring
run_monitoring() {
    log "Starting security monitoring collection"
    
    # Change to project directory
    cd "$PROJECT_ROOT"
    
    # Run the monitoring agent
    if python3 -m agent --collect --output "$STATE_DIR" --config "$CONFIG_FILE"; then
        log "Monitoring collection completed successfully"
        
        # Get latest output file
        latest_file=$(ls -t "$STATE_DIR"/monitoring-*.json 2>/dev/null | head -n1)
        if [[ -n "$latest_file" ]]; then
            log "Latest output: $latest_file"
            
            # Check for alerts
            alert_count=$(python3 -c "
import json
with open('$latest_file', 'r') as f:
    data = json.load(f)
    alerts = [a for a in data.get('diff', {}).get('alerts', []) if a.get('severity') in ['warn', 'high']]
    print(len(alerts))
")
            
            if [[ "$alert_count" -gt 0 ]]; then
                log "WARNING: $alert_count alerts generated"
                python3 -c "
import json
with open('$latest_file', 'r') as f:
    data = json.load(f)
    for alert in data.get('diff', {}).get('alerts', []):
        if alert.get('severity') in ['warn', 'high']:
            print(f'  {alert.get(\"severity\").upper()}: {alert.get(\"message\")}')
"
            else
                log "No critical alerts detected"
            fi
        fi
    else
        log "ERROR: Monitoring collection failed"
        exit 1
    fi
}

# Function to cleanup old files
cleanup_old_files() {
    local retention_days=30
    log "Cleaning up files older than $retention_days days"
    
    # Clean up old monitoring output files
    find "$STATE_DIR" -name "monitoring-*.json" -mtime +$retention_days -delete 2>/dev/null || true
    
    # Clean up old log files
    find /var/log -name "security-monitor*.log" -mtime +$retention_days -delete 2>/dev/null || true
}

# Function to show help
show_help() {
    cat << EOF
Security Monitoring Agent - Run Script

Usage: $0 [OPTIONS]

Options:
    -h, --help          Show this help message
    -c, --check-only    Check dependencies only
    -d, --daemon        Run in daemon mode (continuous)
    -t, --test          Run test collection
    --cleanup           Clean up old files only

Examples:
    $0                  # Run single collection
    $0 --test          # Run test collection
    $0 --check-only    # Check dependencies
    $0 --cleanup       # Clean up old files

EOF
}

# Function to run test
run_test() {
    log "Running test collection"
    
    cd "$PROJECT_ROOT"
    
    # Generate example output
    if python3 -m agent --example --output "$STATE_DIR"; then
        log "Test collection completed successfully"
    else
        log "ERROR: Test collection failed"
        exit 1
    fi
}

# Function to run daemon mode
run_daemon() {
    log "Starting daemon mode (continuous monitoring)"
    
    while true; do
        run_monitoring
        log "Waiting 5 minutes before next collection..."
        sleep 300
    done
}

# Main script logic
main() {
    local check_only=false
    local test_mode=false
    local daemon_mode=false
    local cleanup_only=false
    
    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                show_help
                exit 0
                ;;
            -c|--check-only)
                check_only=true
                shift
                ;;
            -t|--test)
                test_mode=true
                shift
                ;;
            -d|--daemon)
                daemon_mode=true
                shift
                ;;
            --cleanup)
                cleanup_only=true
                shift
                ;;
            *)
                log "ERROR: Unknown option: $1"
                show_help
                exit 1
                ;;
        esac
    done
    
    # Check dependencies first
    check_dependencies
    log "All dependencies available"
    
    if [[ "$check_only" == true ]]; then
        log "Dependency check completed successfully"
        exit 0
    fi
    
    # Check root
    check_root
    
    # Run appropriate mode
    if [[ "$cleanup_only" == true ]]; then
        cleanup_old_files
        exit 0
    elif [[ "$test_mode" == true ]]; then
        run_test
    elif [[ "$daemon_mode" == true ]]; then
        run_daemon
    else
        run_monitoring
        cleanup_old_files
    fi
}

# Run main function
main "$@"
