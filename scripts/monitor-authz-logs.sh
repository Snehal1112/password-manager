#!/bin/bash
#
# Authorization Audit Log Monitor
# This script helps monitor and analyze RBAC authorization decisions
#

LOG_FILE="${LOG_FILE:-logs/app.log}"
WATCH_MODE="${WATCH_MODE:-false}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo "==================================="
echo "RBAC Authorization Log Monitor"
echo "==================================="
echo ""

# Check if log file exists
if [ ! -f "$LOG_FILE" ]; then
    echo -e "${YELLOW}Warning: Log file not found at $LOG_FILE${NC}"
    echo "You can specify a custom path with: LOG_FILE=/path/to/log.log $0"
    echo ""
    echo "Searching for log files..."
    find . -name "*.log" 2>/dev/null | grep -v node_modules | head -5
    exit 1
fi

# Function to display authorization denials
show_denials() {
    echo -e "${RED}=== AUTHORIZATION DENIALS ===${NC}"
    grep -i "authorization.*failed\|access denied\|insufficient permissions" "$LOG_FILE" 2>/dev/null | \
        jq -r 'select(.operation == "authz" or .operation == "authorization") |
               "\(.timestamp) [\(.level | ascii_upcase)] Role: \(.role // "N/A") | \(.method) \(.path) | \(.msg)"' 2>/dev/null || \
        grep -i "authorization.*failed\|access denied" "$LOG_FILE" | tail -20
    echo ""
}

# Function to display authorization successes
show_successes() {
    echo -e "${GREEN}=== AUTHORIZATION SUCCESSES ===${NC}"
    grep -i "authorization.*success" "$LOG_FILE" 2>/dev/null | \
        jq -r 'select(.operation == "authz") |
               "\(.timestamp) [\(.level | ascii_upcase)] \(.msg)"' 2>/dev/null || \
        grep -i "authorization.*success" "$LOG_FILE" | tail -20
    echo ""
}

# Function to display role-based statistics
show_role_stats() {
    echo -e "${BLUE}=== ROLE-BASED STATISTICS ===${NC}"

    echo "Access Denials by Role:"
    grep -i "access denied" "$LOG_FILE" 2>/dev/null | \
        jq -r '.role // "unknown"' 2>/dev/null | \
        sort | uniq -c | sort -rn || \
        echo "  (JSON parsing not available)"
    echo ""

    echo "Most Denied Permissions:"
    grep -i "insufficient permissions" "$LOG_FILE" 2>/dev/null | \
        jq -r '.required_permission // "unknown"' 2>/dev/null | \
        sort | uniq -c | sort -rn | head -10 || \
        echo "  (JSON parsing not available)"
    echo ""
}

# Function to display endpoint statistics
show_endpoint_stats() {
    echo -e "${YELLOW}=== ENDPOINT ACCESS STATISTICS ===${NC}"

    echo "Most Denied Endpoints:"
    grep -i "access denied" "$LOG_FILE" 2>/dev/null | \
        jq -r '"\(.method) \(.path)"' 2>/dev/null | \
        sort | uniq -c | sort -rn | head -10 || \
        echo "  (JSON parsing not available)"
    echo ""
}

# Function to watch logs in real-time
watch_logs() {
    echo -e "${GREEN}Watching authorization logs (Ctrl+C to stop)...${NC}"
    echo ""
    tail -f "$LOG_FILE" 2>/dev/null | grep --line-buffered -i "authz\|authorization" | \
        while IFS= read -r line; do
            if echo "$line" | grep -qi "failed\|denied"; then
                echo -e "${RED}DENIED${NC}: $line"
            elif echo "$line" | grep -qi "success"; then
                echo -e "${GREEN}ALLOWED${NC}: $line"
            else
                echo "$line"
            fi
        done
}

# Function to show recent authorization events
show_recent() {
    local count="${1:-20}"
    echo -e "${BLUE}=== RECENT AUTHORIZATION EVENTS (last $count) ===${NC}"
    grep -i "authz\|authorization" "$LOG_FILE" 2>/dev/null | tail -n "$count" | \
        jq -r 'select(.operation == "authz" or .operation == "authorization") |
               "\(.timestamp) [\(.level | ascii_upcase)] \(.msg) - Role: \(.role // "N/A")"' 2>/dev/null || \
        grep -i "authz\|authorization" "$LOG_FILE" | tail -n "$count"
    echo ""
}

# Function to search for specific user/role activity
search_activity() {
    local search_term="$1"
    echo -e "${BLUE}=== AUTHORIZATION ACTIVITY FOR: $search_term ===${NC}"
    grep -i "authz\|authorization" "$LOG_FILE" 2>/dev/null | grep -i "$search_term" | \
        jq -r 'select(.operation == "authz" or .operation == "authorization") |
               "\(.timestamp) [\(.level | ascii_upcase)] \(.msg)"' 2>/dev/null || \
        grep -i "authz\|authorization" "$LOG_FILE" | grep -i "$search_term"
    echo ""
}

# Main menu
case "${1:-summary}" in
    "summary")
        show_denials
        show_successes
        show_role_stats
        show_endpoint_stats
        ;;
    "denials")
        show_denials
        ;;
    "successes")
        show_successes
        ;;
    "stats")
        show_role_stats
        show_endpoint_stats
        ;;
    "watch")
        watch_logs
        ;;
    "recent")
        show_recent "${2:-20}"
        ;;
    "search")
        if [ -z "$2" ]; then
            echo "Usage: $0 search <role|user|endpoint>"
            exit 1
        fi
        search_activity "$2"
        ;;
    "help"|"-h"|"--help")
        echo "Usage: $0 [command] [options]"
        echo ""
        echo "Commands:"
        echo "  summary              Show complete authorization summary (default)"
        echo "  denials              Show only authorization denials"
        echo "  successes            Show only authorization successes"
        echo "  stats                Show role and endpoint statistics"
        echo "  watch                Watch authorization logs in real-time"
        echo "  recent [n]           Show last N authorization events (default: 20)"
        echo "  search <term>        Search for authorization events matching term"
        echo "  help                 Show this help message"
        echo ""
        echo "Environment Variables:"
        echo "  LOG_FILE             Path to log file (default: logs/app.log)"
        echo ""
        echo "Examples:"
        echo "  $0 summary"
        echo "  $0 watch"
        echo "  $0 recent 50"
        echo "  $0 search 'user'"
        echo "  LOG_FILE=/var/log/app.log $0 denials"
        ;;
    *)
        echo "Unknown command: $1"
        echo "Run '$0 help' for usage information"
        exit 1
        ;;
esac
