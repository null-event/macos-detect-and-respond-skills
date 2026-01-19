#!/bin/bash
#
# collect-es-events.sh - Collect Endpoint Security events for analysis
#
# Usage: ./collect-es-events.sh [options]
#
# Description:
#   Collects Endpoint Security events from common macOS EDR tools or logs
#   for a specified time window. Useful for threat hunting and detection testing.
#
# Output:
#   JSON file containing collected ES events

set -euo pipefail

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

usage() {
    cat << EOF
Usage: $0 [options]

Options:
  -t, --time-range <range>    Time range to collect (e.g., "1h", "30m", "1d")
                              Default: 1h
  -e, --event-types <types>   Comma-separated ES event types to collect
                              Example: "EXEC,FORK,OPEN"
                              Default: all
  -o, --output <file>         Output JSON file
                              Default: es_events_<timestamp>.json
  -s, --source <source>       Data source (esf-client, jamf, unified-log)
                              Default: auto-detect
  -h, --help                  Show this help message

Event Type Examples:
  EXEC                        Process execution
  FORK                        Process fork
  OPEN,CLOSE                  File operations
  CREATE,UNLINK               File creation/deletion
  WRITE                       File modifications

Examples:
  $0 -t 2h -e EXEC,FORK
  $0 -t 30m -o recent_events.json
  $0 --source unified-log --time-range 1d

EOF
    exit 1
}

# Default values
TIME_RANGE="1h"
EVENT_TYPES="all"
OUTPUT_FILE="es_events_$(date +%Y%m%d_%H%M%S).json"
SOURCE="auto"

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -t|--time-range)
            TIME_RANGE="$2"
            shift 2
            ;;
        -e|--event-types)
            EVENT_TYPES="$2"
            shift 2
            ;;
        -o|--output)
            OUTPUT_FILE="$2"
            shift 2
            ;;
        -s|--source)
            SOURCE="$2"
            shift 2
            ;;
        -h|--help)
            usage
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            usage
            ;;
    esac
done

echo -e "${BLUE}=== Endpoint Security Event Collector ===${NC}\n"
echo "Time Range: $TIME_RANGE"
echo "Event Types: $EVENT_TYPES"
echo "Output File: $OUTPUT_FILE"
echo "Source: $SOURCE"
echo ""

# Convert time range to log show format
convert_time_range() {
    local range="$1"
    case "$range" in
        *m)
            minutes="${range%m}"
            echo "${minutes}m"
            ;;
        *h)
            hours="${range%h}"
            minutes=$((hours * 60))
            echo "${minutes}m"
            ;;
        *d)
            days="${range%d}"
            minutes=$((days * 24 * 60))
            echo "${minutes}m"
            ;;
        *)
            echo "1h"
            ;;
    esac
}

LOG_TIME_RANGE=$(convert_time_range "$TIME_RANGE")

# Auto-detect source if needed
if [ "$SOURCE" = "auto" ]; then
    echo -e "${BLUE}Auto-detecting data source...${NC}"

    # Check for common EDR tools
    if pgrep -x "jamfprotect" > /dev/null 2>&1; then
        SOURCE="jamf"
        echo "  Detected: Jamf Protect"
    elif [ -d "/Library/Application Support/JAMF" ]; then
        SOURCE="jamf"
        echo "  Detected: Jamf (checking logs)"
    # Check for other EDR agents
    elif pgrep -x "falconctl" > /dev/null 2>&1; then
        SOURCE="crowdstrike"
        echo "  Detected: CrowdStrike Falcon"
    elif pgrep -x "SentinelAgent" > /dev/null 2>&1; then
        SOURCE="sentinelone"
        echo "  Detected: SentinelOne"
    else
        # Fall back to unified log
        SOURCE="unified-log"
        echo "  No EDR detected, using unified log"
    fi
    echo ""
fi

# Build event type filter
build_event_filter() {
    local types="$1"

    if [ "$types" = "all" ]; then
        echo ""
        return
    fi

    # Convert comma-separated list to ES event type predicates
    IFS=',' read -ra TYPE_ARRAY <<< "$types"
    PREDICATES=()

    for type in "${TYPE_ARRAY[@]}"; do
        # Normalize to ES_EVENT_TYPE_NOTIFY_* format
        if [[ ! "$type" =~ ^ES_EVENT_TYPE ]]; then
            type="ES_EVENT_TYPE_NOTIFY_${type}"
        fi
        PREDICATES+=("eventType == \"$type\"")
    done

    # Join with OR
    local filter=""
    for i in "${!PREDICATES[@]}"; do
        if [ $i -eq 0 ]; then
            filter="${PREDICATES[$i]}"
        else
            filter="$filter OR ${PREDICATES[$i]}"
        fi
    done

    echo "$filter"
}

EVENT_FILTER=$(build_event_filter "$EVENT_TYPES")

# Collect events based on source
collect_from_unified_log() {
    echo -e "${BLUE}Collecting from unified log...${NC}"
    echo ""

    # Build predicate for ESF subsystem
    PREDICATE='subsystem == "com.apple.endpointsecurity"'

    if [ -n "$EVENT_FILTER" ]; then
        PREDICATE="$PREDICATE AND ($EVENT_FILTER)"
    fi

    echo "  Predicate: $PREDICATE"
    echo "  Time Range: Last $LOG_TIME_RANGE"
    echo ""

    # Collect logs
    echo -e "${CYAN}Running log collection (this may take a moment)...${NC}"

    log show --predicate "$PREDICATE" --info --last "$LOG_TIME_RANGE" --style json > "$OUTPUT_FILE" 2>/dev/null || {
        echo -e "${YELLOW}Note: Limited ES events in unified log. Consider using an EDR tool.${NC}"
        echo "[]" > "$OUTPUT_FILE"
    }

    EVENT_COUNT=$(jq 'length' "$OUTPUT_FILE" 2>/dev/null || echo "0")
    echo -e "${GREEN}✓ Collected $EVENT_COUNT events${NC}"
}

collect_from_jamf() {
    echo -e "${BLUE}Collecting from Jamf Protect...${NC}"
    echo ""

    # Jamf Protect stores events in various locations
    JAMF_LOG_DIR="/var/log/jamf"
    JAMF_ANALYTICS_DIR="/Library/Application Support/JamfProtect/groups"

    if [ -d "$JAMF_ANALYTICS_DIR" ]; then
        echo "  Searching Jamf analytics logs..."

        # Find recent analytic events
        find "$JAMF_ANALYTICS_DIR" -name "*.json" -mtime -1 2>/dev/null | while read -r file; do
            cat "$file" 2>/dev/null
        done | jq -s '.' > "$OUTPUT_FILE" 2>/dev/null || echo "[]" > "$OUTPUT_FILE"

        EVENT_COUNT=$(jq 'length' "$OUTPUT_FILE" 2>/dev/null || echo "0")
        echo -e "${GREEN}✓ Collected $EVENT_COUNT events${NC}"
    else
        echo -e "${YELLOW}Jamf Protect analytics directory not found${NC}"
        echo -e "${YELLOW}Falling back to unified log...${NC}"
        collect_from_unified_log
    fi
}

collect_from_crowdstrike() {
    echo -e "${BLUE}Collecting from CrowdStrike Falcon...${NC}"
    echo ""

    # CrowdStrike events would typically be retrieved via API
    echo -e "${YELLOW}Note: CrowdStrike event collection requires API access${NC}"
    echo "  Please use the CrowdStrike Falcon API or console to export events"
    echo "  Falling back to unified log for local events..."
    echo ""

    collect_from_unified_log
}

collect_from_sentinelone() {
    echo -e "${BLUE}Collecting from SentinelOne...${NC}"
    echo ""

    # SentinelOne events would typically be retrieved via API
    echo -e "${YELLOW}Note: SentinelOne event collection requires API access${NC}"
    echo "  Please use the SentinelOne console or API to export events"
    echo "  Falling back to unified log for local events..."
    echo ""

    collect_from_unified_log
}

# Collect events from appropriate source
case "$SOURCE" in
    unified-log)
        collect_from_unified_log
        ;;
    jamf)
        collect_from_jamf
        ;;
    crowdstrike)
        collect_from_crowdstrike
        ;;
    sentinelone)
        collect_from_sentinelone
        ;;
    esf-client)
        # Custom ESF client
        echo -e "${YELLOW}Custom ESF client collection not implemented${NC}"
        echo "Please specify the path to your ESF client's event output"
        exit 1
        ;;
    *)
        echo -e "${RED}Unknown source: $SOURCE${NC}"
        exit 1
        ;;
esac

echo ""

# Generate summary
echo -e "${BLUE}Event Collection Summary${NC}"

if [ -f "$OUTPUT_FILE" ]; then
    FILE_SIZE=$(du -h "$OUTPUT_FILE" | cut -f1)
    EVENT_COUNT=$(jq 'length' "$OUTPUT_FILE" 2>/dev/null || echo "unknown")

    echo "  Output File: $OUTPUT_FILE"
    echo "  File Size: $FILE_SIZE"
    echo "  Event Count: $EVENT_COUNT"
    echo ""

    # Show event type breakdown if available
    if [ "$EVENT_COUNT" != "unknown" ] && [ "$EVENT_COUNT" -gt 0 ]; then
        echo "  Event Type Breakdown:"
        jq -r '.[] | .eventType // .eventMessage // "unknown"' "$OUTPUT_FILE" 2>/dev/null | \
            sort | uniq -c | sort -rn | head -10 | while read -r count type; do
            echo "    $type: $count"
        done
    fi
else
    echo -e "${RED}Error: Failed to create output file${NC}"
fi

echo ""
echo -e "${GREEN}=== Collection Complete ===${NC}\n"

echo "Next Steps:"
echo "  1. Review collected events: jq . $OUTPUT_FILE | less"
echo "  2. Test detection queries against this data"
echo "  3. Filter for specific patterns:"
echo "     jq '.[] | select(.eventType == \"ES_EVENT_TYPE_NOTIFY_EXEC\")' $OUTPUT_FILE"
echo "  4. Export to SIEM for correlation"
echo ""
echo "Useful jq queries:"
echo "  # Count by process:"
echo "  jq -r '.[].process.name' $OUTPUT_FILE | sort | uniq -c | sort -rn"
echo ""
echo "  # Find unsigned binaries:"
echo "  jq '.[] | select(.process.signingId == null or .process.signingId == \"\")' $OUTPUT_FILE"
