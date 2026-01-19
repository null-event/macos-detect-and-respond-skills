#!/bin/bash
#
# analyze-launch-agent.sh - Inspect and triage launch agent/daemon plists
#
# Usage: ./analyze-launch-agent.sh <plist_path>
#
# Description:
#   Automates launch agent/daemon triage by parsing the plist, analyzing
#   the target executable, checking for suspicious indicators, and providing
#   a verdict on whether the persistence mechanism is benign or malicious.
#
# Output:
#   Detailed analysis report with security assessment

set -euo pipefail

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

usage() {
    echo "Usage: $0 <plist_path>"
    echo ""
    echo "Arguments:"
    echo "  plist_path  - Path to launch agent/daemon plist file"
    echo ""
    echo "Examples:"
    echo "  $0 ~/Library/LaunchAgents/com.example.agent.plist"
    echo "  $0 /Library/LaunchDaemons/com.suspicious.daemon.plist"
    exit 1
}

if [ $# -ne 1 ]; then
    usage
fi

PLIST_PATH="$1"

# Verify plist exists
if [ ! -f "$PLIST_PATH" ]; then
    echo -e "${RED}Error: Plist file not found: $PLIST_PATH${NC}"
    exit 1
fi

echo -e "${BLUE}=== Launch Agent/Daemon Analysis ===${NC}\n"
echo -e "${CYAN}Plist:${NC} $PLIST_PATH"
echo -e "${CYAN}Timestamp:${NC} $(date)"
echo ""

# Determine if agent or daemon based on path
if echo "$PLIST_PATH" | grep -q "LaunchAgents"; then
    PERSISTENCE_TYPE="Launch Agent"
    SCOPE=$(echo "$PLIST_PATH" | grep -q "^$HOME" && echo "User" || echo "System")
elif echo "$PLIST_PATH" | grep -q "LaunchDaemons"; then
    PERSISTENCE_TYPE="Launch Daemon"
    SCOPE="System"
else
    PERSISTENCE_TYPE="Unknown"
    SCOPE="Unknown"
fi

echo -e "${BLUE}[1/8] Plist Information${NC}"
echo "  Type: $PERSISTENCE_TYPE"
echo "  Scope: $SCOPE"
echo "  Location: $PLIST_PATH"

# File metadata
FILE_SIZE=$(stat -f%z "$PLIST_PATH" 2>/dev/null || echo "N/A")
MODIFIED=$(stat -f%Sm -t%Y-%m-%d\ %H:%M:%S "$PLIST_PATH" 2>/dev/null || echo "N/A")
OWNER=$(stat -f%Su "$PLIST_PATH" 2>/dev/null || echo "N/A")

echo "  Owner: $OWNER"
echo "  Modified: $MODIFIED"
echo "  Size: $FILE_SIZE bytes"
echo ""

# Parse plist contents
echo -e "${BLUE}[2/8] Plist Contents${NC}"

# Extract key fields
LABEL=$(defaults read "$PLIST_PATH" Label 2>/dev/null || echo "N/A")
PROGRAM=$(defaults read "$PLIST_PATH" Program 2>/dev/null || echo "")
PROGRAM_ARGS=$(defaults read "$PLIST_PATH" ProgramArguments 2>/dev/null || echo "")

echo "  Label: $LABEL"

# Determine executable path
if [ -n "$PROGRAM" ]; then
    EXECUTABLE="$PROGRAM"
    echo "  Program: $PROGRAM"
elif [ -n "$PROGRAM_ARGS" ]; then
    # Parse first element of ProgramArguments array
    EXECUTABLE=$(echo "$PROGRAM_ARGS" | grep -o '"[^"]*"' | head -1 | tr -d '"' || echo "")
    echo "  ProgramArguments:"
    echo "$PROGRAM_ARGS" | grep -o '"[^"]*"' | while read -r arg; do
        echo "    - $(echo $arg | tr -d '"')"
    done
else
    EXECUTABLE=""
    echo -e "  ${YELLOW}Warning: No program or arguments defined${NC}"
fi
echo ""

# Parse execution triggers
echo -e "${BLUE}[3/8] Execution Triggers${NC}"

RUN_AT_LOAD=$(defaults read "$PLIST_PATH" RunAtLoad 2>/dev/null || echo "0")
KEEP_ALIVE=$(defaults read "$PLIST_PATH" KeepAlive 2>/dev/null || echo "0")
START_INTERVAL=$(defaults read "$PLIST_PATH" StartInterval 2>/dev/null || echo "")
START_ON_MOUNT=$(defaults read "$PLIST_PATH" StartOnMount 2>/dev/null || echo "0")

echo "  RunAtLoad: $RUN_AT_LOAD"
if [ "$RUN_AT_LOAD" = "1" ]; then
    echo -e "    ${CYAN}Runs automatically at login/boot${NC}"
fi

echo "  KeepAlive: $KEEP_ALIVE"
if [ "$KEEP_ALIVE" = "1" ]; then
    echo -e "    ${YELLOW}Process will be restarted if it exits${NC}"
fi

if [ -n "$START_INTERVAL" ]; then
    echo "  StartInterval: $START_INTERVAL seconds"
    echo -e "    ${CYAN}Runs periodically every $START_INTERVAL seconds${NC}"
fi

if [ "$START_ON_MOUNT" = "1" ]; then
    echo "  StartOnMount: Yes"
    echo -e "    ${CYAN}Runs when filesystem is mounted${NC}"
fi

# Check for queue directories (file watchers)
QUEUE_DIRS=$(defaults read "$PLIST_PATH" QueueDirectories 2>/dev/null || echo "")
WATCH_PATHS=$(defaults read "$PLIST_PATH" WatchPaths 2>/dev/null || echo "")

if [ -n "$QUEUE_DIRS" ]; then
    echo "  QueueDirectories: $QUEUE_DIRS"
fi

if [ -n "$WATCH_PATHS" ]; then
    echo "  WatchPaths: $WATCH_PATHS"
fi
echo ""

# Analyze executable
echo -e "${BLUE}[4/8] Executable Analysis${NC}"

if [ -n "$EXECUTABLE" ] && [ -f "$EXECUTABLE" ]; then
    echo "  Path: $EXECUTABLE"

    # Check if executable exists and is accessible
    if [ -x "$EXECUTABLE" ]; then
        # Get file type
        FILE_TYPE=$(file -b "$EXECUTABLE" 2>/dev/null || echo "unknown")
        echo "  Type: $FILE_TYPE"

        # Check code signature
        CODESIGN_OUTPUT=$(codesign -dvvv "$EXECUTABLE" 2>&1 || echo "")
        AUTHORITY=$(echo "$CODESIGN_OUTPUT" | grep "Authority=" | head -1 | cut -d'=' -f2 || echo "unsigned")
        TEAM_ID=$(echo "$CODESIGN_OUTPUT" | grep "TeamIdentifier=" | cut -d'=' -f2 || echo "N/A")

        echo "  Signature: $AUTHORITY"
        echo "  Team ID: $TEAM_ID"

        # Check if Apple binary
        if echo "$CODESIGN_OUTPUT" | grep -q "Platform Binary"; then
            echo -e "  ${GREEN}✓ Apple platform binary${NC}"
            IS_APPLE="true"
        elif echo "$AUTHORITY" | grep -qi "apple"; then
            echo -e "  ${GREEN}✓ Apple-signed${NC}"
            IS_APPLE="true"
        else
            echo -e "  ${YELLOW}Third-party or unsigned${NC}"
            IS_APPLE="false"
        fi

        # Hash
        SHA256=$(shasum -a 256 "$EXECUTABLE" 2>/dev/null | awk '{print $1}' || echo "N/A")
        echo "  SHA256: $SHA256"
    else
        echo -e "  ${RED}Executable not accessible or not executable${NC}"
    fi
elif [ -n "$EXECUTABLE" ]; then
    echo -e "  Path: $EXECUTABLE ${RED}(not found)${NC}"
    IS_APPLE="false"
else
    echo -e "  ${YELLOW}No executable specified${NC}"
    IS_APPLE="false"
fi
echo ""

# Check environment variables
echo -e "${BLUE}[5/8] Environment & Configuration${NC}"

ENVIRONMENT_VARS=$(defaults read "$PLIST_PATH" EnvironmentVariables 2>/dev/null || echo "")
if [ -n "$ENVIRONMENT_VARS" ]; then
    echo "  Environment Variables:"
    echo "$ENVIRONMENT_VARS"

    # Check for suspicious env vars
    if echo "$ENVIRONMENT_VARS" | grep -qi "DYLD_INSERT_LIBRARIES"; then
        echo -e "    ${RED}⚠ DYLD_INSERT_LIBRARIES detected (dylib injection)${NC}"
    fi
else
    echo "  Environment Variables: None"
fi

# Check working directory
WORKING_DIR=$(defaults read "$PLIST_PATH" WorkingDirectory 2>/dev/null || echo "")
if [ -n "$WORKING_DIR" ]; then
    echo "  Working Directory: $WORKING_DIR"
fi

# Check for standard out/err redirection
STDOUT=$(defaults read "$PLIST_PATH" StandardOutPath 2>/dev/null || echo "")
STDERR=$(defaults read "$PLIST_PATH" StandardErrorPath 2>/dev/null || echo "")

if [ -n "$STDOUT" ]; then
    echo "  StandardOut: $STDOUT"
fi

if [ -n "$STDERR" ]; then
    echo "  StandardError: $STDERR"
fi

# Check for user context
USER_NAME=$(defaults read "$PLIST_PATH" UserName 2>/dev/null || echo "")
GROUP_NAME=$(defaults read "$PLIST_PATH" GroupName 2>/dev/null || echo "")

if [ -n "$USER_NAME" ]; then
    echo "  Runs as user: $USER_NAME"
fi

if [ -n "$GROUP_NAME" ]; then
    echo "  Runs as group: $GROUP_NAME"
fi
echo ""

# Network listeners
echo -e "${BLUE}[6/8] Network Configuration${NC}"

SOCKETS=$(defaults read "$PLIST_PATH" Sockets 2>/dev/null || echo "")
if [ -n "$SOCKETS" ]; then
    echo "  Network Sockets: Configured"
    echo "$SOCKETS"
else
    echo "  Network Sockets: None configured"
fi
echo ""

# Check if currently loaded
echo -e "${BLUE}[7/8] Current Status${NC}"

LOADED_STATUS=$(launchctl list | grep "$LABEL" 2>/dev/null || echo "")
if [ -n "$LOADED_STATUS" ]; then
    echo -e "  ${CYAN}Currently loaded${NC}"
    PID=$(echo "$LOADED_STATUS" | awk '{print $1}')
    STATUS=$(echo "$LOADED_STATUS" | awk '{print $2}')
    echo "  PID: $PID"
    echo "  Last Exit: $STATUS"
else
    echo "  Not currently loaded"
fi
echo ""

# Suspicious indicators
echo -e "${BLUE}[8/8] Suspicious Indicators${NC}"

SUSPICIOUS=()
RISK_SCORE=0

# Check executable path
if [ -n "$EXECUTABLE" ]; then
    if echo "$EXECUTABLE" | grep -qE "^/(tmp|var/tmp)|/Users/.*/Downloads|/Users/.*/Desktop|/Users/.*/Library/Caches"; then
        SUSPICIOUS+=("Executable in suspicious location: $EXECUTABLE")
        RISK_SCORE=$((RISK_SCORE + 5))
    fi
fi

# Check for unsigned binary
if [ "$IS_APPLE" = "false" ] && [ -n "$EXECUTABLE" ] && [ -f "$EXECUTABLE" ]; then
    if [ "$AUTHORITY" = "unsigned" ]; then
        SUSPICIOUS+=("Executable is unsigned")
        RISK_SCORE=$((RISK_SCORE + 4))
    fi
fi

# Check persistence configuration
if [ "$RUN_AT_LOAD" = "1" ] && [ "$KEEP_ALIVE" = "1" ]; then
    SUSPICIOUS+=("Both RunAtLoad and KeepAlive enabled (very persistent)")
    RISK_SCORE=$((RISK_SCORE + 2))
fi

# Check for DYLD injection
if echo "$ENVIRONMENT_VARS" | grep -qi "DYLD_INSERT_LIBRARIES\|DYLD_LIBRARY_PATH"; then
    SUSPICIOUS+=("DYLD environment variables configured (dylib injection)")
    RISK_SCORE=$((RISK_SCORE + 5))
fi

# Check for hidden output
if echo "$STDOUT" | grep -q "/dev/null" && echo "$STDERR" | grep -q "/dev/null"; then
    SUSPICIOUS+=("Output redirected to /dev/null (hiding activity)")
    RISK_SCORE=$((RISK_SCORE + 2))
fi

# Check for suspicious arguments
if echo "$PROGRAM_ARGS" | grep -qE "bash -c|sh -c|python -c|curl.*\||base64|nc |netcat"; then
    SUSPICIOUS+=("Suspicious command-line patterns detected")
    RISK_SCORE=$((RISK_SCORE + 4))
fi

# Check daemon running as root from user location
if [ "$PERSISTENCE_TYPE" = "Launch Daemon" ] && echo "$PLIST_PATH" | grep -q "/Users/"; then
    SUSPICIOUS+=("System daemon in user directory (unusual)")
    RISK_SCORE=$((RISK_SCORE + 3))
fi

if [ ${#SUSPICIOUS[@]} -eq 0 ]; then
    echo -e "  ${GREEN}✓ No obvious suspicious indicators${NC}"
else
    echo -e "  ${RED}Found ${#SUSPICIOUS[@]} suspicious indicator(s):${NC}"
    for indicator in "${SUSPICIOUS[@]}"; do
        echo -e "    ${RED}•${NC} $indicator"
    done
fi
echo ""

# Generate verdict
echo -e "${BLUE}=== Triage Verdict ===${NC}\n"

# Adjust score based on Apple signature
if [ "$IS_APPLE" = "true" ]; then
    RISK_SCORE=$((RISK_SCORE - 10))
    if [ $RISK_SCORE -lt 0 ]; then
        RISK_SCORE=0
    fi
fi

if [ $RISK_SCORE -ge 8 ]; then
    echo -e "${RED}Risk Level: HIGH${NC}"
    echo "Recommendation: Likely malicious. Remove and investigate system compromise."
    echo ""
    echo "Immediate Actions:"
    echo "  1. Unload: launchctl unload \"$PLIST_PATH\""
    echo "  2. Remove: rm \"$PLIST_PATH\""
    echo "  3. Investigate executable: \"$EXECUTABLE\""
    echo "  4. Check for additional persistence mechanisms"
    echo "  5. Review system logs for related activity"
elif [ $RISK_SCORE -ge 4 ]; then
    echo -e "${YELLOW}Risk Level: MEDIUM${NC}"
    echo "Recommendation: Suspicious. Further investigation required."
    echo ""
    echo "Investigation Steps:"
    echo "  1. Verify if this is a known/expected application"
    echo "  2. Check executable signature and reputation"
    echo "  3. Review what installed this (check installer logs)"
    echo "  4. Monitor behavior if allowed to run"
elif [ $RISK_SCORE -ge 1 ]; then
    echo -e "${CYAN}Risk Level: LOW-MEDIUM${NC}"
    echo "Recommendation: Appears legitimate but has some unusual characteristics."
    echo ""
    echo "Verification Steps:"
    echo "  1. Confirm this matches expected software on this system"
    echo "  2. Verify developer identity"
    echo "  3. Check application reputation online"
else
    echo -e "${GREEN}Risk Level: LOW${NC}"
    echo "Recommendation: Appears to be legitimate system component or application."
    echo ""
    echo "Standard Verification:"
    echo "  1. Confirm this is expected for installed applications"
    echo "  2. Baseline against other similar systems"
fi

echo ""
echo "Additional Context:"
echo "  • Search hash on VirusTotal: https://www.virustotal.com/gui/file/$SHA256"
echo "  • Check for known malware using this label: $LABEL"
echo "  • Review EDR/SIEM for related process execution events"
