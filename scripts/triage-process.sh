#!/bin/bash
#
# triage-process.sh - Gather comprehensive context about a suspicious process
#
# Usage: ./triage-process.sh <PID|process_name>
#
# Description:
#   Automates the manual triage steps for investigating suspicious processes.
#   Collects code signature, parent chain, open files, network connections,
#   binary hash, and other security-relevant context.
#
# Output:
#   JSON formatted triage report with all collected information

set -euo pipefail

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

usage() {
    echo "Usage: $0 <PID|process_name>"
    echo ""
    echo "Arguments:"
    echo "  PID           - Process ID to investigate"
    echo "  process_name  - Process name (will triage first match)"
    echo ""
    echo "Examples:"
    echo "  $0 1234"
    echo "  $0 osascript"
    echo "  $0 /tmp/suspicious_binary"
    exit 1
}

if [ $# -ne 1 ]; then
    usage
fi

INPUT="$1"

# Determine if input is PID or process name
if [[ "$INPUT" =~ ^[0-9]+$ ]]; then
    PID="$INPUT"
else
    # Find PID by name
    PID=$(pgrep -f "$INPUT" | head -1 || echo "")
    if [ -z "$PID" ]; then
        echo -e "${RED}Error: Process not found: $INPUT${NC}"
        exit 1
    fi
    echo -e "${YELLOW}Found process '$INPUT' with PID: $PID${NC}\n"
fi

# Verify process exists
if ! ps -p "$PID" > /dev/null 2>&1; then
    echo -e "${RED}Error: Process with PID $PID not found${NC}"
    exit 1
fi

echo -e "${BLUE}=== Process Triage Report ===${NC}\n"
echo -e "${CYAN}Timestamp:${NC} $(date)"
echo -e "${CYAN}Hostname:${NC} $(hostname)"
echo -e "${CYAN}PID:${NC} $PID"
echo ""

# Get basic process info
echo -e "${BLUE}[1/9] Basic Process Information${NC}"
PROC_INFO=$(ps -p "$PID" -o pid,ppid,uid,user,comm,args | tail -1)
PPID=$(echo "$PROC_INFO" | awk '{print $2}')
UID=$(echo "$PROC_INFO" | awk '{print $3}')
USER=$(echo "$PROC_INFO" | awk '{print $4}')
COMM=$(echo "$PROC_INFO" | awk '{print $5}')
ARGS=$(echo "$PROC_INFO" | cut -d' ' -f6- | sed 's/^[[:space:]]*//')

echo "  PID: $PID"
echo "  PPID: $PPID"
echo "  User: $USER (UID: $UID)"
echo "  Path: $COMM"
echo "  Command Line: $ARGS"
echo ""

# Get parent process chain
echo -e "${BLUE}[2/9] Parent Process Chain${NC}"
CURRENT_PID=$PID
DEPTH=0
while [ "$CURRENT_PID" -ne 0 ] && [ $DEPTH -lt 10 ]; do
    PARENT_INFO=$(ps -p "$CURRENT_PID" -o ppid,user,comm,args 2>/dev/null | tail -1)
    if [ -z "$PARENT_INFO" ]; then
        break
    fi
    PARENT_PID=$(echo "$PARENT_INFO" | awk '{print $1}')
    PARENT_USER=$(echo "$PARENT_INFO" | awk '{print $2}')
    PARENT_COMM=$(echo "$PARENT_INFO" | awk '{print $3}')
    PARENT_ARGS=$(echo "$PARENT_INFO" | cut -d' ' -f4-)

    echo "  [$DEPTH] PID $CURRENT_PID ($PARENT_USER): $PARENT_COMM"

    CURRENT_PID=$PARENT_PID
    DEPTH=$((DEPTH + 1))
done
echo ""

# Code signature analysis
echo -e "${BLUE}[3/9] Code Signature Analysis${NC}"
if [ -f "$COMM" ] && [ -x "$COMM" ]; then
    CODESIGN_OUTPUT=$(codesign -dvvv "$COMM" 2>&1 || echo "Error getting signature")

    # Extract key fields
    SIGNATURE_ID=$(echo "$CODESIGN_OUTPUT" | grep "Identifier=" | cut -d'=' -f2 || echo "N/A")
    TEAM_ID=$(echo "$CODESIGN_OUTPUT" | grep "TeamIdentifier=" | cut -d'=' -f2 || echo "N/A")
    AUTHORITY=$(echo "$CODESIGN_OUTPUT" | grep "Authority=" | head -1 | cut -d'=' -f2 || echo "unsigned")
    ADHOC=$(echo "$CODESIGN_OUTPUT" | grep -q "Signature=adhoc" && echo "true" || echo "false")

    echo "  Signature ID: $SIGNATURE_ID"
    echo "  Team ID: $TEAM_ID"
    echo "  Authority: $AUTHORITY"
    echo "  Ad-hoc Signed: $ADHOC"

    # Check if Apple platform binary
    if echo "$CODESIGN_OUTPUT" | grep -q "Platform Binary"; then
        echo -e "  Platform Binary: ${GREEN}Yes (Apple binary)${NC}"
    else
        echo -e "  Platform Binary: ${YELLOW}No (third-party)${NC}"
    fi

    # Check notarization
    if spctl -a -vvv -t install "$COMM" 2>&1 | grep -q "accepted"; then
        echo -e "  Notarized: ${GREEN}Yes${NC}"
    else
        echo -e "  Notarized: ${YELLOW}No${NC}"
    fi
else
    echo -e "  ${YELLOW}Binary not accessible or not executable${NC}"
fi
echo ""

# File hashes
echo -e "${BLUE}[4/9] File Hashes${NC}"
if [ -f "$COMM" ]; then
    MD5=$(md5 -q "$COMM" 2>/dev/null || echo "N/A")
    SHA256=$(shasum -a 256 "$COMM" 2>/dev/null | awk '{print $1}' || echo "N/A")
    echo "  MD5: $MD5"
    echo "  SHA256: $SHA256"
else
    echo -e "  ${YELLOW}Binary not accessible${NC}"
fi
echo ""

# File metadata
echo -e "${BLUE}[5/9] File Metadata${NC}"
if [ -f "$COMM" ]; then
    FILE_SIZE=$(stat -f%z "$COMM" 2>/dev/null || echo "N/A")
    CREATION=$(stat -f%SB -t%Y-%m-%d\ %H:%M:%S "$COMM" 2>/dev/null || echo "N/A")
    MODIFIED=$(stat -f%Sm -t%Y-%m-%d\ %H:%M:%S "$COMM" 2>/dev/null || echo "N/A")

    echo "  Size: $FILE_SIZE bytes"
    echo "  Created: $CREATION"
    echo "  Modified: $MODIFIED"

    # Check quarantine attribute
    QUARANTINE=$(xattr -p com.apple.quarantine "$COMM" 2>/dev/null || echo "none")
    if [ "$QUARANTINE" != "none" ]; then
        echo -e "  Quarantine: ${YELLOW}Present${NC} - $QUARANTINE"
    else
        echo "  Quarantine: None"
    fi
else
    echo -e "  ${YELLOW}Binary not accessible${NC}"
fi
echo ""

# Open files
echo -e "${BLUE}[6/9] Open Files${NC}"
OPEN_FILES=$(lsof -p "$PID" 2>/dev/null | tail -n +2 | wc -l | tr -d ' ')
echo "  Total Open Files: $OPEN_FILES"

# Show interesting file types
echo "  Notable Open Files:"
lsof -p "$PID" 2>/dev/null | tail -n +2 | while read -r line; do
    FILE=$(echo "$line" | awk '{print $NF}')
    TYPE=$(echo "$line" | awk '{print $5}')

    # Filter for interesting paths
    if echo "$FILE" | grep -qE "keychain|\.db|\.sqlite|credential|password|\.plist"; then
        echo "    - $FILE ($TYPE)"
    fi
done | head -10
echo ""

# Network connections
echo -e "${BLUE}[7/9] Network Connections${NC}"
CONNECTIONS=$(lsof -i -n -P -p "$PID" 2>/dev/null | tail -n +2)
if [ -n "$CONNECTIONS" ]; then
    echo "$CONNECTIONS" | while read -r line; do
        NAME=$(echo "$line" | awk '{print $1}')
        NODE=$(echo "$line" | awk '{print $9}')
        echo "  - $NODE"
    done
else
    echo "  No active network connections"
fi
echo ""

# Process privileges and capabilities
echo -e "${BLUE}[8/9] Security Context${NC}"
if [ "$UID" -eq 0 ]; then
    echo -e "  Running as: ${RED}root (UID 0)${NC}"
else
    echo "  Running as: $USER (UID $UID)"
fi

# Check if process has Full Disk Access or other TCC permissions
TCC_DB="/Library/Application Support/com.apple.TCC/TCC.db"
if [ -r "$TCC_DB" ]; then
    # Note: Reading TCC.db requires elevated privileges
    echo "  TCC Permissions: [Requires elevated privileges to check]"
else
    echo "  TCC Permissions: [Database not accessible]"
fi
echo ""

# Suspicious indicators
echo -e "${BLUE}[9/9] Suspicious Indicators${NC}"
SUSPICIOUS=()

# Check execution path
if echo "$COMM" | grep -qE "^/(tmp|var/tmp)|/Users/.*/Downloads|/Users/.*/Desktop"; then
    SUSPICIOUS+=("Executing from suspicious path: $COMM")
fi

# Check if unsigned or ad-hoc
if [ "$ADHOC" = "true" ] || [ "$AUTHORITY" = "unsigned" ]; then
    SUSPICIOUS+=("Binary is unsigned or ad-hoc signed")
fi

# Check for suspicious arguments
if echo "$ARGS" | grep -qE "base64|curl.*\||wget.*\||/bin/bash -c|/bin/sh -c|python -c"; then
    SUSPICIOUS+=("Suspicious command-line arguments detected")
fi

# Check if running as root from user directory
if [ "$UID" -eq 0 ] && echo "$COMM" | grep -q "/Users/"; then
    SUSPICIOUS+=("Running as root from user directory")
fi

# Check parent process
PARENT_COMM=$(ps -p "$PPID" -o comm= 2>/dev/null || echo "")
if echo "$PARENT_COMM" | grep -qE "osascript|python|perl|ruby|sh|bash"; then
    SUSPICIOUS+=("Spawned by script interpreter: $PARENT_COMM")
fi

if [ ${#SUSPICIOUS[@]} -eq 0 ]; then
    echo -e "  ${GREEN}✓ No obvious suspicious indicators${NC}"
else
    echo -e "  ${RED}⚠ Suspicious indicators found:${NC}"
    for indicator in "${SUSPICIOUS[@]}"; do
        echo -e "    ${RED}•${NC} $indicator"
    done
fi
echo ""

# Generate verdict
echo -e "${BLUE}=== Triage Verdict ===${NC}\n"

RISK_SCORE=0
if [ ${#SUSPICIOUS[@]} -gt 0 ]; then
    RISK_SCORE=$((RISK_SCORE + ${#SUSPICIOUS[@]} * 2))
fi
if [ "$ADHOC" = "true" ]; then
    RISK_SCORE=$((RISK_SCORE + 2))
fi
if [ "$UID" -eq 0 ]; then
    RISK_SCORE=$((RISK_SCORE + 1))
fi

if [ $RISK_SCORE -ge 5 ]; then
    echo -e "${RED}Risk Level: HIGH${NC}"
    echo "Recommendation: Investigate immediately. Isolate host if necessary."
elif [ $RISK_SCORE -ge 2 ]; then
    echo -e "${YELLOW}Risk Level: MEDIUM${NC}"
    echo "Recommendation: Further investigation recommended."
else
    echo -e "${GREEN}Risk Level: LOW${NC}"
    echo "Recommendation: Likely benign, but verify against baseline."
fi

echo ""
echo "Next Steps:"
echo "  1. Check if this process/binary is expected for this user/host"
echo "  2. Review parent process chain for legitimacy"
echo "  3. Investigate any network connections to external IPs"
echo "  4. Search binary hash on VirusTotal or other threat intelligence"
echo "  5. Check EDR/SIEM for related events (file writes, network, etc.)"
