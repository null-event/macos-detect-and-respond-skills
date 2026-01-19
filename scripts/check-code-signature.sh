#!/bin/bash
#
# check-code-signature.sh - Analyze binary code signatures in detail
#
# Usage: ./check-code-signature.sh <binary_path>
#
# Description:
#   Performs comprehensive code signature analysis including signing details,
#   team ID, entitlements, notarization status, and trust evaluation.
#   Critical for determining if a binary is trusted on macOS.
#
# Output:
#   Detailed signature analysis with trust verdict

set -euo pipefail

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

usage() {
    echo "Usage: $0 <binary_path>"
    echo ""
    echo "Arguments:"
    echo "  binary_path  - Path to the binary to analyze"
    echo ""
    echo "Examples:"
    echo "  $0 /Applications/Safari.app"
    echo "  $0 /usr/bin/python3"
    echo "  $0 /tmp/suspicious_binary"
    exit 1
}

if [ $# -ne 1 ]; then
    usage
fi

BINARY_PATH="$1"

# Verify binary exists
if [ ! -e "$BINARY_PATH" ]; then
    echo -e "${RED}Error: File not found: $BINARY_PATH${NC}"
    exit 1
fi

echo -e "${BLUE}=== Code Signature Analysis ===${NC}\n"
echo -e "${CYAN}File:${NC} $BINARY_PATH"
echo -e "${CYAN}Timestamp:${NC} $(date)"
echo ""

# Basic file info
echo -e "${BLUE}[1/6] File Information${NC}"
if [ -d "$BINARY_PATH" ]; then
    FILE_TYPE="Bundle/Application"
    # For bundles, find the actual executable
    if [ -d "$BINARY_PATH/Contents/MacOS" ]; then
        ACTUAL_BINARY=$(find "$BINARY_PATH/Contents/MacOS" -type f -perm +111 | head -1)
        if [ -n "$ACTUAL_BINARY" ]; then
            echo "  Type: Application Bundle"
            echo "  Executable: $ACTUAL_BINARY"
            BINARY_TO_CHECK="$BINARY_PATH"
        else
            echo -e "  ${YELLOW}Warning: No executable found in bundle${NC}"
            BINARY_TO_CHECK="$BINARY_PATH"
        fi
    else
        echo "  Type: Directory/Bundle"
        BINARY_TO_CHECK="$BINARY_PATH"
    fi
elif [ -f "$BINARY_PATH" ]; then
    FILE_TYPE=$(file -b "$BINARY_PATH")
    echo "  Type: $FILE_TYPE"
    BINARY_TO_CHECK="$BINARY_PATH"
else
    echo -e "  ${RED}Unknown file type${NC}"
    exit 1
fi

FILE_SIZE=$(du -h "$BINARY_PATH" | cut -f1)
echo "  Size: $FILE_SIZE"
echo ""

# Code signature verification
echo -e "${BLUE}[2/6] Signature Verification${NC}"
CODESIGN_OUTPUT=$(codesign -dvvv "$BINARY_TO_CHECK" 2>&1)
CODESIGN_EXIT=$?

if [ $CODESIGN_EXIT -eq 0 ]; then
    echo -e "  Status: ${GREEN}Signed${NC}"
else
    echo -e "  Status: ${RED}Unsigned or invalid signature${NC}"
fi

# Parse signature details
IDENTIFIER=$(echo "$CODESIGN_OUTPUT" | grep "^Identifier=" | cut -d'=' -f2 || echo "N/A")
FORMAT=$(echo "$CODESIGN_OUTPUT" | grep "^Format=" | cut -d'=' -f2 || echo "N/A")
CDH=$(echo "$CODESIGN_OUTPUT" | grep "^CodeDirectory" | head -1 | cut -d'=' -f2 || echo "N/A")

echo "  Identifier: $IDENTIFIER"
echo "  Format: $FORMAT"

# Check signature type
if echo "$CODESIGN_OUTPUT" | grep -q "Signature=adhoc"; then
    echo -e "  Signature Type: ${YELLOW}Ad-hoc (self-signed)${NC}"
    SIGNATURE_TYPE="adhoc"
elif echo "$CODESIGN_OUTPUT" | grep -q "Authority="; then
    echo -e "  Signature Type: ${GREEN}Developer Certificate${NC}"
    SIGNATURE_TYPE="developer"
else
    echo -e "  Signature Type: ${RED}Unknown/Invalid${NC}"
    SIGNATURE_TYPE="unknown"
fi
echo ""

# Certificate chain
echo -e "${BLUE}[3/6] Certificate Chain${NC}"
AUTHORITIES=$(echo "$CODESIGN_OUTPUT" | grep "^Authority=" || echo "")
if [ -n "$AUTHORITIES" ]; then
    echo "$AUTHORITIES" | while read -r line; do
        AUTHORITY=$(echo "$line" | cut -d'=' -f2)
        echo "  • $AUTHORITY"
    done

    # Check if Apple-signed
    if echo "$AUTHORITIES" | grep -q "Apple"; then
        echo ""
        echo -e "  ${GREEN}✓ Signed by Apple${NC}"
        IS_APPLE="true"
    else
        echo ""
        echo -e "  ${YELLOW}Third-party developer certificate${NC}"
        IS_APPLE="false"
    fi
else
    echo -e "  ${YELLOW}No certificate chain (ad-hoc or unsigned)${NC}"
    IS_APPLE="false"
fi
echo ""

# Team Identifier
echo -e "${BLUE}[4/6] Developer Information${NC}"
TEAM_ID=$(echo "$CODESIGN_OUTPUT" | grep "^TeamIdentifier=" | cut -d'=' -f2 || echo "N/A")
echo "  Team ID: $TEAM_ID"

# Platform binary check
if echo "$CODESIGN_OUTPUT" | grep -q "flags=.*platform"; then
    echo -e "  Platform Binary: ${GREEN}Yes (Apple system binary)${NC}"
    IS_PLATFORM="true"
else
    echo "  Platform Binary: No"
    IS_PLATFORM="false"
fi

# Runtime version
RUNTIME=$(echo "$CODESIGN_OUTPUT" | grep "^Runtime Version=" | cut -d'=' -f2 || echo "N/A")
if [ "$RUNTIME" != "N/A" ]; then
    echo "  Runtime Version: $RUNTIME (Hardened Runtime enabled)"
else
    echo "  Runtime Version: N/A (Hardened Runtime not enabled)"
fi
echo ""

# Entitlements
echo -e "${BLUE}[5/6] Entitlements${NC}"
ENTITLEMENTS=$(codesign -d --entitlements - "$BINARY_TO_CHECK" 2>/dev/null | xmllint --format - 2>/dev/null || echo "")

if [ -n "$ENTITLEMENTS" ]; then
    # Count entitlements
    ENT_COUNT=$(echo "$ENTITLEMENTS" | grep -c "<key>" || echo "0")
    echo "  Total Entitlements: $ENT_COUNT"
    echo ""
    echo "  Key Entitlements:"

    # Show important entitlements
    if echo "$ENTITLEMENTS" | grep -q "com.apple.security.app-sandbox"; then
        SANDBOX=$(echo "$ENTITLEMENTS" | grep -A1 "com.apple.security.app-sandbox" | tail -1 | grep -o "true\|false")
        echo -e "    • App Sandbox: ${CYAN}$SANDBOX${NC}"
    fi

    if echo "$ENTITLEMENTS" | grep -q "com.apple.security.cs.allow-unsigned-executable-memory"; then
        echo -e "    • ${YELLOW}Allow Unsigned Executable Memory${NC} (security risk)"
    fi

    if echo "$ENTITLEMENTS" | grep -q "com.apple.security.cs.disable-library-validation"; then
        echo -e "    • ${YELLOW}Disable Library Validation${NC} (allows loading arbitrary dylibs)"
    fi

    if echo "$ENTITLEMENTS" | grep -q "com.apple.security.get-task-allow"; then
        echo -e "    • ${YELLOW}Allow Task for PID${NC} (debugging entitlement)"
    fi

    if echo "$ENTITLEMENTS" | grep -q "keychain-access-groups"; then
        echo "    • Keychain Access Groups (defined)"
    fi

    # Show all entitlement keys
    if [ $ENT_COUNT -gt 0 ]; then
        echo ""
        echo "  All Entitlements:"
        echo "$ENTITLEMENTS" | grep "<key>" | sed 's/.*<key>\(.*\)<\/key>/    - \1/'
    fi
else
    echo "  No entitlements"
fi
echo ""

# Notarization and trust
echo -e "${BLUE}[6/6] Notarization & Trust${NC}"

# Check notarization
NOTARIZATION=$(spctl -a -vvv -t install "$BINARY_TO_CHECK" 2>&1 || echo "")
if echo "$NOTARIZATION" | grep -q "accepted"; then
    echo -e "  Notarization: ${GREEN}✓ Notarized by Apple${NC}"
    IS_NOTARIZED="true"

    # Extract ticket info
    if echo "$NOTARIZATION" | grep -q "source="; then
        SOURCE=$(echo "$NOTARIZATION" | grep "source=" | sed 's/.*source=//')
        echo "  Source: $SOURCE"
    fi
else
    echo -e "  Notarization: ${YELLOW}Not notarized${NC}"
    IS_NOTARIZED="false"

    if echo "$NOTARIZATION" | grep -q "rejected"; then
        echo -e "  ${RED}! Explicitly rejected by Gatekeeper${NC}"
    fi
fi

# Check Gatekeeper assessment
GATEKEEPER=$(spctl -a -t exec -vvv "$BINARY_TO_CHECK" 2>&1 || echo "")
if echo "$GATEKEEPER" | grep -q "accepted"; then
    echo -e "  Gatekeeper: ${GREEN}✓ Accepted${NC}"
else
    echo -e "  Gatekeeper: ${YELLOW}Would be blocked${NC}"
fi

# Check quarantine status
if [ -f "$BINARY_PATH" ]; then
    QUARANTINE=$(xattr -p com.apple.quarantine "$BINARY_PATH" 2>/dev/null || echo "")
    if [ -n "$QUARANTINE" ]; then
        echo -e "  Quarantine Flag: ${CYAN}Present${NC}"
        echo "    $QUARANTINE"
    else
        echo "  Quarantine Flag: Not present"
    fi
fi
echo ""

# Trust verdict
echo -e "${BLUE}=== Trust Verdict ===${NC}\n"

TRUST_SCORE=0
ISSUES=()
NOTES=()

# Scoring logic
if [ "$IS_PLATFORM" = "true" ]; then
    TRUST_SCORE=$((TRUST_SCORE + 10))
    NOTES+=("Apple platform binary (highest trust)")
fi

if [ "$IS_APPLE" = "true" ]; then
    TRUST_SCORE=$((TRUST_SCORE + 8))
    NOTES+=("Signed by Apple")
fi

if [ "$IS_NOTARIZED" = "true" ]; then
    TRUST_SCORE=$((TRUST_SCORE + 5))
    NOTES+=("Notarized by Apple")
fi

if [ "$SIGNATURE_TYPE" = "developer" ] && [ "$IS_APPLE" != "true" ]; then
    TRUST_SCORE=$((TRUST_SCORE + 3))
    NOTES+=("Signed by registered developer")
fi

if [ "$SIGNATURE_TYPE" = "adhoc" ]; then
    TRUST_SCORE=$((TRUST_SCORE - 5))
    ISSUES+=("Ad-hoc signature (self-signed)")
fi

if [ "$SIGNATURE_TYPE" = "unknown" ]; then
    TRUST_SCORE=$((TRUST_SCORE - 10))
    ISSUES+=("Unsigned or invalid signature")
fi

# Check for risky entitlements
if echo "$ENTITLEMENTS" | grep -q "com.apple.security.cs.allow-unsigned-executable-memory"; then
    ISSUES+=("Allows unsigned executable memory")
fi

if echo "$ENTITLEMENTS" | grep -q "com.apple.security.cs.disable-library-validation"; then
    ISSUES+=("Library validation disabled")
fi

# Final verdict
if [ $TRUST_SCORE -ge 10 ]; then
    echo -e "${GREEN}Trust Level: HIGH (Score: $TRUST_SCORE)${NC}"
    echo "Verdict: Trusted binary, safe to execute"
elif [ $TRUST_SCORE -ge 5 ]; then
    echo -e "${CYAN}Trust Level: MEDIUM (Score: $TRUST_SCORE)${NC}"
    echo "Verdict: Likely safe, but verify developer identity"
elif [ $TRUST_SCORE -ge 0 ]; then
    echo -e "${YELLOW}Trust Level: LOW (Score: $TRUST_SCORE)${NC}"
    echo "Verdict: Proceed with caution, investigate further"
else
    echo -e "${RED}Trust Level: UNTRUSTED (Score: $TRUST_SCORE)${NC}"
    echo "Verdict: Do not execute without thorough analysis"
fi

echo ""

if [ ${#NOTES[@]} -gt 0 ]; then
    echo "Positive Indicators:"
    for note in "${NOTES[@]}"; do
        echo -e "  ${GREEN}✓${NC} $note"
    done
    echo ""
fi

if [ ${#ISSUES[@]} -gt 0 ]; then
    echo "Security Concerns:"
    for issue in "${ISSUES[@]}"; do
        echo -e "  ${YELLOW}⚠${NC} $issue"
    done
    echo ""
fi

echo "Recommendations:"
if [ $TRUST_SCORE -lt 5 ]; then
    echo "  1. Do not execute this binary without investigation"
    echo "  2. Search binary hash on threat intelligence platforms"
    echo "  3. Review where this binary came from"
    echo "  4. Consider sandboxed execution if testing is needed"
else
    echo "  1. Verify the developer/publisher is expected"
    echo "  2. Check if this binary is required for your use case"
    echo "  3. Monitor execution for unexpected behavior"
fi
