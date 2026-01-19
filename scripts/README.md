# macOS Detect and Respond Scripts

This directory contains utility scripts that complement the macOS Detect and Respond skill. These scripts automate common detection engineering, triage, and analysis tasks for macOS security.

## Quick Reference

| Script | Purpose | Use Case |
|--------|---------|----------|
| [triage-process.sh](#triage-processsh) | Investigate suspicious processes | Alert triage, incident response |
| [check-code-signature.sh](#check-code-signaturesh) | Analyze binary signatures | Trust evaluation, malware analysis |
| [analyze-launch-agent.sh](#analyze-launch-agentsh) | Inspect persistence mechanisms | Persistence triage, baseline validation |
| [collect-es-events.sh](#collect-es-eventssh) | Collect Endpoint Security events | Threat hunting, detection testing |
| [generate-sigma-rule.py](#generate-sigma-rulepy) | Create Sigma detection rules | Detection authoring, rule development |
| [convert-detection.py](#convert-detectionpy) | Convert detection formats | Porting detections between platforms |

---

## Scripts

### triage-process.sh

**Gather comprehensive context about a suspicious process**

Automates the manual triage steps for investigating suspicious processes by collecting code signature, parent chain, open files, network connections, binary hash, and other security-relevant context.

**Usage:**
```bash
./triage-process.sh <PID|process_name>
```

**Examples:**
```bash
# Triage by PID
./triage-process.sh 1234

# Triage by process name
./triage-process.sh osascript

# Triage by binary path
./triage-process.sh /tmp/suspicious_binary
```

**Output:**
- Process metadata (PID, user, path, command line)
- Parent process chain (up to 10 levels)
- Code signature analysis (signing authority, team ID, notarization)
- File hashes (MD5, SHA256)
- File metadata (size, timestamps, quarantine status)
- Open files (with focus on sensitive files)
- Network connections
- Security context (privileges, TCC permissions)
- Suspicious indicators and risk assessment
- Triage verdict (HIGH/MEDIUM/LOW risk)

**When to use:**
- Investigating alerts for suspicious process execution
- Triaging EDR detections
- Incident response and forensic analysis
- Validating if a process is benign or malicious

---

### check-code-signature.sh

**Analyze binary code signatures in detail**

Performs comprehensive code signature analysis including signing details, team ID, entitlements, notarization status, and trust evaluation. Critical for determining if a binary is trusted on macOS.

**Usage:**
```bash
./check-code-signature.sh <binary_path>
```

**Examples:**
```bash
# Check application bundle
./check-code-signature.sh /Applications/Safari.app

# Check system binary
./check-code-signature.sh /usr/bin/python3

# Check suspicious binary
./check-code-signature.sh /tmp/suspicious_binary
```

**Output:**
- File information (type, size)
- Signature verification status
- Certificate chain
- Developer information (Team ID, platform binary status)
- Entitlements (including security-sensitive ones)
- Notarization and Gatekeeper assessment
- Quarantine status
- Trust verdict with scoring

**When to use:**
- Determining if a binary should be trusted
- Analyzing malware samples
- Understanding application permissions (entitlements)
- Validating code signing for security assessment
- Pre-execution trust evaluation

**Trust Scoring:**
- HIGH (10+): Apple platform binaries, trusted system components
- MEDIUM (5-9): Notarized third-party apps, signed by registered developers
- LOW (0-4): Developer-signed but not notarized
- UNTRUSTED (<0): Unsigned, ad-hoc signed, or invalid signatures

---

### analyze-launch-agent.sh

**Inspect and triage launch agent/daemon plists**

Automates launch agent/daemon triage by parsing the plist, analyzing the target executable, checking for suspicious indicators, and providing a verdict on whether the persistence mechanism is benign or malicious.

**Usage:**
```bash
./analyze-launch-agent.sh <plist_path>
```

**Examples:**
```bash
# Analyze user launch agent
./analyze-launch-agent.sh ~/Library/LaunchAgents/com.example.agent.plist

# Analyze system daemon
./analyze-launch-agent.sh /Library/LaunchDaemons/com.suspicious.daemon.plist

# Analyze from alert
./analyze-launch-agent.sh "/Users/user/Library/LaunchAgents/com.malware.plist"
```

**Output:**
- Plist metadata (type, scope, owner, modification time)
- Parsed plist contents (label, program, arguments)
- Execution triggers (RunAtLoad, KeepAlive, StartInterval)
- Executable analysis (path, signature, hash)
- Environment variables (including DYLD injection checks)
- Network configuration (if listening)
- Current load status
- Suspicious indicators
- Risk assessment (HIGH/MEDIUM/LOW)

**Suspicious Indicators:**
- Executable in unusual paths (/tmp, ~/Downloads)
- Unsigned or ad-hoc signed binaries
- Both RunAtLoad and KeepAlive enabled
- DYLD environment variables (dylib injection)
- Output redirected to /dev/null
- Suspicious command-line patterns
- System daemon in user directory

**When to use:**
- Triaging persistence mechanism alerts
- Baseline validation for launch agents/daemons
- Malware persistence analysis
- Incident response for persistence investigation

---

### collect-es-events.sh

**Collect Endpoint Security events for analysis**

Collects Endpoint Security events from common macOS EDR tools or unified logs for a specified time window. Useful for threat hunting and detection testing.

**Usage:**
```bash
./collect-es-events.sh [options]
```

**Options:**
```
-t, --time-range <range>    Time range (e.g., "1h", "30m", "1d")
-e, --event-types <types>   Comma-separated ES event types
-o, --output <file>         Output JSON file
-s, --source <source>       Data source (esf-client, jamf, unified-log)
-h, --help                  Show help
```

**Examples:**
```bash
# Collect last 2 hours of EXEC and FORK events
./collect-es-events.sh -t 2h -e EXEC,FORK

# Collect last 30 minutes to specific file
./collect-es-events.sh -t 30m -o recent_events.json

# Collect from Jamf Protect for 1 day
./collect-es-events.sh --source jamf --time-range 1d

# Collect all event types for last hour
./collect-es-events.sh -t 1h
```

**Supported Sources:**
- **unified-log**: macOS unified logging system (default)
- **jamf**: Jamf Protect analytics
- **crowdstrike**: CrowdStrike Falcon (requires API)
- **sentinelone**: SentinelOne (requires API)

**Output:**
JSON file containing collected ES events with metadata and event type breakdown.

**When to use:**
- Threat hunting across historical events
- Testing detection queries against real data
- Building baselines of normal activity
- Collecting evidence for incident response
- Validating EDR visibility

---

### generate-sigma-rule.py

**Interactive Sigma rule generator for macOS detections**

Guides you through creating a properly formatted Sigma rule for macOS detections with ATT&CK mapping, field validation, and best practices.

**Usage:**
```bash
./generate-sigma-rule.py
```

**Interactive Prompts:**
1. **Basic Information**: Title, ID, status, description, author
2. **ATT&CK Mapping**: Tactic and technique selection
3. **Log Source**: ESF, auditd, syslog, osquery
4. **Detection Logic**: Selection criteria and filters
5. **False Positives**: Expected FP scenarios
6. **Severity Level**: low/medium/high/critical

**Example Session:**
```bash
$ ./generate-sigma-rule.py

=== Sigma Rule Generator for macOS ===

Rule title: Unsigned Binary Execution from /tmp
Generate UUID for rule ID? (y/n) [y]: y
✓ Generated ID: 12345678-1234-1234-1234-123456789abc

Rule status:
  1. test
  2. experimental
  3. stable
Select option: 2

Rule description:
Detects execution of unsigned binaries from temporary directories
<empty line>

[... continues interactively ...]

=== Generated Sigma Rule ===

title: Unsigned Binary Execution from /tmp
id: 12345678-1234-1234-1234-123456789abc
status: experimental
[... full rule output ...]

Save to file? (y/n) [y]: y
Filename [unsigned_binary_execution_from_tmp.yml]:
✓ Saved to unsigned_binary_execution_from_tmp.yml
```

**Generated Rule Features:**
- Proper YAML formatting
- ATT&CK tags (tactic + technique)
- macOS-specific logsource definitions
- Detection logic with selection and filters
- False positive documentation
- Severity level assignment

**When to use:**
- Creating new detection rules
- Converting behavioral descriptions to Sigma format
- Standardizing detection rule format
- Documenting detection logic with ATT&CK mapping

---

### convert-detection.py

**Convert detection formats between platforms**

Converts detection queries between different formats (Splunk SPL, Sigma YAML, KQL) with automatic field mapping for macOS-specific fields. Helps port detections across different SIEM/EDR platforms.

**Usage:**
```bash
./convert-detection.py [options] <input_file>
```

**Options:**
```
-i, --input-format     Input format (sigma, splunk, kql, auto)
-o, --output-format    Output format (sigma, splunk, kql, elastic)
-O, --output-file      Save to file instead of stdout
-t, --title            Detection title (for Sigma conversions)
-d, --description      Detection description
-a, --author           Author name
-l, --level            Severity level (low, medium, high, critical)
```

**Supported Conversions:**
- **Splunk SPL → Sigma YAML**: Extract search logic and convert to Sigma format
- **Sigma YAML → Splunk SPL**: Generate SPL queries with proper field mapping
- **Sigma YAML → KQL**: Convert to Microsoft Sentinel/Defender queries
- **Sigma YAML → Elastic**: (Recommend using sigma-cli for full support)

**Examples:**
```bash
# Auto-detect format and convert to Sigma
./convert-detection.py -o sigma detection.spl

# Convert Sigma rule to Splunk SPL
./convert-detection.py -i sigma -o splunk unsigned_exec.yml

# Convert Sigma to KQL for Microsoft Sentinel
./convert-detection.py -i sigma -o kql persistence_rule.yml -O sentinel_rule.kql

# Provide metadata when converting SPL to Sigma
./convert-detection.py -o sigma \
  -t "Malicious Launch Agent" \
  -d "Detects suspicious launch agent creation" \
  -a "Security Team" \
  -l high \
  detection.spl
```

**Field Mapping:**
The script automatically maps macOS-specific fields between platforms:

| Sigma Field | Splunk Field | KQL Field |
|-------------|--------------|-----------|
| Image | process.executable.path | ProcessName |
| CommandLine | process.cmdline | ProcessCommandLine |
| ParentImage | process.parent.name | InitiatingProcessFileName |
| SigningId | process.signing_id | (custom) |
| TeamId | process.team_id | (custom) |
| User | user | AccountName |
| Computer | host | DeviceName |

**Example Conversion:**

Input (Splunk SPL):
```spl
index=macos sourcetype="esf:json" event_type="ES_EVENT_TYPE_NOTIFY_EXEC"
| where isnull('process.signing_id') OR 'process.signing_id'=""
| where match('process.executable.path', "^/tmp/")
```

Output (Sigma YAML):
```yaml
title: Unsigned Binary Execution from /tmp
status: experimental
description: Detects unsigned binaries executing from /tmp
logsource:
    product: macos
    service: esf
detection:
    selection:
        Image|re: '^/tmp/'
        SigningId: ''
    condition: selection
level: medium
```

**Limitations:**
- Complex SPL queries with multiple pipes may need manual review
- Custom field names require manual mapping
- Platform-specific functions may not convert perfectly
- Always validate converted detections against your data schema

**When to use:**
- Porting detections from Splunk to Sigma (for multi-platform use)
- Converting Sigma rules to platform-specific queries
- Migrating between SIEM platforms
- Creating platform-agnostic detection libraries

**Best Practices:**
1. Review converted output for accuracy
2. Test against sample data in target platform
3. Validate field names match your schema
4. Document any manual adjustments needed
5. Keep original detection for reference

---

## Prerequisites

### System Requirements
- macOS 10.15 or later
- Bash 4.0+ (for shell scripts)
- Python 3.6+ (for Python scripts)

### Optional Dependencies
- **jq**: JSON parsing (for event collection scripts)
  ```bash
  brew install jq
  ```

- **sigma-cli**: Sigma rule validation (for generate-sigma-rule.py)
  ```bash
  pip install sigma-cli
  ```

### Permissions
Some scripts require elevated privileges:
- **triage-process.sh**: No special permissions (reads process info)
- **check-code-signature.sh**: No special permissions
- **analyze-launch-agent.sh**: Read access to plist files
- **collect-es-events.sh**: May require sudo for reading certain logs
- **generate-sigma-rule.py**: No special permissions

---

## Common Workflows

### Alert Triage Workflow

1. **Initial triage of suspicious process:**
   ```bash
   ./triage-process.sh 1234
   ```

2. **Deep dive on binary signature:**
   ```bash
   ./check-code-signature.sh /path/to/binary
   ```

3. **If persistence detected, analyze launch agent:**
   ```bash
   ./analyze-launch-agent.sh ~/Library/LaunchAgents/suspicious.plist
   ```

### Detection Development Workflow

1. **Generate Sigma rule interactively:**
   ```bash
   ./generate-sigma-rule.py
   ```

2. **Convert to platform-specific format:**
   ```bash
   # Convert to Splunk SPL
   ./convert-detection.py -i sigma -o splunk my_rule.yml

   # Convert to KQL for Microsoft Sentinel
   ./convert-detection.py -i sigma -o kql my_rule.yml -O sentinel_rule.kql
   ```

3. **Collect test events:**
   ```bash
   ./collect-es-events.sh -t 1h -e EXEC,FORK -o test_events.json
   ```

4. **Validate detection logic against collected events**
   (Use your SIEM or sigma-cli for conversion and testing)

### Threat Hunting Workflow

1. **Collect events for time window:**
   ```bash
   ./collect-es-events.sh -t 24h -o hunt_events.json
   ```

2. **Analyze interesting processes:**
   ```bash
   # Extract unique processes from events
   jq -r '.[] | .process.path' hunt_events.json | sort -u | while read proc; do
       ./triage-process.sh "$proc"
   done
   ```

3. **Check signatures of suspicious binaries:**
   ```bash
   ./check-code-signature.sh /path/from/hunting
   ```

### Detection Migration Workflow

**Scenario:** Migrating detections from Splunk to Sigma (for multi-platform deployment)

1. **Convert existing Splunk detections to Sigma:**
   ```bash
   # Convert with metadata
   ./convert-detection.py -o sigma \
     -t "Suspicious Process Execution" \
     -d "Detects unsigned binaries from /tmp" \
     -a "Security Team" \
     -l high \
     existing_splunk_detection.spl \
     -O sigma_rules/suspicious_exec.yml
   ```

2. **Review and refine the Sigma rule:**
   ```bash
   # Edit the generated rule for accuracy
   vim sigma_rules/suspicious_exec.yml

   # Validate syntax
   sigma check sigma_rules/suspicious_exec.yml
   ```

3. **Convert Sigma to target platforms:**
   ```bash
   # For Microsoft Sentinel deployment
   ./convert-detection.py -i sigma -o kql \
     sigma_rules/suspicious_exec.yml \
     -O kql_rules/suspicious_exec.kql

   # For Elastic deployment (use sigma-cli for best results)
   sigma convert -t es-qs sigma_rules/suspicious_exec.yml
   ```

4. **Test in each platform:**
   - Deploy to test environment
   - Validate field mappings
   - Tune for platform-specific false positives

---

## Tips and Best Practices

### Performance
- **collect-es-events.sh**: Collecting large time ranges may take time. Start with smaller windows.
- **triage-process.sh**: Process info is point-in-time. Run as soon as suspicious activity is detected.

### Security
- Always validate scripts before running with elevated privileges
- Review collected data before sharing (may contain sensitive information)
- Hash and verify binaries before detailed analysis

### Integration
- Scripts output structured data (JSON) that can be ingested into SIEMs
- Combine scripts in pipelines for automated workflows
- Use with cron for periodic baseline collection

### Detection Development
- Test Sigma rules in a test environment before production
- Document expected false positives in the rule
- Map every detection to ATT&CK for coverage tracking
- Validate field names against your actual data schema

---

## Troubleshooting

### "Permission denied" errors
- Some scripts need read access to system directories
- Use `sudo` if accessing protected files: `sudo ./script.sh`

### "jq: command not found"
- Install jq: `brew install jq`

### ES events not appearing in unified log
- macOS doesn't log all ES events to unified log by default
- Consider using an EDR solution (Jamf Protect, CrowdStrike, etc.)
- Use the `--source` flag to specify your EDR

### Python script errors
- Ensure Python 3.6+: `python3 --version`
- Check script has execute permission: `chmod +x script.py`

---

## Contributing

To add new scripts or improve existing ones:

1. Follow the established script structure (header comments, usage, color output)
2. Include comprehensive error handling
3. Provide clear usage examples
4. Update this README with documentation
5. Test on multiple macOS versions

---

## Additional Resources

- [Endpoint Security Framework Documentation](https://developer.apple.com/documentation/endpointsecurity)
- [Sigma Rule Specification](https://github.com/SigmaHQ/sigma-specification)
- [MITRE ATT&CK for macOS](https://attack.mitre.org/matrices/enterprise/macos/)
- [Parent Skill Documentation](../SKILL.md)

---

**Need help?** Refer to the main skill documentation in `../SKILL.md` or individual script `--help` output.
