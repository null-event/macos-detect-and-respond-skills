# macOS Telemetry Sources

## Overview

This document provides a quick reference for macOS logging and telemetry sources available for detection engineering.

## Primary Sources

### 1. Endpoint Security Framework (ES)

**Description:** Kernel-level security event monitoring framework introduced in macOS 10.15 (Catalina).

**Availability:** Requires Full Disk Access permission and ES entitlement

**Collection Methods:**
- EDR agents (CrowdStrike, SentinelOne, Jamf Protect)
- eslogger (built-in command-line tool)
- Custom ES client applications

**Event Categories:**
- Process events (exec, fork, exit, signal)
- File events (create, write, rename, unlink, open, close)
- Authentication events (login, sudo, TCC)
- Network events (UNIX sockets, XPC)
- Code signing events (CS invalidation)
- Task port events (process injection)
- Persistence events (BTM launch items, profiles)
- OpenDirectory events (user/group management)

**Strengths:**
- Most comprehensive security telemetry
- Kernel-level visibility
- Low-level system events
- Real-time monitoring capability

**Limitations:**
- Requires system-level permissions
- Can generate high volume
- Some events are userspace (discretionary)
- Not all events available on all macOS versions

**Example Events:**
```json
{
  "event_type": "ES_EVENT_TYPE_NOTIFY_EXEC",
  "process": {
    "executable": {"path": "/usr/bin/python3"},
    "signing_id": "com.apple.python3",
    "cmdline": "python3 suspicious.py"
  }
}
```

### 2. Unified Logging (log show)

**Description:** Apple's centralized logging system replacing ASL (Apple System Log).

**Availability:** All macOS systems 10.12+

**Collection Methods:**
```bash
# Real-time streaming
log stream --predicate 'subsystem == "com.apple.securityd"'

# Historical queries
log show --last 1h --predicate 'eventMessage CONTAINS "authentication"'

# Export to file
log collect --output /tmp/logs.logarchive
```

**Key Subsystems:**
- `com.apple.securityd` - Security daemon
- `com.apple.opendirectoryd` - Directory services
- `com.apple.TCC` - Transparency, Consent, & Control (privacy)
- `com.apple.sshd` - SSH daemon
- `com.apple.login` - Login process
- `com.apple.lsd` - Launch Services daemon

**Strengths:**
- Built-in, always available
- Rich contextual information
- Subsystem-based filtering
- Process correlation

**Limitations:**
- Verbose, high volume
- Privacy limitations (some logs redacted)
- Query syntax can be complex
- Not all security events logged

**Example Query:**
```bash
log show --predicate 'subsystem == "com.apple.TCC" AND eventMessage CONTAINS "camera"' --last 24h
```

### 3. System Audit (BSM)

**Description:** Basic Security Module (BSM) audit framework for tracking security-relevant events.

**Availability:** macOS 10.5+, must be enabled

**Configuration:**
```bash
# Enable auditing
sudo audit -s

# Check status
sudo audit -t

# Review configuration
cat /etc/security/audit_control
```

**Audit Classes:**
- `lo` - Login/logout
- `ex` - Exec
- `fc` - File create
- `fd` - File delete
- `fw` - File write
- `pc` - Process control
- `nt` - Network

**Log Location:** `/var/audit/`

**Strengths:**
- Kernel-level audit trail
- Tamper-resistant (if configured properly)
- Established standard (BSM)

**Limitations:**
- Must be manually enabled
- Performance overhead
- Complex binary format
- Limited by configured audit classes

**Parsing:**
```bash
# Convert binary to text
praudit /var/audit/20240101012345.crash_recovery
```

### 4. osquery

**Description:** SQL-powered endpoint visibility and monitoring framework.

**Availability:** Open source, must be installed

**Collection Methods:**
- Scheduled queries
- Live queries
- Differential logging

**Key Tables:**
- `processes` - Running processes
- `launchd` - Launch agents/daemons
- `signature` - Code signature verification
- `apps` - Installed applications
- `users`, `groups` - Account information
- `listening_ports` - Network listeners
- `startup_items` - Persistence mechanisms

**Strengths:**
- SQL interface (familiar)
- Cross-platform consistency
- Rich table schema
- Active community

**Limitations:**
- Point-in-time queries (not continuous)
- Polling-based (some delay)
- Performance impact if over-queried
- Requires agent installation

**Example:**
```sql
SELECT p.*, s.authority
FROM processes p
LEFT JOIN signature s ON p.path = s.path
WHERE s.signed = 0;
```

## Secondary Sources

### 5. File System Events (FSEvents)

**Description:** File system change notifications.

**Access:**
- `/private/var/log/.fsevents/` (root only)
- `fs_usage` command for live monitoring
- FSEvents API for programmatic access

**Use Cases:**
- File modification tracking
- Persistence detection (plist changes)
- Data staging detection

### 6. Process Accounting

**Description:** Kernel process accounting (acct).

**Configuration:**
```bash
sudo accton /var/account/acct
```

**Limitations:**
- Must be enabled
- Basic process info only
- Binary format

### 7. Network Traffic

**Sources:**
- `/var/log/system.log` - Some network events
- pfctl logs - Packet Filter firewall
- Third-party: Wireshark, tcpdump

### 8. TCC Database

**Description:** Transparency, Consent, & Control - privacy permission database.

**Location:**
- System: `/Library/Application Support/com.apple.TCC/TCC.db`
- User: `~/Library/Application Support/com.apple.TCC/TCC.db`

**Query:**
```bash
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db "SELECT * FROM access;"
```

**Permissions Tracked:**
- Camera, Microphone
- Location Services
- Contacts, Calendar
- Photos, Full Disk Access

### 9. Install Logs

**Locations:**
- `/var/log/install.log` - Package installations
- `/Library/Receipts/` - Installation receipts
- pkgutil database

**Queries:**
```bash
# List installed packages
pkgutil --pkgs

# Package info
pkgutil --pkg-info <identifier>

# Package files
pkgutil --files <identifier>
```

### 10. Crash Reports

**Locations:**
- User: `~/Library/Logs/DiagnosticReports/`
- System: `/Library/Logs/DiagnosticReports/`

**Use Cases:**
- Exploit detection (unusual crashes)
- Code injection failures
- Application stability

## EDR/XDR Platforms

Commercial security platforms provide enhanced telemetry:

### CrowdStrike Falcon
- Falcon Data Replicator (FDR)
- Real-time ES events
- Process tree correlation
- Threat intelligence integration

### Jamf Protect
- ES framework integration
- Analytic-based detections
- Custom unified log collection
- macOS-native platform

### SentinelOne
- Storyline (process graph)
- Behavioral AI
- Deep Visibility (DVQuery)

### Microsoft Defender for Endpoint
- Advanced hunting (KQL)
- Cross-platform correlation
- Integration with Sentinel

## Telemetry Comparison

| Source | Scope | Real-time | Historical | Overhead | Requires Install |
|--------|-------|-----------|------------|----------|------------------|
| ES Framework | Comprehensive | Yes | No | Medium | EDR/Agent |
| Unified Log | System-wide | Yes | Limited | Low | No |
| System Audit | Configurable | Yes | Yes | Medium | No (built-in) |
| osquery | Point-in-time | No | Via logs | Low-Medium | Yes |
| FSEvents | File system | Yes | Rolling | Low | No (built-in) |

## Detection Coverage Matrix

| ATT&CK Tactic | Primary Source | Secondary Source |
|---------------|----------------|------------------|
| Initial Access | ES (exec, open), Unified Log | Quarantine xattrs |
| Execution | ES (exec) | Process Accounting |
| Persistence | ES (BTM, file events) | FSEvents, launchd |
| Privilege Escalation | ES (sudo, setuid) | Audit, Unified Log |
| Defense Evasion | ES (CS invalidation, xattr delete) | Unified Log (TCC) |
| Credential Access | ES (open, get_task) | TCC, Unified Log |
| Discovery | ES (exec) | osquery |
| Lateral Movement | ES (SSH, screensharing) | Audit, Network logs |
| Collection | ES (file access) | FSEvents |
| C2 | Network monitoring | Listening ports (osquery) |
| Exfiltration | Network monitoring | File access patterns |
| Impact | ES (file delete/modify) | FSEvents, Crash logs |

## Collection Architecture

### Centralized Logging

```
macOS Endpoints
    |
    ├─ ES Framework → EDR Agent → SIEM/Data Lake
    ├─ Unified Log → Log forwarder → SIEM
    ├─ osquery → Fleet server → SIEM
    └─ System Audit → Syslog → SIEM
```

### Recommended Stack

**Minimum:**
- EDR with ES framework support (CrowdStrike, Jamf Protect, etc.)
- Unified log collection for TCC, authentication events
- osquery for scheduled queries

**Enhanced:**
- Full ES event streaming
- Unified log streaming with custom predicates
- osquery with differential logging
- System audit for compliance
- Network flow data

## Performance Considerations

### Volume Estimates

**Endpoint Security:**
- Typical: 1-5 MB/hour per endpoint
- Heavy use: 10-50 MB/hour
- High-security environment: 100+ MB/hour

**Unified Log:**
- System: 100-500 MB/day
- With predicates: 10-50 MB/day

**osquery:**
- Scheduled queries (1h interval): <1 MB/day
- Differential logging: 5-10 MB/day

### Optimization Strategies

1. **ES Framework:**
   - Use path/process muting
   - Subscribe only to needed events
   - Filter at source

2. **Unified Log:**
   - Use specific predicates
   - Target relevant subsystems
   - Limit streaming scope

3. **osquery:**
   - Optimize query intervals
   - Use differential logging
   - Focus on security-relevant tables

## References

- Apple Platform Security Guide: https://support.apple.com/guide/security/
- Endpoint Security Framework: `/usr/include/EndpointSecurity/`
- Unified Logging: `man log`
- osquery Schema: https://osquery.io/schema/
