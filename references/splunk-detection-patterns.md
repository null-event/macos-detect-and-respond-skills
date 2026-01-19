# Splunk Detection Patterns for macOS

## Overview

This guide covers Splunk query patterns and best practices for macOS detection engineering. Focus is on writing efficient, accurate detections using macOS telemetry sources.

## Common Data Sources

### Endpoint Security Framework Logs

**Sourcetype**: Depends on EDR/log forwarder (e.g., `jamf:protect:json`, `crowdstrike:fdr:json`, `sentinelone:json`, `esf:json`)

**Common Fields:**
- `event_type` - ES event type (e.g., "ES_EVENT_TYPE_NOTIFY_EXEC")
- `process.executable.path` - Process executable path
- `process.signing_id` - Code signing identifier
- `process.team_id` - Developer team ID
- `process.is_platform_binary` - Apple platform binary flag
- `target.executable.path` - Target process path (for signal, get_task, etc.)
- `file.path` - File path (for file events)
- `action` - Event action (auth/notify)

### Unified Log (via log show / eslogger)

**Sourcetype**: `macos:unifiedlog`

**Common Fields:**
- `subsystem` - Log subsystem
- `category` - Log category
- `processImagePath` - Process path
- `eventMessage` - Log message
- `timestamp` - Event timestamp

### osquery Logs

**Sourcetype**: `osquery:results` or `osquery:differential`

**Common Fields:**
- `name` - Query name
- `hostIdentifier` - Host identifier
- `calendarTime` - Event time
- `columns.*` - Query result columns
- `action` - added/removed (for differential)

## Field Extraction Patterns

### Endpoint Security Fields

```spl
| rex field=event_type "ES_EVENT_TYPE_(?<event_category>\w+)_(?<event_name>\w+)"
| rex field=process.executable.path "\/(?<process_name>[^\/]+)$"
| rex field=process.executable.path "^(?<process_directory>.*)\/"
```

### Common Extractions

```spl
# Extract parent process from process hierarchy
| rex field=process.parent.executable.path "\/(?<parent_name>[^\/]+)$"

# Extract file extension
| rex field=file.path "\.(?<file_extension>\w+)$"

# Extract user home directory path components
| rex field=file.path "\/Users\/(?<username>[^\/]+)"

# Extract launch agent/daemon name from path
| rex field=file.path "\/Launch(?:Agents|Daemons)\/(?<launchd_label>[^\/]+)\.plist"
```

## Detection Query Patterns

### Process Execution Detections

#### Unsigned Binary Execution
```spl
index=macos sourcetype="esf:json" event_type="ES_EVENT_TYPE_NOTIFY_EXEC"
| where isnull('process.signing_id') OR 'process.signing_id'=""
| where NOT match('process.executable.path', "^/System/")
| where NOT match('process.executable.path', "^/usr/")
| where NOT match('process.executable.path', "^/Applications/")
| stats count by host, process.executable.path, process.cmdline, user
| where count > 0
```

#### Execution from Suspicious Locations
```spl
index=macos sourcetype="esf:json" event_type="ES_EVENT_TYPE_NOTIFY_EXEC"
(process.executable.path="/tmp/*" OR
 process.executable.path="/var/tmp/*" OR
 process.executable.path="/dev/shm/*" OR
 process.executable.path="/Users/*/Downloads/*" OR
 process.executable.path="/Users/Shared/*")
| table _time, host, user, process.name, process.executable.path, process.cmdline
```

#### Unusual Parent-Child Relationships
```spl
index=macos sourcetype="esf:json" event_type="ES_EVENT_TYPE_NOTIFY_EXEC"
process.parent.name IN ("Microsoft Word", "Microsoft Excel", "Microsoft PowerPoint", "Preview", "Safari", "Mail")
process.name IN ("bash", "zsh", "sh", "python", "python3", "curl", "wget", "osascript")
| table _time, host, user, process.parent.name, process.name, process.cmdline
```

#### Scripting Interpreter Execution
```spl
index=macos sourcetype="esf:json" event_type="ES_EVENT_TYPE_NOTIFY_EXEC"
process.name IN ("osascript", "python", "python3", "perl", "ruby", "node", "sh", "bash", "zsh")
| eval suspicious_args=if(match(process.cmdline, "(curl|wget|base64|eval|exec|sh -c|chmod|\/tmp)"), 1, 0)
| where suspicious_args=1
| table _time, host, user, process.name, process.cmdline
```

### Persistence Detections

#### Launch Agent/Daemon Creation
```spl
index=macos sourcetype="esf:json" event_type="ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD"
| eval is_suspicious=if(match(item.item_url, "(\/tmp\/|\/var\/tmp\/|Downloads)"), 1, 0)
| eval is_legacy=if(item.legacy=true, 1, 0)
| where is_suspicious=1 OR is_legacy=1
| table _time, host, user, item.item_type, item.item_url, item.app_url, instigator.executable.path
```

#### Plist File Modifications (Alternative Detection)
```spl
index=macos sourcetype="esf:json"
event_type IN ("ES_EVENT_TYPE_NOTIFY_CREATE", "ES_EVENT_TYPE_NOTIFY_WRITE")
(file.path="/Users/*/Library/LaunchAgents/*" OR
 file.path="/Library/LaunchAgents/*" OR
 file.path="/Library/LaunchDaemons/*")
file.path="*.plist"
| table _time, host, user, process.name, process.executable.path, file.path
```

#### Shell Configuration Modification
```spl
index=macos sourcetype="esf:json" event_type IN ("ES_EVENT_TYPE_NOTIFY_CREATE", "ES_EVENT_TYPE_NOTIFY_WRITE")
file.path IN ("/Users/*/.bash_profile", "/Users/*/.bashrc", "/Users/*/.zshrc", "/Users/*/.zprofile", "/Users/*/.profile")
| table _time, host, user, process.name, file.path
```

### Privilege Escalation Detections

#### Sudo Usage Anomalies
```spl
index=macos sourcetype="esf:json" event_type="ES_EVENT_TYPE_NOTIFY_SUDO"
| eval is_suspicious=if(success=false OR NOT match(from_username, "^(admin|root)"), 1, 0)
| where is_suspicious=1
| stats count, values(command) as commands by host, from_username, to_username
| where count > 5 OR match(commands, "(passwd|dscl|defaults|chmod|chown)")
```

#### SETUID/SETGID Events
```spl
index=macos sourcetype="esf:json"
event_type IN ("ES_EVENT_TYPE_NOTIFY_SETUID", "ES_EVENT_TYPE_NOTIFY_SETGID", "ES_EVENT_TYPE_NOTIFY_SETEUID", "ES_EVENT_TYPE_NOTIFY_SETEGID")
| where uid=0 OR euid=0
| table _time, host, process.name, process.executable.path, process.cmdline, uid, euid
```

#### SUID Binary Creation
```spl
index=macos sourcetype="esf:json" event_type="ES_EVENT_TYPE_NOTIFY_SETMODE"
| eval suid_bit=if(match(mode, "^4"), 1, 0)
| where suid_bit=1
| table _time, host, user, process.name, target.path, mode
```

### Defense Evasion Detections

#### Quarantine Attribute Removal
```spl
index=macos sourcetype="esf:json" event_type="ES_EVENT_TYPE_NOTIFY_DELETEEXTATTR"
extattr="com.apple.quarantine"
| table _time, host, user, process.name, process.executable.path, target.path
```

#### Code Signature Invalidation
```spl
index=macos sourcetype="esf:json" event_type="ES_EVENT_TYPE_NOTIFY_CS_INVALIDATED"
| table _time, host, process.name, process.executable.path, process.signing_id
```

#### Process Injection Indicators
```spl
index=macos sourcetype="esf:json"
event_type IN ("ES_EVENT_TYPE_NOTIFY_REMOTE_THREAD_CREATE", "ES_EVENT_TYPE_NOTIFY_GET_TASK")
| table _time, host, process.name, process.executable.path, target.executable.path
```

#### File Deletion (Log Clearing)
```spl
index=macos sourcetype="esf:json" event_type="ES_EVENT_TYPE_NOTIFY_UNLINK"
file.path IN ("/var/log/*", "/Library/Logs/*", "/Users/*/Library/Logs/*")
| rex field=file.path "\/(?<log_file>[^\/]+)$"
| table _time, host, user, process.name, file.path, log_file
```

### Credential Access Detections

#### Keychain Access
```spl
index=macos sourcetype="esf:json" event_type="ES_EVENT_TYPE_NOTIFY_OPEN"
file.path="*.keychain*"
process.name NOT IN ("SecurityAgent", "loginwindow", "securityd", "secd")
| table _time, host, user, process.name, process.executable.path, file.path
```

#### Security Tool Execution
```spl
index=macos sourcetype="esf:json" event_type="ES_EVENT_TYPE_NOTIFY_EXEC"
process.name="security"
| eval suspicious=if(match(process.cmdline, "(dump-keychain|find-generic-password|find-internet-password)"), 1, 0)
| where suspicious=1
| table _time, host, user, process.cmdline, process.parent.name
```

#### Memory Access to Security Daemons
```spl
index=macos sourcetype="esf:json" event_type="ES_EVENT_TYPE_NOTIFY_GET_TASK"
target.name IN ("securityd", "opendirectoryd", "SecurityAgent")
| table _time, host, process.name, process.executable.path, target.name, get_task_type
```

#### Browser Credential File Access
```spl
index=macos sourcetype="esf:json" event_type="ES_EVENT_TYPE_NOTIFY_OPEN"
(file.path="/Users/*/Library/Application Support/Google/Chrome/*/Login Data" OR
 file.path="/Users/*/Library/Application Support/Firefox/Profiles/*/logins.json" OR
 file.path="/Users/*/Library/Cookies/*")
process.name NOT IN ("Google Chrome", "Firefox", "Safari")
| table _time, host, user, process.name, file.path
```

### Lateral Movement Detections

#### SSH Activity
```spl
index=macos sourcetype="esf:json" event_type="ES_EVENT_TYPE_NOTIFY_OPENSSH_LOGIN"
| eval is_internal=if(match(source_address, "^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)"), 1, 0)
| eval is_suspicious=if(success=true AND is_internal=0, 1, 0)
| where is_suspicious=1
| stats count by host, username, source_address, result_type
| where count > 0
```

#### Screen Sharing Connections
```spl
index=macos sourcetype="esf:json" event_type="ES_EVENT_TYPE_NOTIFY_SCREENSHARING_ATTACH"
| table _time, host, authentication_type, authentication_username, source_address, success
```

### Discovery Detections

#### Reconnaissance Commands
```spl
index=macos sourcetype="esf:json" event_type="ES_EVENT_TYPE_NOTIFY_EXEC"
process.name IN ("whoami", "id", "groups", "dscacheutil", "dscl", "sw_vers", "uname", "system_profiler", "networksetup", "ifconfig", "netstat", "lsof", "ps", "top")
| bucket _time span=5m
| stats count, dc(process.name) as unique_commands, values(process.name) as commands by _time, host, user, process.parent.name
| where unique_commands >= 3
```

#### Bulk File Enumeration
```spl
index=macos sourcetype="esf:json" event_type="ES_EVENT_TYPE_NOTIFY_EXEC"
process.name IN ("find", "mdfind", "locate")
| eval is_broad_search=if(match(process.cmdline, "(\/ |\~)"), 1, 0)
| where is_broad_search=1
| table _time, host, user, process.cmdline
```

## Advanced Techniques

### Correlation Searches

#### Process Tree Reconstruction
```spl
index=macos sourcetype="esf:json" event_type="ES_EVENT_TYPE_NOTIFY_EXEC"
| eval ppid='process.parent.audit_token.pid'
| eval pid='process.audit_token.pid'
| fields _time, host, pid, ppid, process.name, process.executable.path, process.cmdline
| rename process.name as name, process.executable.path as path, process.cmdline as cmdline
```

#### Time-Based Anomaly Detection
```spl
index=macos sourcetype="esf:json" event_type="ES_EVENT_TYPE_NOTIFY_EXEC"
earliest=-7d
| bucket _time span=1h
| stats count by _time, process.name, host
| eventstats avg(count) as avg_count, stdev(count) as stdev_count by process.name, host
| eval threshold=avg_count+(stdev_count*3)
| where count > threshold
```

### Statistical Outlier Detection

#### Rare Process Execution
```spl
index=macos sourcetype="esf:json" event_type="ES_EVENT_TYPE_NOTIFY_EXEC"
earliest=-30d
| stats count by host, process.executable.path
| where count < 5
```

#### Beaconing Detection (Network Connections)
```spl
index=macos sourcetype="esf:json" event_type="ES_EVENT_TYPE_NOTIFY_EXEC"
process.name IN ("curl", "wget", "nc", "ncat")
| bucket _time span=1h
| stats count by _time, host, process.name, process.cmdline
| where count > 1
```

## Lookup Tables

### Known Good Binaries
```spl
| inputlookup known_good_macos_binaries.csv
| where NOT [search index=macos event_type="ES_EVENT_TYPE_NOTIFY_EXEC"
   | stats count by process.executable.path
   | rename process.executable.path as path
   | fields path]
```

### Threat Intelligence Enrichment
```spl
index=macos sourcetype="esf:json" event_type="ES_EVENT_TYPE_NOTIFY_EXEC"
| eval sha256='process.executable.sha256'
| lookup threat_intel_hashes.csv sha256 OUTPUT malware_family, threat_score
| where NOT isnull(malware_family)
```

## Performance Optimization

### Best Practices

1. **Use Time Ranges**: Always specify `earliest` and `latest`
2. **Field Filtering**: Use `fields` command early to reduce data volume
3. **Index-time Extraction**: Extract common fields at index time
4. **Summary Indexing**: Create summary indexes for historical baselines
5. **Scheduled Searches**: Use summary indexing for expensive correlations

### Optimized Query Structure
```spl
index=macos sourcetype="esf:json" event_type="ES_EVENT_TYPE_NOTIFY_EXEC"
earliest=-1h
| fields _time, host, process.*, user
| search process.name IN ("bash", "zsh", "python")
| where match(process.cmdline, "suspicious_pattern")
| stats count by host, process.name
```

## Alert Configuration

### Example Alert Configuration
```json
{
  "alert_type": "number of events",
  "alert_comparator": "greater than",
  "alert_threshold": "0",
  "cron_schedule": "*/15 * * * *",
  "alert.digest_mode": "true",
  "alert.suppress": "true",
  "alert.suppress.fields": "host,process.executable.path",
  "alert.suppress.period": "1h"
}
```

### Alert Throttling
```spl
... your search ...
| eval alert_key=host."-".process.executable.path
| lookup alert_throttle.csv alert_key OUTPUT last_alert_time
| where isnull(last_alert_time) OR (now() - last_alert_time) > 3600
```

## Common Field Mappings by Data Source

### Jamf Protect
```
event_type -> EventType
process.executable.path -> ProcessPath
process.cmdline -> ProcessCommandLine
file.path -> FilePath
```

### CrowdStrike FDR
```
event_type -> EventType
process.executable.path -> ImageFileName
process.cmdline -> CommandLine
```

### Generic ESF Format
```
event_type -> event.type or event_type
process.executable.path -> process.executable.path
process.cmdline -> process.command_line or process.args
```

## Splunk Add-ons & Apps

- **Splunk Add-on for Unix and Linux** - Basic OS monitoring
- **Jamf Protect Add-on** - Jamf Protect ES events
- **CrowdStrike Add-on** - Falcon endpoint data
- **OSQuery Add-on** - osquery integration
- **Splunk Enterprise Security** - SIEM framework with macOS support

## Data Model Acceleration

Map ES events to Splunk CIM:
```spl
| eval vendor_product="Apple EndpointSecurity"
| eval action=case(
    match(event_type, "EXEC"), "process_created",
    match(event_type, "EXIT"), "process_terminated",
    match(event_type, "OPEN"), "file_accessed"
  )
| eval dest=host
| eval user=user
| eval src_user=user
| eval process='process.executable.path'
| eval process_name='process.name'
| eval parent_process='process.parent.executable.path'
| eval parent_process_name='process.parent.name'
```

## References

- Splunk Docs: https://docs.splunk.com/
- Splunk Security Essentials: Pre-built macOS detections
- Common Information Model: https://docs.splunk.com/Documentation/CIM/
