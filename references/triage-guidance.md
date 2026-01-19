# macOS Alert Triage Guidance

## Overview

This guide provides structured approaches to triaging common macOS security alerts, helping analysts determine if behavior is malicious, suspicious, or benign.

## General Triage Framework

### 1. Initial Assessment
- **What happened?** - Understand the alert trigger
- **When?** - Timestamp and frequency
- **Who?** - User and process context
- **Where?** - Host, path, network location

### 2. Context Gathering
- Process tree (parent-child relationships)
- Code signing information
- File provenance (downloaded, created locally)
- Recent user activity
- Historical baselines

### 3. Verdict
- **True Positive** - Malicious activity confirmed
- **Suspicious** - Warrants further investigation
- **False Positive** - Benign activity, tune detection
- **Indeterminate** - Insufficient data, escalate

## Alert Type Triage

### Process Execution Alerts

#### Unsigned Binary Execution

**Key Questions:**
- Is the process signed by a known developer?
- Where is the executable located?
- What are the parent-child relationships?
- What is the command line?

**Benign Indicators:**
- Developer tools (go, rustc, g++)
- Locally compiled software in ~/bin or /usr/local
- Known package managers (Homebrew builds)
- Scripts with #!/usr/bin/env shebang

**Suspicious Indicators:**
- Execution from /tmp, /var/tmp
- Execution from ~/Downloads
- Parent: Office apps, browsers, email clients
- Network activity immediately after execution
- Obfuscated or base64-encoded arguments

**Investigation Steps:**
```bash
# Check code signature
codesign -dvvv /path/to/binary

# Check file metadata
ls -l@ /path/to/binary
mdls /path/to/binary

# Check for quarantine xattr
xattr -l /path/to/binary

# Hash for threat intel
shasum -a 256 /path/to/binary
```

**osquery Queries:**
```sql
-- Process details
SELECT * FROM processes WHERE pid = <pid>;

-- File signature
SELECT * FROM signature WHERE path = '/path/to/binary';

-- Extended attributes
SELECT * FROM extended_attributes WHERE path = '/path/to/binary';
```

#### Unusual Parent-Child Relationship

**Common Benign Scenarios:**
- Microsoft Office → bash: Legitimate macros, mail merge scripts
- Safari → python: Web-based development tools
- Preview → osascript: PDF automation workflows

**Suspicious Scenarios:**
- Office → curl | bash: Command injection, malicious macro
- Mail.app → python download: Email-based initial access
- Any app → multiple discovery commands: Reconnaissance

**Triage Checklist:**
- [ ] Review complete command line arguments
- [ ] Check if parent app is commonly scripted in environment
- [ ] Correlate with user activity (did they initiate?)
- [ ] Look for network connections post-execution
- [ ] Check for persistence mechanisms created

### Persistence Alerts

#### Launch Agent/Daemon Creation

**Key Questions:**
- Who created the launch item?
- What is the target executable?
- Is the executable signed?
- Where is the plist/executable located?

**Benign Indicators:**
- Created by installer packages (pkgutil history)
- Apple-signed executables
- Well-known application paths (/Applications/)
- Managed by MDM (check is_managed flag)

**Suspicious Indicators:**
- Executable in /tmp, /var/tmp, user directories
- RunAtLoad + KeepAlive enabled
- Unsigned or ad-hoc signed executable
- Suspicious program arguments (curl, base64, etc.)
- Legacy plist format (not common for modern apps)

**Investigation Steps:**
```bash
# Read plist content
plutil -p /path/to/launch/item.plist

# Check if loaded
launchctl list | grep <label>

# Check executable signature
codesign -dvvv <program_path>

# Review recent package installations
pkgutil --pkgs-since=<date>
```

**Common FPs:**
- Google Chrome updater
- Dropbox, OneDrive sync agents
- Adobe Creative Cloud services
- Homebrew services

#### Shell Profile Modification

**Benign Indicators:**
- User recently modified via text editor (vim, nano)
- Changes from terminal profile preferences
- Package manager PATH updates (Homebrew, MacPorts)

**Suspicious Indicators:**
- Modification by unexpected process (browser, Office)
- Addition of curl/wget commands
- Base64-encoded content
- Export of unusual environment variables (DYLD_*)

**Investigation Steps:**
```bash
# View file content
cat ~/.bash_profile ~/.bashrc ~/.zshrc

# Check file modification time
ls -l ~/.bash_profile

# Review file history (if versioned)
git log ~/.bash_profile
```

### Privilege Escalation Alerts

#### Sudo Usage Anomalies

**Key Questions:**
- What command was executed via sudo?
- Who executed it (expected admin user)?
- Was it successful?
- Any password modification or user account changes?

**Benign Indicators:**
- System administrators performing routine tasks
- Package installations (brew, apt-get)
- Configuration changes during business hours
- Success on first attempt

**Suspicious Indicators:**
- Multiple failed attempts
- Unusual users running sudo
- Commands: dscl, sysadminctl, passwd, visudo
- Execution from unexpected scripts
- After-hours activity

**Triage Workflow:**
1. Identify user and verify they have legitimate admin access
2. Review command - is it appropriate for user's role?
3. Check for recent account changes (created users, password mods)
4. Look for persistence established after sudo
5. Contact user if uncertain

#### SUID Binary Creation

**Key Questions:**
- What process created/modified the SUID binary?
- Where is the binary located?
- What does the binary do?

**Benign Indicators:**
- System update processes
- Package installers (pkg)
- Known system paths (/usr/bin, /usr/sbin)

**Suspicious Indicators:**
- Created in user-writable directories
- Wrapper scripts around system binaries
- Unsigned binaries
- Combined with network activity

**Immediate Actions:**
```bash
# Identify the SUID binary
ls -la <path>

# Check what it is
file <path>
strings <path>

# Verify signature
codesign -dvvv <path>

# Consider removing SUID bit if suspicious
sudo chmod u-s <path>
```

### Defense Evasion Alerts

#### Quarantine Attribute Removal

**Key Questions:**
- What file had quarantine removed?
- What process removed it?
- Was the file recently downloaded?

**Benign Indicators:**
- User explicitly using xattr -d (with understanding)
- Known safe software after manual verification
- Developer tools on dev systems

**Suspicious Indicators:**
- Automated removal by script
- File is executable (.app, .dmg, .pkg)
- Shortly after download
- Combined with execution

**Investigation:**
```bash
# Check if file exists
ls -l <file_path>

# Check current attributes
xattr -l <file_path>

# Check file signature
codesign -dvvv <file_path>

# If executable, check what it does
file <file_path>
otool -L <file_path>  # Check linked libraries
```

**Risk Assessment:**
- Low: Image/document files, known safe apps
- Medium: Scripts, unsigned utilities
- High: Executables, packages, disk images

### Credential Access Alerts

#### Keychain Access

**Key Questions:**
- What process accessed the keychain?
- Is it a known password manager or system service?
- Was it read or write access?

**Benign Indicators:**
- Safari, Chrome, Firefox (own keychains)
- SecurityAgent, securityd (system)
- 1Password, LastPass, Dashlane (password managers)

**Suspicious Indicators:**
- Shells (bash, python) accessing keychains
- Unfamiliar binaries
- Multiple rapid accesses
- Export/dump operations

**Investigation:**
```bash
# Check running processes
ps aux | grep -i security

# Review keychain items (requires auth)
security dump-keychain

# Check access logs (if available)
log show --predicate 'subsystem == "com.apple.securityd"' --last 1h
```

#### Browser Credential File Access

**Expected Processes:**
- Browser itself (Chrome, Firefox, Safari)
- Keychain Access.app
- Password manager apps

**Suspicious Processes:**
- Shells, scripts
- Unknown binaries
- Recently created processes

### Lateral Movement Alerts

#### SSH Activity

**Key Questions:**
- Is the source IP internal or external?
- Is the user expected to SSH from that location?
- Was authentication successful?
- What happened after login?

**Benign Indicators:**
- Internal IP ranges
- Known jump hosts
- Expected administrative users
- Business hours access

**Suspicious Indicators:**
- External IPs (except VPN ranges)
- Failed authentication attempts
- Multiple hosts accessed in sequence
- After-hours access
- Unusual commands post-login

**Investigation:**
```bash
# Check SSH logs
log show --predicate 'process == "sshd"' --last 1h

# Check auth.log
sudo tail -f /var/log/auth.log

# Active SSH sessions
who
w

# Check SSH keys
cat ~/.ssh/authorized_keys
```

## Baseline Knowledge Required

### Expected System Behavior

**Normal LaunchDaemons/Agents:**
- com.apple.* (all Apple services)
- com.google.GoogleUpdater
- com.adobe.*
- com.microsoft.*
- org.homebrew.*

**Normal System Binaries:**
- /System/ - All Apple system files
- /usr/bin/ - Standard UNIX tools
- /usr/sbin/ - System administration tools
- /usr/libexec/ - Internal helper binaries

**Normal Parent-Child Relationships:**
- launchd → most processes
- Terminal.app → shells
- Xcode → compilers, debuggers
- Installer.app → pkg installers

### macOS Version Differences

**Big Sur+ (11.x+):**
- Sealed System Volume (SSV)
- System extensions instead of kexts
- Rosetta 2 on Apple Silicon

**Monterey+ (12.x+):**
- Universal Control features
- Enhanced privacy controls

**Ventura+ (13.x+):**
- Userspace security events (ES framework expanded)
- Endpoint Security maturity

**Sonoma+ (14.x+):**
- Additional ES events for sudo, su, profiles

## Escalation Criteria

### Immediate Escalation (Critical)
- Confirmed malware execution
- Active lateral movement
- Data exfiltration in progress
- Ransomware indicators
- Root compromise

### Escalate for Review (High)
- Multiple related suspicious indicators
- Credential dumping attempts
- Kernel-level modifications
- Unknown processes with network connections

### Monitor/Log (Medium-Low)
- Single anomalous event
- Known software behaving oddly
- Requires user clarification
- Potential false positives

## Documentation Template

```markdown
## Alert: [Alert Name]
**Severity:** [Critical/High/Medium/Low]
**Time:** [Timestamp]
**Host:** [Hostname]
**User:** [Username]

### Summary
[Brief description of what triggered]

### Evidence
- Process: [name, path, cmdline, signing]
- File: [path, hash, attributes]
- Network: [IP, domain, port]

### Analysis
[Findings from investigation]

### Verdict
[TP / FP / Suspicious / Indeterminate]

### Actions Taken
- [ ] Isolated host
- [ ] Collected forensics
- [ ] Notified user
- [ ] Updated detection

### Next Steps
[If escalated or requires follow-up]
```

## Tools Reference

**Built-in macOS:**
- `codesign` - Code signature verification
- `xattr` - Extended attribute management
- `mdls` - File metadata
- `log show` - Unified log queries
- `lsof` - List open files
- `fs_usage` - File system usage tracking
- `dtruss` - System call tracing (requires SIP disable)

**Third-party:**
- eslogger - ES event logging
- osquery - Endpoint telemetry
- KnockKnock - Persistence enumeration
- BlockBlock - Persistence monitoring

## References

- Apple Platform Security Guide
- macOS Security Compliance Project
- Objective-See Tools & Blog
- MITRE ATT&CK for macOS
