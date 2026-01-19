# MITRE ATT&CK for macOS

## Overview

This reference maps MITRE ATT&CK tactics and techniques specific to macOS environments. Use this to understand adversary behaviors, identify detection gaps, and prioritize detection engineering efforts.

## Tactic Overview

| Tactic | Technique Count | Priority for Detection |
|--------|----------------|------------------------|
| Initial Access | 10 | High |
| Execution | 10 | Critical |
| Persistence | 18 | Critical |
| Privilege Escalation | 11 | High |
| Defense Evasion | 26 | High |
| Credential Access | 15 | Critical |
| Discovery | 26 | Medium |
| Lateral Movement | 7 | High |
| Collection | 14 | Medium |
| Command and Control | 18 | Medium |
| Exfiltration | 8 | Medium |
| Impact | 15 | Medium |

## Initial Access

### T1566 - Phishing
- **Spearphishing Attachment** (.dmg, .pkg, .app files)
- **Spearphishing Link** (credential harvesting, drive-by downloads)
- **Spearphishing via Service** (iMessage, Slack, etc.)

### T1195 - Supply Chain Compromise
- Compromised developer tools (Xcode projects)
- Malicious npm/pip/gem packages
- Trojanized applications

### T1078 - Valid Accounts
- Compromised Apple IDs
- Stolen SSH keys
- Local account compromise

**Detection Opportunities:**
- Monitor email attachments with quarantine attributes
- NOTIFY_PROFILE_ADD for unexpected profiles
- AUTHENTICATION events for unusual login patterns
- OPENSSH_LOGIN from unexpected IPs

## Execution

### T1059 - Command and Scripting Interpreter

**T1059.002 - AppleScript**
- Location: `/usr/bin/osascript`
- Detection: EXEC events for osascript, unusual parent processes

**T1059.004 - Unix Shell**
- Shells: bash, zsh, sh, csh, tcsh
- Detection: Shell execution from unexpected parents (Office apps, browsers)

**T1059.006 - Python**
- Location: `/usr/bin/python3`
- Detection: Python execution with network activity, from /tmp

**T1059.007 - JavaScript**
- Location: `/System/Library/Frameworks/JavaScriptCore.framework`
- JXA (JavaScript for Automation) via osascript
- Detection: osascript with -l JavaScript

### T1569.001 - Launchctl
- Launch agents/daemons management
- Detection: launchctl load/bootout commands via EXEC events

### T1204 - User Execution
- Malicious applications (.app bundles)
- Detection: Execution of unsigned/unnotarized apps, Gatekeeper bypasses

**Detection Opportunities:**
- EXEC events for scripting interpreters
- Command line arguments containing curl, wget, base64
- Execution from user writable directories

## Persistence

### T1543.001 - Launch Agent
**User-level:**
- `~/Library/LaunchAgents/` - Current user
- `/Library/LaunchAgents/` - All users (requires root)

**Detection:**
- BTM_LAUNCH_ITEM_ADD events
- CREATE/WRITE events in LaunchAgents directories
- Unusual plist keys (RunAtLoad, KeepAlive, Sockets)

### T1543.004 - Launch Daemon
**System-level:**
- `/Library/LaunchDaemons/` - Runs as root
- `/System/Library/LaunchDaemons/` - Apple system daemons

**Detection:**
- BTM_LAUNCH_ITEM_ADD with daemon type
- CREATE/WRITE in LaunchDaemons (requires root, high severity)
- launchctl commands via EXEC

### T1547.015 - Login Items
- Added via System Settings or SMLoginItemSetEnabled
- Legacy login items: `~/Library/Preferences/com.apple.loginitems.plist`

**Detection:**
- BTM_LAUNCH_ITEM_ADD with LOGIN_ITEM type
- WRITE to loginitems plist

### T1037 - Boot or Logon Initialization Scripts
- `/etc/rc.common` (deprecated)
- Login/logout hooks

### T1136 - Create Account
- OD_CREATE_USER events
- dscl commands via EXEC
- sysadminctl commands

### T1543.002 - Systemd Service (rare on macOS)

### T1546.004 - Unix Shell Configuration Modification
- `.bash_profile`, `.bashrc`, `.zshrc`, `.zprofile`
- Detection: WRITE/CREATE events for shell rc files

**Detection Opportunities:**
- BTM_LAUNCH_ITEM_ADD (primary)
- File creation in persistence directories
- EXEC of persistence tools (launchctl, dscl, sysadminctl)
- OD_* events for account creation/modification

## Privilege Escalation

### T1548.003 - Sudo and Sudo Caching
- Exploit sudo timestamp_timeout
- Detection: SUDO events, unusual sudo usage patterns

### T1574.006 - Dynamic Linker Hijacking
- DYLD_INSERT_LIBRARIES
- @rpath abuse
- Detection: EXEC with DYLD_* environment variables

### T1548.002 - Bypass User Account Control (Authorization Services)
- AuthorizationExecuteWithPrivileges abuse
- Detection: AUTHORIZATION_PETITION/JUDGEMENT events

### T1548.001 - Setuid and Setgid
- Exploitation of SUID/SGID binaries
- Creation of malicious SUID binaries
- Detection: SETUID/SETGID events, SETMODE/SETOWNER events adding SUID bit

### T1068 - Exploitation for Privilege Escalation
- Kernel exploits
- LPE vulnerabilities
- Detection: Unusual SETUID/EXEC patterns, CS_INVALIDATED

### T1548.004 - Elevated Execution with Prompt (TCC Manipulation)
- TCC.db modification
- Detection: WRITE to TCC databases

**Detection Opportunities:**
- SUDO/SU events (userspace)
- SETUID/SETGID/SETEUID/SETEGID events (kernel - more reliable)
- AUTHORIZATION_* events
- WRITE to TCC databases
- EXEC with DYLD environment variables

## Defense Evasion

### T1553.001 - Gatekeeper Bypass
- quarantine attribute removal
- com.apple.quarantine xattr
- Detection: DELETEEXTATTR where extattr = "com.apple.quarantine"

### T1055 - Process Injection
**T1055.002 - Portable Executable Injection**
**T1055.012 - Process Hollowing**
- Detection: REMOTE_THREAD_CREATE, GET_TASK, CS_INVALIDATED

### T1574.006 - Dynamic Linker Hijacking (also Persistence)
- DYLD_INSERT_LIBRARIES
- DYLD_LIBRARY_PATH
- Detection: EXEC with suspicious DYLD_* env vars

### T1574.004 - Dylib Hijacking
- LC_LOAD_DYLIB hijacking
- Detection: EXEC of binaries loading dylibs from unexpected paths, MMAP events

### T1218 - System Binary Proxy Execution
- Abuse of legitimate macOS binaries
- osascript, automator, etc.

### T1070.004 - File Deletion
- Log deletion, evidence removal
- Detection: UNLINK events for log files, security-relevant files

### T1562.001 - Disable or Modify Tools
- Killing security tools
- Detection: SIGNAL events targeting security processes

### T1036.005 - Match Legitimate Name or Location
- Renaming malware to look like system binaries
- Detection: Process metadata analysis (signing_id, team_id mismatch)

### T1027 - Obfuscated Files or Information
- Encrypted/encoded payloads
- Detection: EXEC with base64, openssl, suspicious arguments

### T1564.001 - Hidden Files and Directories
- Files starting with '.'
- chflags hidden
- Detection: CREATE with hidden names, SETFLAGS with UF_HIDDEN

**Detection Opportunities:**
- DELETEEXTATTR for quarantine removal (critical)
- REMOTE_THREAD_CREATE, GET_TASK (process injection)
- CS_INVALIDATED (code integrity violations)
- SIGNAL targeting security tools
- UNLINK for log files

## Credential Access

### T1555.001 - Keychain
- Accessing user keychains
- `/Users/*/Library/Keychains/`
- `security dump-keychain`
- Detection: OPEN events for .keychain files, EXEC of security command

### T1555.003 - Credentials from Web Browsers
- Browser password stores
- ~/Library/Application Support/Google/Chrome/
- ~/Library/Application Support/Firefox/Profiles/
- Detection: OPEN/READ events for browser credential files

### T1003.001 - LSASS Memory (securityd on macOS)
- Memory dumping of securityd
- Detection: GET_TASK where target = securityd

### T1003.008 - /etc/passwd and /etc/shadow
- Reading user account files
- Detection: OPEN events for /etc/master.passwd

### T1056.001 - Keylogging
- Input monitoring APIs abuse
- Detection: Process loading IOKit input frameworks

### T1552.001 - Credentials In Files
- Searching for passwords in files
- Detection: EXEC of grep/find with password-related patterns

### T1539 - Steal Web Session Cookie
- Cookie theft from browsers
- Detection: OPEN/READ of Cookies files in browser directories

**Detection Opportunities:**
- OPEN events for keychain files
- EXEC of `security` command
- GET_TASK targeting securityd/opendirectoryd
- OPEN events for browser credential stores
- OPEN for /etc/master.passwd

## Discovery

### T1087 - Account Discovery
- dscacheutil -q user
- dscl . list /Users
- Detection: EXEC of dscacheutil, dscl with enumeration

### T1069 - Permission Groups Discovery
- id, groups, dscl
- Detection: EXEC of id, groups, dscl

### T1082 - System Information Discovery
- uname, sw_vers, system_profiler
- Detection: EXEC of system enumeration tools

### T1083 - File and Directory Discovery
- find, mdfind, ls
- Detection: EXEC with broad search patterns

### T1057 - Process Discovery
- ps, top, lsof
- Detection: EXEC of process enumeration tools

### T1049 - System Network Connections Discovery
- netstat, lsof -i, nettop
- Detection: EXEC of network enumeration tools

### T1614 - System Location Discovery
- Language/timezone checks
- defaults read -g AppleLocale

### T1518.001 - Security Software Discovery
- Checking for AV/EDR
- Detection: EXEC probing for security tools

**Detection Opportunities:**
- Multiple discovery commands in sequence
- Discovery from unexpected processes (droppers, downloaders)
- Bulk enumeration patterns

## Lateral Movement

### T1021.004 - SSH
- SSH to other macOS/Unix systems
- Detection: OPENSSH_* events, EXEC of ssh client

### T1021.005 - VNC (Screen Sharing)
- Remote desktop access
- Detection: SCREENSHARING_ATTACH events

### T1534 - Internal Spearphishing
- Using compromised accounts for phishing
- Detection: Analysis of iMessage/email activity

### T1091 - Replication Through Removable Media
- USB-based spread
- Detection: MOUNT events with disposition EXTERNAL

**Detection Opportunities:**
- OPENSSH_LOGIN from internal IPs
- SCREENSHARING_ATTACH without user initiation
- EXEC of ssh to internal hosts
- MOUNT of external devices

## Collection

### T1005 - Data from Local System
- File access and staging
- Detection: OPEN/READ of sensitive documents

### T1113 - Screen Capture
- screencapture command
- Detection: EXEC of screencapture

### T1119 - Automated Collection
- Scripted data gathering
- Detection: Bulk file access patterns

### T1115 - Clipboard Data
- pbpaste command
- Detection: EXEC of pbpaste

### T1123 - Audio Capture
- Microphone access
- Detection: TCC events for microphone

### T1125 - Video Capture
- Camera access
- Detection: TCC events for camera, processes accessing camera

### T1056.001 - Keylogging
- Keystroke capture
- Detection: Input monitoring API usage

**Detection Opportunities:**
- EXEC of screen capture tools
- Bulk file access (many OPEN events)
- TCC events for camera/microphone
- Data staging in unusual locations

## Detection Prioritization Matrix

### Critical (Immediate Alerting)
- Persistence: BTM_LAUNCH_ITEM_ADD, LaunchDaemon creation
- Privilege Escalation: SETUID, unexpected SUDO
- Defense Evasion: Quarantine removal, CS_INVALIDATED
- Credential Access: Keychain access, securityd memory access
- Execution: Shell execution from Office/browsers

### High (Alert with Context)
- Lateral Movement: SSH to internal hosts, screen sharing
- Process Injection: REMOTE_THREAD_CREATE, GET_TASK
- Code Signing: Unsigned binaries executing
- Account Creation: OD_CREATE_USER

### Medium (Log for Hunting)
- Discovery commands (many in sequence = high)
- File access patterns
- Network connections

### Low (Baseline/Audit)
- Individual discovery commands
- Normal application behavior

## Mapping to macOS Telemetry

| ATT&CK Technique | Primary ES Event | Secondary ES Event | osquery Tables |
|------------------|------------------|-------------------|----------------|
| Launch Agent Persistence | BTM_LAUNCH_ITEM_ADD | CREATE in LaunchAgents | launchd |
| Dylib Hijacking | EXEC + MMAP | CS_INVALIDATED | process_open_files |
| Process Injection | REMOTE_THREAD_CREATE | GET_TASK | processes |
| Credential Access | OPEN keychain | GET_TASK (securityd) | keychain_items |
| Sudo Privilege Escalation | SUDO | SETUID | last, sudo_audit |

## References

- MITRE ATT&CK macOS Matrix: https://attack.mitre.org/matrices/enterprise/macos/
- macOS Security Compliance Project: https://github.com/usnistgov/macos_security
