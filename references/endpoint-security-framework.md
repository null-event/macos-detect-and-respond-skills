# Endpoint Security Framework Reference

## Overview

The Endpoint Security (ES) framework is Apple's modern system for monitoring and controlling system events on macOS. It provides access to security-relevant events at the kernel level and is the primary telemetry source for macOS detection engineering.

## Key Concepts

### Event Types

ES events are categorized into two types:

1. **AUTH Events** - Authorization events that require a response (allow/deny) before the operation proceeds
2. **NOTIFY Events** - Notification events that inform about operations that have already occurred

### Message Versions

ES messages include a version field. Fields are only available if the message version meets minimum requirements. Always check message version before accessing version-specific fields.

## Event Categories

### Process Events

**ES_EVENT_TYPE_NOTIFY_EXEC** (since macOS 10.15)
- Fires when a process executes a new program via exec() or posix_spawn()
- Fields: target process, arguments, environment variables, file descriptors, cwd, script (if applicable)
- Critical for detecting: malicious execution, living-off-the-land techniques, suspicious parent-child relationships
- Cache key: (process executable, target executable)

**ES_EVENT_TYPE_NOTIFY_FORK** (since macOS 10.15)
- Fires when a process creates a child process
- Fields: child process information
- Notify-only (no AUTH equivalent)

**ES_EVENT_TYPE_NOTIFY_EXIT** (since macOS 10.15)
- Fires when a process terminates
- Fields: exit status
- Notify-only

**ES_EVENT_TYPE_NOTIFY_SIGNAL** (since macOS 10.15)
- Fires when one process sends a signal to another
- Fields: signal number, target process
- Does not fire for self-signaling
- Detection use: privilege escalation, process injection attempts

### File System Events

**ES_EVENT_TYPE_NOTIFY_OPEN** (since macOS 10.15)
- Fires when a file is opened
- Fields: fflag (file open flags), file path
- Note: fflag uses kernel FFLAG values (FREAD, FWRITE), not open(2) oflag values

**ES_EVENT_TYPE_NOTIFY_CREATE** (since macOS 10.15)
- Fires when a file system object is created
- Fields: destination (existing_file or new_path with dir/filename/mode), ACL
- Can fire multiple times for a single syscall due to VFS retries

**ES_EVENT_TYPE_NOTIFY_WRITE** (since macOS 10.15)
- Fires when a file is written to
- Fields: target file
- Notify-only
- High volume event - use path muting for performance

**ES_EVENT_TYPE_NOTIFY_RENAME** (since macOS 10.15)
- Fires when a file is renamed/moved
- Fields: source file, destination (existing_file or new_path)
- Can fire multiple times for a single syscall

**ES_EVENT_TYPE_NOTIFY_UNLINK** (since macOS 10.15)
- Fires when a file is deleted
- Fields: target file, parent directory
- Can fire multiple times for a single syscall

**ES_EVENT_TYPE_NOTIFY_CLOSE** (since macOS 10.15)
- Fires when a file descriptor is closed
- Fields: modified flag, target file, was_mapped_writable (v6+)
- Use for detecting file modifications that bypass write monitoring

### Persistence Events

**ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD** (since macOS 13.0)
- Fires when launch items are added (launch agents, daemons, login items)
- Fields: instigator process, app process, item (type, legacy, managed, uid, URLs)
- Critical for persistence detection
- Userspace event (discretionary)

**ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_REMOVE** (since macOS 13.0)
- Fires when launch items are removed
- Fields: instigator process, app process, item

### Authentication & Privilege Events

**ES_EVENT_TYPE_NOTIFY_AUTHENTICATION** (since macOS 13.0)
- Fires for authentication attempts
- Fields: success, type (OD/TouchID/Token/AutoUnlock), type-specific data
- Types:
  - OD: OpenDirectory (username/password)
  - TouchID: biometric authentication
  - Token: CryptoTokenKit (smart cards, YubiKey)
  - Auto Unlock: Apple Watch unlock
- Userspace event (discretionary)

**ES_EVENT_TYPE_NOTIFY_AUTHORIZATION_PETITION** (since macOS 14.0)
- Fires when a process requests authorization rights
- Fields: instigator, petitioner, flags, rights array
- Use to detect privilege escalation attempts

**ES_EVENT_TYPE_NOTIFY_AUTHORIZATION_JUDGEMENT** (since macOS 14.0)
- Fires when authorization petition is judged
- Fields: instigator, petitioner, return_code, results (per-right granted status)

**ES_EVENT_TYPE_NOTIFY_SUDO** (since macOS 14.0)
- Fires for sudo operations
- Fields: success, reject_info (if failed), from_uid/username, to_uid/username, command
- Userspace event (only fires for platform sudo binary)

**ES_EVENT_TYPE_NOTIFY_SU** (since macOS 14.0)
- Fires for su operations
- Fields: success, failure_message, from/to uid/username, shell, argv, env
- Userspace event (only fires for platform su binary)

**ES_EVENT_TYPE_NOTIFY_SETUID/SETGID/SETEUID/SETEGID/SETREUID/SETREGID** (since macOS 12.0)
- Fire when process changes user/group IDs
- Kernel events (mandatory) - more reliable than su/sudo events

### Code Signing & Integrity Events

**ES_EVENT_TYPE_NOTIFY_CS_INVALIDATED** (since macOS 11.0)
- Fires when a process's code signature becomes invalid
- Occurs when: invalid page is loaded, or csops(CS_OPS_MARKINVALID) is called
- Does not fire if CS_HARD is set (process is killed instead)
- Critical for detecting code injection, dylib hijacking

### Task Port Events

**ES_EVENT_TYPE_NOTIFY_GET_TASK** (since macOS 10.15)
- Fires when process obtains task control port of another process
- Fields: target process, type (task_for_pid/expose_task/identity_token)
- Detection use: process injection, debugging, memory access
- Note: Many legitimate uses exist; context matters

**ES_EVENT_TYPE_NOTIFY_GET_TASK_READ** (since macOS 11.3)
- Task read port acquisition
- Less powerful than task control port

**ES_EVENT_TYPE_NOTIFY_GET_TASK_INSPECT** (since macOS 11.3)
- Task inspect port acquisition
- Least powerful task port variant

**ES_EVENT_TYPE_NOTIFY_GET_TASK_NAME** (since macOS 11.0)
- Task name port acquisition

### Memory & Code Injection Events

**ES_EVENT_TYPE_NOTIFY_MMAP** (since macOS 10.15)
- Fires when a file is memory-mapped
- Fields: protection, max_protection, flags, file_pos, source file
- Detection use: dylib loading, code injection preparation

**ES_EVENT_TYPE_NOTIFY_MPROTECT** (since macOS 10.15)
- Fires when memory protection is changed
- Fields: protection flags, address, size
- Detection use: RWX memory regions (code injection indicator)

**ES_EVENT_TYPE_NOTIFY_REMOTE_THREAD_CREATE** (since macOS 11.0)
- Fires when process creates thread in another process
- Fields: target process, thread_state
- Critical for detecting process injection

### XProtect Events

**ES_EVENT_TYPE_NOTIFY_XP_MALWARE_DETECTED** (since macOS 13.0)
- Fires when XProtect detects malware
- Fields: signature_version, malware_identifier, incident_identifier, detected_path
- Userspace event

**ES_EVENT_TYPE_NOTIFY_XP_MALWARE_REMEDIATED** (since macOS 13.0)
- Fires when XProtect remediates malware
- Fields: signature_version, malware_identifier, incident_identifier, action_type, success, result_description

### OpenDirectory Events (since macOS 14.0)

**User/Group Management:**
- ES_EVENT_TYPE_NOTIFY_OD_CREATE_USER/GROUP
- ES_EVENT_TYPE_NOTIFY_OD_DELETE_USER/GROUP
- ES_EVENT_TYPE_NOTIFY_OD_DISABLE_USER
- ES_EVENT_TYPE_NOTIFY_OD_ENABLE_USER
- ES_EVENT_TYPE_NOTIFY_OD_MODIFY_PASSWORD
- ES_EVENT_TYPE_NOTIFY_OD_GROUP_ADD/REMOVE/SET

**Attribute Management:**
- ES_EVENT_TYPE_NOTIFY_OD_ATTRIBUTE_VALUE_ADD/REMOVE
- ES_EVENT_TYPE_NOTIFY_OD_ATTRIBUTE_SET

All OD events are userspace (discretionary) and include:
- instigator process
- error_code (0 = success)
- node_name (e.g., "/Local/Default", "/LDAPv3/<server>")
- db_path (for local node)

### Session Events (since macOS 13.0)

**LoginWindow:**
- ES_EVENT_TYPE_NOTIFY_LW_SESSION_LOGIN/LOGOUT
- ES_EVENT_TYPE_NOTIFY_LW_SESSION_LOCK/UNLOCK
- Fields: username, graphical_session_id

**SSH:**
- ES_EVENT_TYPE_NOTIFY_OPENSSH_LOGIN/LOGOUT
- Fields: username, source_address, uid, result_type

**Screen Sharing:**
- ES_EVENT_TYPE_NOTIFY_SCREENSHARING_ATTACH/DETACH
- Fields: source_address, viewer_appleid, authentication details, graphical_session_id

**login(1):**
- ES_EVENT_TYPE_NOTIFY_LOGIN_LOGIN/LOGOUT

### Profile Events (since macOS 14.0)

**ES_EVENT_TYPE_NOTIFY_PROFILE_ADD/REMOVE**
- Configuration profile installation/removal
- Fields: instigator, profile (identifier, UUID, install_source, organization, display_name, scope)
- Detection use: MDM enrollment, malicious profiles

### Network Events

**ES_EVENT_TYPE_NOTIFY_UIPC_BIND** (since macOS 10.15.1)
- UNIX-domain socket bind
- Fields: directory, filename, mode

**ES_EVENT_TYPE_NOTIFY_UIPC_CONNECT** (since macOS 10.15.1)
- UNIX-domain socket connect
- Fields: socket file, domain, type, protocol

**ES_EVENT_TYPE_NOTIFY_XPC_CONNECT** (since macOS 14.0)
- XPC connection to named service
- Fields: service_name, service_domain_type
- Detection use: malicious XPC abuse, persistence

### Extended Attributes

**ES_EVENT_TYPE_NOTIFY_SETEXTATTR** (since macOS 10.15)
**ES_EVENT_TYPE_NOTIFY_GETEXTATTR** (since macOS 10.15.1)
**ES_EVENT_TYPE_NOTIFY_DELETEEXTATTR** (since macOS 10.15.1)
**ES_EVENT_TYPE_NOTIFY_LISTEXTATTR** (since macOS 10.15.1)
- Extended attribute operations
- Detection use: quarantine attribute removal (com.apple.quarantine)

### Kernel Extensions

**ES_EVENT_TYPE_NOTIFY_KEXTLOAD** (since macOS 10.15)
**ES_EVENT_TYPE_NOTIFY_KEXTUNLOAD** (since macOS 10.15)
- Kernel extension load/unload
- Fields: identifier (signing ID)
- Note: Deprecated in favor of System Extensions

## Important Process Fields

### es_process_t

Key fields available in all process structs:

- **audit_token** - Contains pid, pidversion (incremented on exec), uid, gid, etc.
- **executable** - es_file_t describing the executable
- **signing_id** - Code signing identifier
- **team_id** - Developer team ID
- **cdhash** - Code directory hash
- **codesigning_flags** - From kern/cs_blobs.h (CS_VALID, CS_HARD, CS_KILL, etc.)
- **is_platform_binary** - Apple-signed platform binary
- **is_es_client** - Has Endpoint Security entitlement
- **ppid** - Parent PID (use parent_audit_token instead if available)
- **original_ppid** - Original parent (doesn't change on reparenting)
- **group_id** - Process group ID
- **session_id** - Session ID
- **tty** - Associated TTY (v2+)
- **start_time** - Process start time (v3+)
- **responsible_audit_token** - Responsible process (v4+)
- **parent_audit_token** - Parent process (v4+)

### Code Signing Caveats

- CS_VALID bit means "valid so far" not "fully validated"
- Pages are validated on-demand as they're loaded
- If CS_HARD or CS_KILL is set, invalid pages kill the process
- Platform binaries and hardened runtime binaries have CS_KILL
- Code signature fields reflect state at message generation time
- For EXEC events, signature validated but pages not yet loaded

## Event Filtering & Muting

### Path Muting

Mute events for specific paths to reduce volume:
- ES_MUTE_PATH_TYPE_PREFIX - Mute path prefixes
- ES_MUTE_PATH_TYPE_LITERAL - Mute exact paths
- ES_MUTE_PATH_TYPE_TARGET_PREFIX - Mute target path prefixes
- ES_MUTE_PATH_TYPE_TARGET_LITERAL - Mute target exact paths

### Process Muting

Mute events from specific processes by audit token.

### Mute Inversion

Invert muting to create allowlists (monitor only specific paths/processes).

### Default Mute Set

New ES clients have default muted paths to prevent:
- Deadlocks
- Watchdog timeouts
- System instability

Unmute carefully, especially for AUTH events.

## Detection Engineering Considerations

### High-Volume Events

These events generate significant volume and should be filtered:
- NOTIFY_WRITE
- NOTIFY_LOOKUP
- NOTIFY_STAT
- NOTIFY_ACCESS
- NOTIFY_CLOSE

Use path muting and targeted monitoring.

### Critical Detection Events

Focus on these for security monitoring:
- EXEC (process execution)
- BTM_LAUNCH_ITEM_ADD (persistence)
- AUTHENTICATION (auth attempts)
- SUDO/SU (privilege escalation)
- CS_INVALIDATED (code injection)
- GET_TASK (process access)
- REMOTE_THREAD_CREATE (process injection)
- XP_MALWARE_DETECTED (malware)
- OD_* (user/group management)
- PROFILE_ADD (MDM/config changes)

### Userspace vs Kernel Events

**Kernel Events (Mandatory):**
- Cannot be bypassed
- Always fire if the operation occurs
- Examples: EXEC, SETUID, SIGNAL, file operations

**Userspace Events (Discretionary):**
- Only fire for Apple's platform binaries
- Can be bypassed by custom implementations
- Examples: SUDO, SU, AUTHENTICATION, OD_*, BTM_*

For critical detections, prefer kernel events or combine userspace + kernel (e.g., monitor both SUDO and SETUID).

### Detection Blind Spots

1. **Custom binaries bypass userspace events** - A custom `sudo` won't fire ES_EVENT_TYPE_NOTIFY_SUDO
2. **Self-signaling doesn't fire SIGNAL events**
3. **Screensharing events don't fire for local sessions** (same source/destination)
4. **File descriptor limits** - EXEC events may not include all FDs
5. **Event drops** - Check seq_num and global_seq_num for dropped events

## Performance Considerations

1. **Use muting aggressively** - Reduce unnecessary events
2. **Avoid AUTH events when possible** - NOTIFY is faster
3. **Process out-of-order** - Don't block event handler
4. **Use es_retain_message** - For async processing
5. **Monitor deadlines** - AUTH events have strict deadlines
6. **Watch for drops** - seq_num gaps indicate overwhelmed client

## Common Detection Patterns

### Suspicious Process Execution
```
ES_EVENT_TYPE_NOTIFY_EXEC where:
- Unusual parent-child relationship
- Execution from suspicious paths (/tmp, /var/tmp, /dev/shm)
- Unsigned or ad-hoc signed binaries
- Unexpected arguments (e.g., curl | bash)
```

### Persistence Establishment
```
ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD where:
- Unexpected instigator process
- Launch item pointing to suspicious paths
- Legacy plist modifications
```

### Privilege Escalation
```
ES_EVENT_TYPE_NOTIFY_SUDO where:
- Unusual users running sudo
- Suspicious target commands
- Failed sudo attempts (detect enumeration)

Combined with:
ES_EVENT_TYPE_NOTIFY_SETUID for kernel-level validation
```

### Code Injection
```
ES_EVENT_TYPE_NOTIFY_REMOTE_THREAD_CREATE
ES_EVENT_TYPE_NOTIFY_CS_INVALIDATED
ES_EVENT_TYPE_NOTIFY_GET_TASK where type = task_for_pid
ES_EVENT_TYPE_NOTIFY_MPROTECT where protection = RWX
```

### Credential Access
```
ES_EVENT_TYPE_NOTIFY_OPEN where:
- Target file = login.keychain, login.keychain-db
- Target file = ~/Library/Keychains/*

ES_EVENT_TYPE_NOTIFY_GET_TASK where:
- Target = securityd, opendirectoryd
```

### Defense Evasion
```
ES_EVENT_TYPE_NOTIFY_DELETEEXTATTR where:
- extattr = "com.apple.quarantine"

ES_EVENT_TYPE_NOTIFY_CS_INVALIDATED

ES_EVENT_TYPE_NOTIFY_SETFLAGS where:
- flags remove UF_HIDDEN
```

## Tools for ES Monitoring

- **eslogger** - Built-in ES event logger (ships with macOS)
- **ESF Playground** - Apple sample code for ES experimentation
- **Commercial EDR** - CrowdStrike, SentinelOne, Jamf Protect, etc.

## Version History

- **macOS 10.15** (Catalina) - ES framework introduced
- **macOS 10.15.1** - Extended attribute events, chdir, chroot, utimes, clone, more
- **macOS 10.15.4** - PTY events, proc_check, auth get_task
- **macOS 11.0** (Big Sur) - Task port events, fcntl, cs_invalidated, trace, remote_thread_create
- **macOS 11.3** - get_task_read, get_task_inspect
- **macOS 12.0** (Monterey) - setuid/setgid events, copyfile, path muting improvements
- **macOS 13.0** (Ventura) - Authentication, XProtect, session events, XPC connect, mute inversion
- **macOS 14.0** (Sonoma) - Profile, su, authorization, sudo, OpenDirectory events
- **macOS 15.0** (Sequoia) - gatekeeper_user_override

## References

- EndpointSecurity.framework headers: `/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk/usr/include/EndpointSecurity/`
- WWDC Sessions on Endpoint Security
- TN3127: Inside Code Signing (for codesigning_flags interpretation)
