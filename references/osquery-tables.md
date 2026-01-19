# osquery Tables for macOS Detection

## Overview

osquery exposes macOS system data as SQL tables. This reference covers tables most relevant for detection engineering and threat hunting on macOS.

## Process & Execution Tables

### processes
Lists all running processes with detailed information.

**Key Columns:**
- `pid` - Process ID
- `name` - Process name
- `path` - Full executable path
- `cmdline` - Complete command line
- `cwd` - Current working directory
- `uid`, `gid` - User/group IDs
- `euid`, `egid` - Effective user/group IDs
- `parent` - Parent PID
- `start_time` - Process start timestamp
- `state` - Process state
- `nice` - Process priority

**Detection Use Cases:**
```sql
-- Unsigned processes running
SELECT p.*, s.authority
FROM processes p
LEFT JOIN signature s ON p.path = s.path
WHERE s.authority IS NULL AND p.path NOT LIKE '/System/%';

-- Processes running from suspicious locations
SELECT * FROM processes
WHERE path LIKE '/tmp/%'
   OR path LIKE '/var/tmp/%'
   OR path LIKE '/dev/shm/%'
   OR path LIKE '/Users/%/Downloads/%';

-- Unusual parent-child relationships
SELECT p.name, p.path, p.cmdline, pp.name AS parent_name
FROM processes p
JOIN processes pp ON p.parent = pp.pid
WHERE (pp.name IN ('Word', 'Excel', 'PowerPoint', 'Preview', 'Safari')
       AND p.name IN ('bash', 'zsh', 'sh', 'curl', 'python', 'python3'));
```

### process_open_files
Maps processes to open file handles.

**Key Columns:**
- `pid` - Process ID
- `fd` - File descriptor number
- `path` - Path of open file

**Detection Use Cases:**
```sql
-- Processes with open keychain files
SELECT p.name, p.path, pof.path AS open_file
FROM process_open_files pof
JOIN processes p ON pof.pid = p.pid
WHERE pof.path LIKE '%/Keychains/%';

-- Processes accessing sensitive browser data
SELECT p.name, p.path, pof.path AS open_file
FROM process_open_files pof
JOIN processes p ON pof.pid = p.pid
WHERE pof.path LIKE '%/Cookies.binarycookies'
   OR pof.path LIKE '%/Login Data';
```

### process_envs
Shows environment variables for running processes.

**Key Columns:**
- `pid` - Process ID
- `key` - Environment variable name
- `value` - Environment variable value

**Detection Use Cases:**
```sql
-- DYLD injection via environment variables
SELECT p.name, p.path, pe.key, pe.value
FROM process_envs pe
JOIN processes p ON pe.pid = p.pid
WHERE pe.key LIKE 'DYLD_%';

-- Suspicious LD_PRELOAD usage
SELECT * FROM process_envs
WHERE key IN ('DYLD_INSERT_LIBRARIES', 'DYLD_LIBRARY_PATH', 'DYLD_FRAMEWORK_PATH');
```

### listening_ports
Shows processes listening on network ports.

**Key Columns:**
- `pid` - Process ID
- `port` - Listening port
- `address` - Bind address
- `protocol` - TCP/UDP

**Detection Use Cases:**
```sql
-- Unsigned processes listening on network
SELECT lp.*, p.path, s.authority
FROM listening_ports lp
JOIN processes p ON lp.pid = p.pid
LEFT JOIN signature s ON p.path = s.path
WHERE s.authority IS NULL
  AND lp.port > 1024;

-- High privilege ports by non-system processes
SELECT lp.*, p.path
FROM listening_ports lp
JOIN processes p ON lp.pid = p.pid
WHERE lp.port < 1024
  AND p.path NOT LIKE '/System/%'
  AND p.path NOT LIKE '/usr/sbin/%';
```

## Persistence Tables

### launchd
Lists all launch agents and daemons.

**Key Columns:**
- `path` - Plist file path
- `name` - Service name
- `label` - Service label
- `program` - Executable path
- `program_arguments` - Arguments
- `run_at_load` - Auto-start flag
- `keep_alive` - Restart flag
- `on_demand` - On-demand flag
- `disabled` - Disabled flag
- `username` - Run as user
- `groupname` - Run as group
- `root_directory` - Chroot path
- `stdout_path`, `stderr_path` - Log paths

**Detection Use Cases:**
```sql
-- Unsigned launch items
SELECT l.*, s.authority
FROM launchd l
LEFT JOIN signature s ON l.program = s.path
WHERE s.authority IS NULL
  AND l.program IS NOT NULL;

-- Launch items executing from suspicious paths
SELECT * FROM launchd
WHERE program LIKE '/tmp/%'
   OR program LIKE '/var/tmp/%'
   OR program LIKE '/Users/%/Downloads/%';

-- Launch items with KeepAlive and unusual programs
SELECT * FROM launchd
WHERE keep_alive = 1
  AND program NOT LIKE '/System/%'
  AND program NOT LIKE '/usr/%'
  AND program NOT LIKE '/Applications/%';

-- Recently added launch items
SELECT * FROM launchd
JOIN file f ON launchd.path = f.path
WHERE f.ctime > (strftime('%s', 'now') - 86400); -- Last 24h
```

### startup_items (legacy)
Lists startup items (deprecated persistence method).

**Key Columns:**
- `name` - Item name
- `path` - Item path
- `source` - Source location

### crontab
Lists cron jobs.

**Key Columns:**
- `event` - Cron schedule
- `command` - Command to execute
- `path` - Crontab file path

**Detection Use Cases:**
```sql
-- Unusual cron jobs
SELECT * FROM crontab
WHERE command LIKE '%curl%'
   OR command LIKE '%wget%'
   OR command LIKE '%python%'
   OR command LIKE '%/tmp/%';
```

### authorization_mechanisms
Shows authorization plugins and mechanisms.

**Detection Use Cases:**
```sql
-- Unauthorized authorization mechanisms
SELECT * FROM authorization_mechanisms
WHERE privileged = 1
  AND mechanisms NOT LIKE '%com.apple.%';
```

## Code Signing & Application Tables

### signature
Validates code signatures of files/applications.

**Key Columns:**
- `path` - File path
- `authority` - Signing authority
- `identifier` - Signing identifier
- `team_id` - Team identifier
- `signed` - Is signed (0/1)

**Detection Use Cases:**
```sql
-- Running unsigned processes
SELECT p.name, p.path, s.signed, s.authority
FROM processes p
LEFT JOIN signature s ON p.path = s.path
WHERE (s.signed = 0 OR s.signed IS NULL)
  AND p.path NOT LIKE '/System/%';

-- Processes with unexpected signing authority
SELECT p.name, p.path, s.authority, s.identifier
FROM processes p
JOIN signature s ON p.path = s.path
WHERE p.name = 'SecurityAgent'
  AND s.authority NOT LIKE '%Apple%';
```

### apps
Lists installed applications.

**Key Columns:**
- `name` - App name
- `path` - App bundle path
- `bundle_identifier` - Bundle ID
- `bundle_version` - Version
- `bundle_short_version` - Short version
- `bundle_executable` - Main executable
- `last_opened_time` - Last execution

**Detection Use Cases:**
```sql
-- Recently installed apps
SELECT * FROM apps
WHERE last_opened_time > (strftime('%s', 'now') - 86400);

-- Apps in unusual locations
SELECT * FROM apps
WHERE path NOT LIKE '/Applications/%'
  AND path NOT LIKE '/System/Applications/%'
  AND path NOT LIKE '/System/Library/%';
```

### kernel_extensions
Lists loaded kernel extensions.

**Key Columns:**
- `name` - Kext name
- `path` - Kext bundle path
- `version` - Kext version
- `linked_against` - Dependencies
- `integrity` - Integrity status

**Detection Use Cases:**
```sql
-- Third-party kernel extensions
SELECT * FROM kernel_extensions
WHERE path NOT LIKE '/System/%'
  AND path NOT LIKE '/Library/Apple/%';
```

### system_extensions
Lists system extensions (modern replacement for kexts).

**Key Columns:**
- `path` - Extension path
- `UUID` - Extension UUID
- `state` - Activation state
- `identifier` - Bundle identifier
- `version` - Version
- `category` - Extension category
- `team` - Team identifier

## User & Account Tables

### users
Lists user accounts.

**Key Columns:**
- `uid` - User ID
- `gid` - Primary group ID
- `username` - Username
- `description` - Full name
- `directory` - Home directory
- `shell` - Login shell
- `uuid` - User UUID

**Detection Use Cases:**
```sql
-- Recently created users
SELECT u.*
FROM users u
JOIN file f ON f.path = '/var/db/dslocal/nodes/Default/users/' || u.username || '.plist'
WHERE f.ctime > (strftime('%s', 'now') - 86400);

-- Users with UID 0 (root equivalent)
SELECT * FROM users WHERE uid = 0 AND username != 'root';

-- Users with unusual shells
SELECT * FROM users
WHERE shell NOT IN ('/bin/bash', '/bin/zsh', '/bin/sh', '/usr/bin/false', '/sbin/nologin');
```

### groups
Lists groups and membership.

**Key Columns:**
- `gid` - Group ID
- `groupname` - Group name

### user_groups
Maps users to groups.

**Detection Use Cases:**
```sql
-- Admin group membership changes
SELECT u.username, ug.gid
FROM user_groups ug
JOIN users u ON ug.uid = u.uid
WHERE ug.gid = 80; -- admin group
```

### last
Shows login history.

**Key Columns:**
- `username` - Username
- `tty` - Terminal
- `pid` - Session PID
- `type` - Login type
- `time` - Login time
- `host` - Remote host

**Detection Use Cases:**
```sql
-- SSH logins from unusual IPs
SELECT * FROM last
WHERE type = 7 -- USER_PROCESS
  AND host NOT LIKE '192.168.%'
  AND host NOT LIKE '10.%'
  AND host != 'localhost';

-- Failed login attempts
SELECT * FROM last
WHERE type = 6; -- DEAD_PROCESS with status indicating failure
```

### logged_in_users
Shows currently logged in users.

**Detection Use Cases:**
```sql
-- Multiple concurrent sessions for same user
SELECT username, COUNT(*) as session_count
FROM logged_in_users
GROUP BY username
HAVING COUNT(*) > 2;
```

### sudo_audit
Tracks sudo usage (if logging enabled).

**Detection Use Cases:**
```sql
-- Unusual sudo usage
SELECT * FROM sudo_audit
WHERE command NOT IN (known_good_commands);
```

## File System Tables

### file
Retrieves file metadata.

**Key Columns:**
- `path` - File path
- `directory` - Parent directory
- `filename` - File name
- `size` - File size
- `uid`, `gid` - Owner IDs
- `mode` - Permissions
- `atime`, `mtime`, `ctime`, `btime` - Timestamps
- `hard_links` - Hard link count
- `type` - File type

**Detection Use Cases:**
```sql
-- Recently modified system files
SELECT * FROM file
WHERE path LIKE '/System/%'
  AND mtime > (strftime('%s', 'now') - 3600);

-- SUID/SGID binaries in unusual locations
SELECT * FROM file
WHERE (mode LIKE '4%' OR mode LIKE '2%')
  AND path NOT LIKE '/bin/%'
  AND path NOT LIKE '/sbin/%'
  AND path NOT LIKE '/usr/%'
  AND path NOT LIKE '/System/%';

-- World-writable files
SELECT * FROM file
WHERE directory = '/Library/LaunchDaemons'
  AND mode LIKE '%2' OR mode LIKE '%6';
```

### extended_attributes
Lists extended attributes (xattrs) on files.

**Key Columns:**
- `path` - File path
- `key` - xattr key
- `value` - xattr value (hex)

**Detection Use Cases:**
```sql
-- Files with quarantine attribute removed
SELECT f.path, f.ctime
FROM file f
WHERE f.path LIKE '/Users/%/Downloads/%'
  AND NOT EXISTS (
    SELECT 1 FROM extended_attributes ea
    WHERE ea.path = f.path
      AND ea.key = 'com.apple.quarantine'
  );

-- Check for quarantine attribute on downloads
SELECT path, value FROM extended_attributes
WHERE key = 'com.apple.quarantine'
  AND path LIKE '/Users/%/Downloads/%';
```

### hash
Computes file hashes.

**Key Columns:**
- `path` - File path
- `md5`, `sha1`, `sha256` - Hash values

**Detection Use Cases:**
```sql
-- Hash running executables for threat intel matching
SELECT p.path, h.sha256
FROM processes p
JOIN hash h ON p.path = h.path;
```

## Network Tables

### interface_addresses
Lists network interface IP addresses.

### routes
Shows routing table.

### arp_cache
Shows ARP cache entries.

**Detection Use Cases:**
```sql
-- Unusual ARP entries (spoofing detection)
SELECT * FROM arp_cache
WHERE permanent = 0;
```

### dns_cache (if available via extension)
Shows DNS cache entries.

## macOS-Specific Tables

### keychain_items
Lists items in keychains.

**Key Columns:**
- `label` - Item label
- `account` - Account name
- `service` - Service name
- `comment` - Comment
- `path` - Keychain path
- `type` - Item type
- `created` - Creation time
- `modified` - Modification time

**Detection Use Cases:**
```sql
-- Recently added keychain items
SELECT * FROM keychain_items
WHERE created > (strftime('%s', 'now') - 86400);

-- Unusual keychain access patterns (requires process correlation)
```

### preferences
Reads macOS preference files.

**Key Columns:**
- `domain` - Preference domain
- `key` - Preference key
- `subkey` - Sub-key
- `value` - Preference value
- `forced` - Is managed
- `username` - User

**Detection Use Cases:**
```sql
-- Check Gatekeeper status
SELECT * FROM preferences
WHERE domain = 'com.apple.LaunchServices'
  AND key = 'LSQuarantine';

-- Check SIP status
SELECT * FROM preferences
WHERE domain = 'com.apple.security'
  AND key = 'SIP';
```

### sandboxes
Shows application sandbox profiles.

### iokit_devicetree
Shows IOKit device tree (hardware info).

### smc_keys
Reads System Management Controller keys (hardware sensors).

### unified_log
Queries macOS Unified Logging system.

**Key Columns:**
- `timestamp` - Log timestamp
- `message` - Log message
- `subsystem` - Logging subsystem
- `category` - Log category
- `level` - Log level
- `pid` - Process ID
- `process` - Process name

**Detection Use Cases:**
```sql
-- Authentication failures
SELECT * FROM unified_log
WHERE subsystem = 'com.apple.opendirectoryd'
  AND message LIKE '%authentication failed%'
  AND timestamp > (strftime('%s', 'now') - 3600);

-- TCC prompts/denials
SELECT * FROM unified_log
WHERE subsystem = 'com.apple.TCC'
  AND timestamp > (strftime('%s', 'now') - 3600);
```

### virtual_memory_info
Shows memory statistics.

### mounts
Lists mounted file systems.

**Detection Use Cases:**
```sql
-- Suspicious mounts
SELECT * FROM mounts
WHERE path LIKE '/Volumes/%'
  AND device_alias LIKE '/dev/disk%'
  AND type != 'apfs';

-- Recently mounted volumes
SELECT m.* FROM mounts m
WHERE m.path LIKE '/Volumes/%';
```

## Detection Query Examples

### Comprehensive Process Analysis
```sql
SELECT
  p.pid,
  p.name,
  p.path,
  p.cmdline,
  p.uid,
  p.parent,
  pp.name AS parent_name,
  pp.path AS parent_path,
  s.signed,
  s.authority,
  s.identifier,
  lp.port
FROM processes p
LEFT JOIN processes pp ON p.parent = pp.pid
LEFT JOIN signature s ON p.path = s.path
LEFT JOIN listening_ports lp ON p.pid = lp.pid
WHERE p.path NOT LIKE '/System/%'
  AND p.path NOT LIKE '/usr/sbin/%'
  AND p.path NOT LIKE '/usr/libexec/%';
```

### Persistence Hunting
```sql
SELECT
  'launchd' AS source,
  l.name,
  l.path AS config_path,
  l.program AS executable,
  l.program_arguments AS args,
  s.authority,
  f.ctime
FROM launchd l
LEFT JOIN signature s ON l.program = s.path
LEFT JOIN file f ON l.path = f.path
WHERE l.program IS NOT NULL
  AND (s.authority IS NULL OR s.authority NOT LIKE '%Apple%')

UNION

SELECT
  'cron' AS source,
  'cron_job' AS name,
  c.path AS config_path,
  c.command AS executable,
  '' AS args,
  '' AS authority,
  0 AS ctime
FROM crontab c;
```

### Credential Access Detection
```sql
-- Processes accessing credential stores
SELECT
  p.name,
  p.path,
  pof.path AS accessed_file,
  s.authority
FROM process_open_files pof
JOIN processes p ON pof.pid = p.pid
LEFT JOIN signature s ON p.path = s.path
WHERE (pof.path LIKE '%/Keychains/%'
       OR pof.path LIKE '%/Cookies%'
       OR pof.path LIKE '%/Login Data%')
  AND p.name NOT IN ('SecurityAgent', 'loginwindow', 'Safari', 'Chrome', 'Firefox');
```

## Performance Considerations

1. **Index Usage**: osquery builds indexes on commonly queried columns
2. **Avoid SELECT ***: Specify needed columns to reduce overhead
3. **Time Windows**: Use time constraints to limit result sets
4. **JOIN Carefully**: Complex joins can be expensive
5. **Cache Results**: Use queries with appropriate intervals

## Scheduled Query Examples

```json
{
  "schedule": {
    "unsigned_processes_hourly": {
      "query": "SELECT p.* FROM processes p LEFT JOIN signature s ON p.path = s.path WHERE s.signed IS NULL;",
      "interval": 3600
    },
    "new_launchd_items_daily": {
      "query": "SELECT l.*, f.ctime FROM launchd l JOIN file f ON l.path = f.path WHERE f.ctime > (strftime('%s', 'now') - 86400);",
      "interval": 86400
    }
  }
}
```

## References

- osquery Schema: https://osquery.io/schema/
- osquery Deployment Guide: https://osquery.readthedocs.io/
- macOS Security Tables: Query unified_log, sandbox, and TCC-related data
