# Sigma Rules for macOS Detection

## Overview

Sigma is a generic signature format for SIEM systems. This guide covers writing Sigma rules for macOS detection engineering, with a focus on macOS-specific logsources and detection patterns.

## Sigma Rule Structure

```yaml
title: <Rule Title>
id: <UUID>
status: <experimental|test|stable>
description: <Description>
references:
    - <Reference URL>
author: <Author Name>
date: <YYYY-MM-DD>
modified: <YYYY-MM-DD>
tags:
    - attack.<tactic>
    - attack.<technique_id>
logsource:
    product: <product>
    service: <service>
    category: <category>
detection:
    selection:
        <field>: <value>
    condition: selection
falsepositives:
    - <Known false positives>
level: <low|medium|high|critical>
```

## macOS Log Sources

### Endpoint Security Framework

```yaml
logsource:
    product: macos
    service: es  # or endpoint_security
```

**Common Event Types:**
- `es_event_type: ES_EVENT_TYPE_NOTIFY_EXEC`
- `es_event_type: ES_EVENT_TYPE_NOTIFY_OPEN`
- `es_event_type: ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD`
- `es_event_type: ES_EVENT_TYPE_NOTIFY_AUTHENTICATION`

### Unified Log

```yaml
logsource:
    product: macos
    service: unified_log
```

**Common Fields:**
- `subsystem`
- `category`
- `message`
- `process`

### Process Creation

```yaml
logsource:
    product: macos
    category: process_creation
```

Maps to ES_EVENT_TYPE_NOTIFY_EXEC events.

### File Events

```yaml
logsource:
    product: macos
    category: file_event
```

Maps to file-related ES events (CREATE, WRITE, RENAME, etc.).

## Field Mappings

### Common Fields

| Sigma Field | macOS ES Field | Description |
|-------------|----------------|-------------|
| `CommandLine` | `process.cmdline` or `process.arguments` | Process command line |
| `Image` | `process.executable.path` | Process executable path |
| `ParentImage` | `process.parent.executable.path` | Parent process path |
| `ParentCommandLine` | `process.parent.cmdline` | Parent command line |
| `User` | `process.uid` or `user` | User context |
| `ProcessId` | `process.audit_token.pid` | Process ID |
| `ParentProcessId` | `process.parent.audit_token.pid` | Parent PID |
| `TargetFilename` | `file.path` or `target.path` | File path |
| `DestinationIp` | `destination_ip` | Network destination |
| `SourceIp` | `source_ip` or `source_address` | Network source |

### macOS-Specific Fields

| Field | ES Field | Description |
|-------|----------|-------------|
| `signing_id` | `process.signing_id` | Code signing ID |
| `team_id` | `process.team_id` | Developer team ID |
| `is_platform_binary` | `process.is_platform_binary` | Apple platform binary |
| `codesigning_flags` | `process.codesigning_flags` | Code signing flags |
| `es_event_type` | `event_type` | ES event type |

## Example Rules

### Process Execution Detection

#### Unsigned Binary Execution
```yaml
title: Unsigned Binary Execution on macOS
id: 1a2b3c4d-5e6f-7a8b-9c0d-1e2f3a4b5c6d
status: experimental
description: Detects execution of unsigned binaries outside system directories
references:
    - https://developer.apple.com/documentation/security/code_signing_services
author: Detection Engineer
date: 2024-01-01
tags:
    - attack.defense_evasion
    - attack.t1553.001
logsource:
    product: macos
    category: process_creation
detection:
    selection:
        signing_id: null
    filter_system:
        Image|startswith:
            - '/System/'
            - '/usr/'
            - '/bin/'
            - '/sbin/'
    condition: selection and not filter_system
falsepositives:
    - Developer tools and scripts
    - Locally compiled binaries
level: medium
```

#### Execution from Temporary Directories
```yaml
title: Process Execution from Temporary Directory on macOS
id: a1b2c3d4-e5f6-7a8b-9c0d-1e2f3a4b5c6d
status: test
description: Detects process execution from temporary directories
author: Detection Engineer
date: 2024-01-01
tags:
    - attack.execution
    - attack.t1204.002
logsource:
    product: macos
    category: process_creation
detection:
    selection:
        Image|startswith:
            - '/tmp/'
            - '/var/tmp/'
            - '/private/tmp/'
            - '/Users/Shared/'
    condition: selection
falsepositives:
    - Software installers
    - Package managers (Homebrew during compilation)
level: high
```

#### Suspicious Parent-Child Relationship
```yaml
title: Suspicious macOS Parent-Child Process Relationship
id: 2b3c4d5e-6f7a-8b9c-0d1e-2f3a4b5c6d7e
status: experimental
description: Detects suspicious process spawning from productivity applications
author: Detection Engineer
date: 2024-01-01
tags:
    - attack.execution
    - attack.t1204.002
logsource:
    product: macos
    category: process_creation
detection:
    selection:
        ParentImage|endswith:
            - '/Microsoft Word'
            - '/Microsoft Excel'
            - '/Microsoft PowerPoint'
            - '/Preview.app/Contents/MacOS/Preview'
            - '/Safari.app/Contents/MacOS/Safari'
        Image|endswith:
            - '/bash'
            - '/zsh'
            - '/sh'
            - '/python'
            - '/python3'
            - '/perl'
            - '/ruby'
            - '/osascript'
            - '/curl'
            - '/wget'
    condition: selection
falsepositives:
    - Legitimate macros and scripts
    - Office plugins and extensions
level: high
```

### Persistence Detection

#### Launch Agent Creation
```yaml
title: macOS Launch Agent Creation
id: 3c4d5e6f-7a8b-9c0d-1e2f-3a4b5c6d7e8f
status: test
description: Detects creation of launch agents for persistence
author: Detection Engineer
date: 2024-01-01
tags:
    - attack.persistence
    - attack.t1543.001
logsource:
    product: macos
    service: es
detection:
    selection:
        es_event_type: ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD
    condition: selection
falsepositives:
    - Legitimate application installations
    - Software updates
level: medium
```

#### Launch Agent Plist Modification
```yaml
title: macOS Launch Agent Plist File Modification
id: 4d5e6f7a-8b9c-0d1e-2f3a-4b5c6d7e8f9a
status: experimental
description: Detects creation or modification of launch agent plist files
author: Detection Engineer
date: 2024-01-01
tags:
    - attack.persistence
    - attack.t1543.001
logsource:
    product: macos
    category: file_event
detection:
    selection:
        TargetFilename|contains:
            - '/Library/LaunchAgents/'
            - '/Library/LaunchDaemons/'
        TargetFilename|endswith: '.plist'
    filter_system:
        Image|startswith:
            - '/System/'
            - '/usr/libexec/'
    condition: selection and not filter_system
falsepositives:
    - System updates
    - Application installations via pkg installers
level: medium
```

#### Shell Profile Modification
```yaml
title: macOS Shell Profile Modification
id: 5e6f7a8b-9c0d-1e2f-3a4b-5c6d7e8f9a0b
status: test
description: Detects modification of shell profile files for persistence
author: Detection Engineer
date: 2024-01-01
tags:
    - attack.persistence
    - attack.t1546.004
logsource:
    product: macos
    category: file_event
detection:
    selection:
        TargetFilename|endswith:
            - '/.bash_profile'
            - '/.bashrc'
            - '/.zshrc'
            - '/.zprofile'
            - '/.profile'
    condition: selection
falsepositives:
    - User customization
    - Legitimate profile updates
level: low
```

### Privilege Escalation Detection

#### Sudo Execution Anomaly
```yaml
title: macOS Sudo Execution Anomaly
id: 6f7a8b9c-0d1e-2f3a-4b5c-6d7e8f9a0b1c
status: experimental
description: Detects unusual sudo command execution
author: Detection Engineer
date: 2024-01-01
tags:
    - attack.privilege_escalation
    - attack.t1548.003
logsource:
    product: macos
    service: es
detection:
    selection:
        es_event_type: ES_EVENT_TYPE_NOTIFY_SUDO
    suspicious_commands:
        command|contains:
            - 'dscl'
            - 'chown'
            - 'chmod'
            - '/etc/sudoers'
            - 'visudo'
    condition: selection and suspicious_commands
falsepositives:
    - System administration tasks
    - Configuration management tools
level: medium
```

#### SUID Binary Creation
```yaml
title: macOS SUID/SGID Binary Creation
id: 7a8b9c0d-1e2f-3a4b-5c6d-7e8f9a0b1c2d
status: test
description: Detects creation of SUID or SGID binaries
author: Detection Engineer
date: 2024-01-01
tags:
    - attack.privilege_escalation
    - attack.t1548.001
logsource:
    product: macos
    service: es
detection:
    selection:
        es_event_type: ES_EVENT_TYPE_NOTIFY_SETMODE
        # Mode starts with 4 (SUID) or 2 (SGID)
    filter_system:
        target.path|startswith:
            - '/System/'
            - '/usr/bin/'
            - '/usr/sbin/'
    condition: selection and not filter_system
falsepositives:
    - System updates
    - Application installations
level: high
```

### Defense Evasion Detection

#### Quarantine Attribute Removal
```yaml
title: macOS Quarantine Attribute Removal
id: 8b9c0d1e-2f3a-4b5c-6d7e-8f9a0b1c2d3e
status: stable
description: Detects removal of quarantine extended attribute from downloaded files
references:
    - https://knight.sc/reverse%20engineering/2019/02/20/gatekeeper-bypass-2019.html
author: Detection Engineer
date: 2024-01-01
tags:
    - attack.defense_evasion
    - attack.t1553.001
logsource:
    product: macos
    service: es
detection:
    selection:
        es_event_type: ES_EVENT_TYPE_NOTIFY_DELETEEXTATTR
        extattr: 'com.apple.quarantine'
    condition: selection
falsepositives:
    - User intentionally bypassing Gatekeeper for known safe files
    - Some legitimate applications removing quarantine
level: high
```

#### Code Signature Invalidation
```yaml
title: macOS Code Signature Invalidation
id: 9c0d1e2f-3a4b-5c6d-7e8f-9a0b1c2d3e4f
status: experimental
description: Detects when a process code signature becomes invalid
author: Detection Engineer
date: 2024-01-01
tags:
    - attack.defense_evasion
    - attack.t1055
logsource:
    product: macos
    service: es
detection:
    selection:
        es_event_type: ES_EVENT_TYPE_NOTIFY_CS_INVALIDATED
    condition: selection
falsepositives:
    - Debugging and development activities
    - Modified system files (unusual)
level: high
```

#### Process Injection Detection
```yaml
title: macOS Process Injection via Remote Thread Creation
id: 0d1e2f3a-4b5c-6d7e-8f9a-0b1c2d3e4f5a
status: test
description: Detects process injection attempts via remote thread creation
author: Detection Engineer
date: 2024-01-01
tags:
    - attack.privilege_escalation
    - attack.defense_evasion
    - attack.t1055
logsource:
    product: macos
    service: es
detection:
    selection:
        es_event_type: ES_EVENT_TYPE_NOTIFY_REMOTE_THREAD_CREATE
    condition: selection
falsepositives:
    - Debuggers (lldb, gdb)
    - Monitoring tools
    - Legitimate inter-process communication
level: high
```

### Credential Access Detection

#### Keychain Access
```yaml
title: macOS Keychain Access by Non-System Process
id: 1e2f3a4b-5c6d-7e8f-9a0b-1c2d3e4f5a6b
status: experimental
description: Detects access to keychain files by non-system processes
author: Detection Engineer
date: 2024-01-01
tags:
    - attack.credential_access
    - attack.t1555.001
logsource:
    product: macos
    service: es
detection:
    selection:
        es_event_type: ES_EVENT_TYPE_NOTIFY_OPEN
        file.path|endswith:
            - '.keychain'
            - '.keychain-db'
    filter_system:
        process.name:
            - 'SecurityAgent'
            - 'securityd'
            - 'secd'
            - 'loginwindow'
    condition: selection and not filter_system
falsepositives:
    - Password managers
    - Browser applications
    - Developer tools
level: medium
```

#### Security Command Execution
```yaml
title: macOS Security Command Usage for Credential Access
id: 2f3a4b5c-6d7e-8f9a-0b1c-2d3e4f5a6b7c
status: test
description: Detects usage of security command for dumping credentials
author: Detection Engineer
date: 2024-01-01
tags:
    - attack.credential_access
    - attack.t1555.001
logsource:
    product: macos
    category: process_creation
detection:
    selection:
        Image|endswith: '/security'
        CommandLine|contains:
            - 'dump-keychain'
            - 'find-generic-password'
            - 'find-internet-password'
            - 'export'
    condition: selection
falsepositives:
    - System administration
    - Security auditing
level: medium
```

### Lateral Movement Detection

#### SSH Connection Monitoring
```yaml
title: macOS SSH Connection from Unexpected Source
id: 3a4b5c6d-7e8f-9a0b-1c2d-3e4f5a6b7c8d
status: experimental
description: Detects SSH connections from non-internal IP addresses
author: Detection Engineer
date: 2024-01-01
tags:
    - attack.lateral_movement
    - attack.t1021.004
logsource:
    product: macos
    service: es
detection:
    selection:
        es_event_type: ES_EVENT_TYPE_NOTIFY_OPENSSH_LOGIN
        success: true
    filter_internal:
        source_address|re: '^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)'
    condition: selection and not filter_internal
falsepositives:
    - Legitimate remote administration
    - VPN connections
level: medium
```

## Detection Engineering Workflow

### 1. Identify Adversary Behavior
- Reference MITRE ATT&CK for macOS
- Analyze real-world malware samples
- Review incident response findings

### 2. Map to Telemetry
- Determine which ES event types cover the behavior
- Identify key fields for detection logic
- Consider alternative detection data sources

### 3. Write Sigma Rule
- Use appropriate logsource
- Define clear selection criteria
- Add comprehensive filters for false positives
- Include MITRE ATT&CK tags

### 4. Test & Validate
- Convert to target SIEM format (Splunk, Elastic, etc.)
- Test against known malicious samples
- Baseline against production data
- Tune for false positive rate

### 5. Deploy & Monitor
- Deploy to production SIEM
- Monitor alert volume and quality
- Iterate based on feedback

## Sigma Converters

### sigmac (deprecated)
```bash
sigmac -t splunk -c macos-endpoint-security sigma_rule.yml
```

### pySigma (modern)
```bash
sigma convert -t splunk -p macos_es sigma_rule.yml
```

### Backend Targets
- `splunk` - Splunk SPL
- `elasticsearch` - Elasticsearch Query DSL
- `qradar` - IBM QRadar
- `sentinel` - Microsoft Sentinel KQL
- `athena` - AWS Athena SQL

## Best Practices

1. **Use Specific Logsources**: Prefer `service: es` over generic `product: macos`
2. **Include ATT&CK Tags**: Always map to MITRE ATT&CK techniques
3. **Document False Positives**: List known FPs in the rule
4. **Test Thoroughly**: Validate against production data before deployment
5. **Version Control**: Track rule changes in git
6. **Peer Review**: Have rules reviewed by other analysts
7. **Regular Updates**: Update rules as macOS and attack techniques evolve

## Common Pitfalls

1. **Over-broad Selection**: Too many false positives
2. **Under-specified Filters**: Missing legitimate system activity
3. **Ignoring Field Types**: String vs regex vs contains operators
4. **Missing Edge Cases**: Not considering all macOS versions
5. **Incorrect Field Mappings**: Using Windows field names for macOS
6. **Neglecting Performance**: Rules that are too expensive to run

## Rule Testing

### Manual Testing
1. Trigger the behavior in a test environment
2. Verify the expected log event is generated
3. Confirm the Sigma rule matches
4. Check for false positives

### Automated Testing
```yaml
# test_cases.yml
- rule: unsigned_binary_execution.yml
  should_match:
    - process.executable.path: /tmp/malicious
      process.signing_id: null
  should_not_match:
    - process.executable.path: /System/Library/CoreServices/Finder.app/Contents/MacOS/Finder
      process.signing_id: com.apple.finder
```

## References

- Sigma GitHub: https://github.com/SigmaHQ/sigma
- Sigma Specification: https://github.com/SigmaHQ/sigma-specification
- pySigma: https://github.com/SigmaHQ/pySigma
- macOS Sigma Rules: https://github.com/SigmaHQ/sigma/tree/master/rules/macos
- MITRE ATT&CK for macOS: https://attack.mitre.org/matrices/enterprise/macos/
