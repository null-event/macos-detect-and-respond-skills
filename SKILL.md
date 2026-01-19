---
name: macos-detect-and-respond
description: Assists with macOS security detection engineering including writing detections for Endpoint Security events, translating adversary behaviors to queries (Splunk/osquery/Sigma), analyzing macOS telemetry, mapping to ATT&CK, and triaging alerts.
---

# macOS Detect and Respond

## Purpose

This skill provides specialized knowledge and workflows for macOS detection engineering. It helps translate adversary behaviors into actionable detections, understand macOS telemetry sources, write queries for multiple platforms, and triage security alerts on macOS systems.

## When to Use This Skill

Use this skill when:

- **Writing detections** for macOS threats and adversary behaviors
- **Translating ATT&CK techniques** into Splunk, osquery, or Sigma queries
- **Understanding macOS telemetry** (Endpoint Security framework, unified logs, osquery)
- **Analyzing Endpoint Security events** and their detection opportunities
- **Mapping detections to ATT&CK** for coverage analysis
- **Triaging macOS security alerts** to determine if behavior is malicious or benign
- **Identifying detection gaps** in macOS monitoring
- **Understanding baseline behavior** on macOS systems

**Example queries that trigger this skill:**
- "Write a detection for credential dumping on macOS"
- "What Endpoint Security events show process execution?"
- "Create a Splunk query to detect unsigned binaries from /tmp"
- "How do I detect launch agent persistence in Sigma?"
- "Help me triage this alert for suspicious osascript execution"
- "Map my current macOS detections to ATT&CK"

## Primary Tasks

### 1. Detection Authoring

Translate adversary behaviors into queries, rules, or signatures for various tooling:

**Supported Platforms:**
- **Splunk** - SPL queries for ES events, unified logs, osquery results
- **Elastic** - Query DSL for Elastic Security
- **Microsoft Sentinel** - KQL queries
- **Sigma** - Platform-agnostic detection rules
- **osquery** - SQL queries for endpoint data
- **Jamf Protect** - Analytics for Jamf's EDR
- **CrowdStrike** - Queries for Falcon platform
- **Santa** - Binary/certificate allow/deny rules

**Workflow:**
1. Understand the adversary behavior (ATT&CK technique, TTPs)
2. Identify relevant macOS telemetry sources
3. Map behavior to Endpoint Security events and/or logs
4. Write detection logic in target platform syntax
5. Include appropriate filters to reduce false positives
6. Test and validate detection

### 2. Telemetry Comprehension

Understand what macOS actually logs and how to access it:

**Primary Sources:**
- **Endpoint Security Framework** - Kernel-level security events (ES_EVENT_TYPE_*)
- **Unified Logging** - System-wide logging (log show predicates)
- **osquery** - SQL-queryable endpoint data
- **System Audit (BSM)** - Audit trail for compliance
- **File System Events** - File system change tracking
- **TCC Database** - Privacy permissions

**For each source, understand:**
- What events are available
- How to access/query the data
- Which fields are present
- Detection opportunities
- Limitations and blind spots

### 3. Coverage Analysis

Map current detections against ATT&CK for macOS:

**Process:**
1. Inventory existing detections
2. Map each detection to ATT&CK technique(s)
3. Identify coverage gaps
4. Prioritize new detection development
5. Focus on critical techniques (persistence, credential access, privilege escalation)

**Use the ATT&CK reference** (`references/attack-macos.md`) to:
- Understand macOS-specific techniques
- Identify detection opportunities per technique
- Learn common adversary behaviors

### 4. Triage Assistance

Determine if observed behavior is expected on macOS:

**Triage Framework:**
1. **Understand the alert** - What triggered it?
2. **Gather context** - Process tree, code signing, file provenance
3. **Assess indicators** - Benign vs suspicious vs malicious
4. **Determine verdict** - True positive, false positive, or escalate
5. **Document findings** - Record analysis and actions

**Common Alert Types:**
- Unsigned binary execution
- Unusual parent-child relationships
- Launch agent/daemon creation
- Privilege escalation (sudo, SUID)
- Quarantine attribute removal
- Keychain access
- Process injection indicators

### 5. Baseline & Anomaly Definition

Understand normal macOS system behavior:

**Key Baselines:**
- Expected system processes and paths
- Normal launch agents/daemons
- Typical parent-child relationships
- Common code signing authorities
- Standard user behaviors

**Anomaly Indicators:**
- Execution from unusual paths (/tmp, ~/Downloads)
- Unsigned or ad-hoc signed binaries
- Suspicious command-line arguments
- Unexpected network connections
- Abnormal file access patterns

## How to Use This Skill

### Detection Writing Workflow

When writing a detection:

1. **Start with the behavior:**
   - "I need to detect [adversary behavior]"
   - Example: "credential dumping from keychains"

2. **Identify telemetry sources:**
   - Consult `references/macos-telemetry-sources.md`
   - Determine which ES events, logs, or osquery tables provide visibility
   - Example: ES_EVENT_TYPE_NOTIFY_OPEN for keychain files

3. **Map to ATT&CK:**
   - Use `references/attack-macos.md`
   - Find relevant technique (e.g., T1555.001 - Keychain)
   - Understand the technique's detection opportunities

4. **Consult platform-specific guidance:**
   - **For Splunk:** Use `references/splunk-detection-patterns.md`
   - **For Sigma:** Use `references/sigma-macos.md`
   - **For osquery:** Use `references/osquery-tables.md`
   - **For ES events:** Use `references/endpoint-security-framework.md`

5. **Write the detection:**
   - Include selection criteria (what to match)
   - Add filters for false positives
   - Tag with ATT&CK techniques
   - Document expected false positives

6. **Test and iterate:**
   - Validate against known malicious samples
   - Baseline against production data
   - Tune for false positive rate

### Example: Writing a Splunk Detection

**User Request:** "Write a Splunk query to detect unsigned binaries executing from /tmp"

**Process:**
1. **Identify telemetry:** ES_EVENT_TYPE_NOTIFY_EXEC events
2. **Review ES framework reference:** Check process fields (signing_id, path)
3. **Consult Splunk patterns:** Find similar examples in `references/splunk-detection-patterns.md`
4. **Map to ATT&CK:** T1204.002 (User Execution: Malicious File)
5. **Write query:**

```spl
index=macos sourcetype="esf:json" event_type="ES_EVENT_TYPE_NOTIFY_EXEC"
| where isnull('process.signing_id') OR 'process.signing_id'=""
| where match('process.executable.path', "^/tmp/")
| table _time, host, user, process.executable.path, process.cmdline, process.parent.name
```

6. **Add context:** Include parent process, user, command line for triage

### Example: Triaging an Alert

**User Request:** "Help me triage this Endpoint Security alert for suspicious launch agent creation"

**Process:**
1. **Consult triage guidance:** `references/triage-guidance.md` → Launch Agent section
2. **Key questions:**
   - Who created it? (Check instigator process)
   - What's the target executable? (Check signing, path)
   - Where is it located? (User vs system LaunchAgents)
   - Is it signed? (Check code signature)

3. **Benign indicators:**
   - Created by installer package
   - Apple-signed executable
   - Well-known app (Google Chrome updater, Dropbox)

4. **Suspicious indicators:**
   - Executable in /tmp or user directories
   - Unsigned or ad-hoc signed
   - RunAtLoad + KeepAlive enabled
   - Unusual program arguments

5. **Provide verdict and next steps**

### Understanding Endpoint Security Events

When a query mentions an ES event type (e.g., "What events show file modification?"):

1. **Consult ES framework reference:** `references/endpoint-security-framework.md`
2. **Find relevant events:** ES_EVENT_TYPE_NOTIFY_WRITE, ES_EVENT_TYPE_NOTIFY_CLOSE (with modified flag)
3. **Review event fields:** Understand available data (target file, process, modification status)
4. **Check detection considerations:** Volume, caching, version availability
5. **Provide detection guidance**

## Reference Materials

All reference materials are located in the `references/` directory:

### Core References (Load as Needed)

**`endpoint-security-framework.md`**
- Comprehensive ES event catalog
- Event types, fields, and structures
- Detection patterns per event type
- Code signing interpretation
- Performance considerations
- **Use when:** Working with ES events, understanding macOS telemetry at kernel level

**`attack-macos.md`**
- MITRE ATT&CK for macOS
- Tactics and techniques specific to macOS
- Detection opportunities per technique
- Telemetry mapping
- **Use when:** Mapping detections to ATT&CK, identifying coverage gaps, understanding adversary TTPs

**`macos-telemetry-sources.md`**
- Overview of all macOS logging sources
- ES framework, unified log, osquery, system audit
- Collection methods and architecture
- Performance considerations
- **Use when:** Determining what telemetry is available, architecting collection

**`osquery-tables.md`**
- macOS-relevant osquery tables
- Table schemas and key columns
- Detection query examples
- Performance best practices
- **Use when:** Writing osquery queries, understanding endpoint visibility

**`splunk-detection-patterns.md`**
- Splunk SPL query patterns for macOS
- Field extractions and mappings
- Detection examples by ATT&CK tactic
- Optimization techniques
- **Use when:** Writing Splunk detections for macOS

**`sigma-macos.md`**
- Sigma rule structure for macOS
- Log source definitions
- Field mappings
- Example rules by tactic
- **Use when:** Writing Sigma rules for macOS detections

**`triage-guidance.md`**
- Alert triage workflows
- Benign vs suspicious indicators
- Investigation procedures
- Baseline knowledge
- **Use when:** Analyzing alerts, determining if behavior is malicious

## Utility Scripts

The `scripts/` directory contains practical tools that automate common detection engineering and triage tasks:

### Alert Triage & Investigation

**`triage-process.sh`** - Comprehensive process investigation
- Gathers code signature, parent chain, open files, network connections
- Provides risk scoring and triage verdict (HIGH/MEDIUM/LOW)
- **Use when:** Investigating suspicious process execution alerts
- Example: `./scripts/triage-process.sh 1234`

**`check-code-signature.sh`** - Binary trust evaluation
- Deep analysis of code signatures, entitlements, notarization
- Trust scoring system and security assessment
- **Use when:** Determining if a binary should be trusted
- Example: `./scripts/check-code-signature.sh /tmp/suspicious_binary`

**`analyze-launch-agent.sh`** - Persistence mechanism analysis
- Parses launch agent/daemon plists and analyzes target executables
- Identifies suspicious indicators (DYLD injection, unusual paths)
- **Use when:** Triaging persistence alerts or baseline validation
- Example: `./scripts/analyze-launch-agent.sh ~/Library/LaunchAgents/suspicious.plist`

### Data Collection & Hunting

**`collect-es-events.sh`** - Endpoint Security event collection
- Collects ES events from unified logs or EDR tools (Jamf, CrowdStrike, etc.)
- Flexible time ranges and event type filtering
- **Use when:** Threat hunting or collecting test data for detections
- Example: `./scripts/collect-es-events.sh -t 2h -e EXEC,FORK -o events.json`

### Detection Development

**`generate-sigma-rule.py`** - Interactive Sigma rule generator
- Step-by-step guidance for creating Sigma rules
- ATT&CK mapping, field validation, macOS-specific logsources
- **Use when:** Writing new detection rules in Sigma format
- Example: `./scripts/generate-sigma-rule.py`

**`convert-detection.py`** - Detection format converter
- Converts between Splunk SPL, Sigma YAML, and KQL
- Handles field mapping for macOS-specific fields
- **Use when:** Porting detections between platforms
- Example: `./scripts/convert-detection.py -o sigma detection.spl`

### Using the Scripts

All scripts are fully documented with `--help` flags and include:
- Color-coded output for readability
- Comprehensive error handling
- Detailed usage examples
- Real-world security analysis

See `scripts/README.md` for complete documentation, workflows, and troubleshooting.

## Detection Development Best Practices

### 1. Start with ATT&CK
- Identify the technique being detected
- Understand the adversary's goal and method
- Map to macOS-specific implementation

### 2. Choose Appropriate Telemetry
- **Kernel events (ES)** for high-fidelity detection
- **Userspace events** for enrichment (note: discretionary)
- **osquery** for point-in-time queries
- **Unified log** for system context

### 3. Write Precise Logic
- Be specific in selection criteria
- Use appropriate field matches (exact, regex, contains)
- Consider macOS version differences
- Account for legitimate use cases

### 4. Filter False Positives
- Exclude known benign processes
- Filter system paths (/System/, /usr/)
- Consider code signing authority
- Use allowlists for expected behavior

### 5. Test Thoroughly
- Validate against known malicious samples
- Baseline against production environment
- Monitor alert volume and quality
- Iterate based on analyst feedback

### 6. Document Thoroughly
- Describe what the detection looks for
- List expected false positives
- Include ATT&CK mapping
- Note any limitations

## Common Detection Patterns

### Process Execution
```
Suspicious indicators:
- Unsigned or ad-hoc signed
- Execution from /tmp, /var/tmp, ~/Downloads
- Unusual parent-child relationship
- Suspicious command-line arguments (curl | bash, base64, etc.)
- Network activity immediately after execution
```

### Persistence
```
Key indicators:
- Launch agent/daemon creation (BTM events)
- Plist modifications in LaunchAgents/LaunchDaemons
- Shell profile modifications (.bashrc, .zshrc)
- Login items additions
- Unusual RunAtLoad + KeepAlive combinations
```

### Privilege Escalation
```
Monitor:
- SUDO/SU events (userspace)
- SETUID/SETGID events (kernel - more reliable)
- SUID binary creation
- TCC database modifications
- Authorization Service abuse
```

### Defense Evasion
```
Critical detections:
- Quarantine attribute removal (com.apple.quarantine)
- Code signature invalidation (CS_INVALIDATED)
- Process injection (REMOTE_THREAD_CREATE, GET_TASK)
- File deletion (UNLINK for logs, security files)
```

### Credential Access
```
High-value detections:
- Keychain file access (.keychain, .keychain-db)
- Browser credential file access (Login Data, Cookies)
- Memory access to security daemons (GET_TASK on securityd)
- Security command execution (dump-keychain)
```

## Limitations and Blind Spots

### Userspace Events
- ES events from userspace (SUDO, SU, AUTHENTICATION, OD_*, BTM_*) only fire for Apple's platform binaries
- Custom implementations bypass these events
- Mitigation: Also monitor kernel events (SETUID, file operations)

### Event Drops
- High event volume can cause drops (check seq_num, global_seq_num)
- Use path/process muting to reduce volume
- Monitor for gaps in sequence numbers

### Version Differences
- Not all ES events available on all macOS versions
- Check message version field before accessing version-specific fields
- Document minimum macOS version for detection

### Code Signing Caveats
- CS_VALID doesn't mean "fully validated" - only "valid so far"
- Pages validated on-demand as loaded
- Invalid pages may be loaded later, triggering CS_INVALIDATED

## Workflow Example

**Scenario:** User asks "How do I detect dylib hijacking on macOS?"

**Response Process:**
1. **Understand the technique:**
   - Consult `references/attack-macos.md` → T1574.006
   - Dylib hijacking exploits dynamic library loading

2. **Identify telemetry:**
   - ES_EVENT_TYPE_NOTIFY_EXEC with DYLD environment variables
   - ES_EVENT_TYPE_NOTIFY_MMAP for dylib loading
   - ES_EVENT_TYPE_NOTIFY_CS_INVALIDATED if dylib breaks signature

3. **Provide detection logic:**
   - **For Splunk:** Reference `references/splunk-detection-patterns.md`
   - **For Sigma:** Reference `references/sigma-macos.md`
   - **For ES events:** Reference `references/endpoint-security-framework.md`

4. **Include filters:**
   - Exclude system processes
   - Focus on unusual dylib paths
   - Check code signing of loaded libraries

5. **Provide triage guidance:**
   - What makes this benign vs malicious?
   - How to investigate further?

## Additional Notes

- **Code Signing is Critical:** Always check signing_id, team_id, and is_platform_binary
- **Context Matters:** Parent-child relationships, user context, timing all inform verdict
- **Baseline First:** Know what's normal before detecting anomalies
- **Correlate Events:** Single events are ambiguous; patterns are revealing
- **Performance Counts:** High-volume detections need careful tuning

## Skill Invocation

This skill should be invoked for:
- Any macOS detection engineering task
- Understanding macOS security telemetry
- Writing queries for macOS threat hunting
- Triaging macOS security alerts
- ATT&CK coverage analysis for macOS

It provides expert knowledge on macOS security instrumentation, adversary behaviors, and detection engineering specific to the Apple ecosystem.
