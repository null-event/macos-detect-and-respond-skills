# macOS Detect and Respond - Gemini Skill

A comprehensive knowledge base for macOS threat detection and response, packaged as a Gemini CLI skill. Provides reference materials, workflows, and expert guidance for writing detections, analyzing telemetry, and triaging alerts on macOS systems.

## Overview

This Gemini skill contains curated reference materials covering macOS security telemetry, adversary techniques, and detection engineering patterns across multiple platforms (Splunk, Sigma, osquery, Elastic, Sentinel, and more). It's designed to help security engineers, detection engineers, and threat hunters understand macOS-specific detection opportunities and build high-quality detections for macOS threats.

## Key Features

- **Comprehensive Endpoint Security Framework reference** - Complete catalog of ES events, fields, and detection patterns
- **MITRE ATT&CK for macOS** - Tactics, techniques, and detection opportunities specific to macOS
- **Multi-platform detection guidance** - Examples and patterns for Splunk, Sigma, osquery, Elastic, Sentinel, and other platforms
- **Triage workflows** - Guidance for analyzing alerts and distinguishing benign from malicious behavior
- **Gemini CLI skill integration** - Interactive assistant for detection writing and analysis

## Installation

### Using with Gemini CLI

This skill is designed to work with [Gemini CLI](https://geminicli.com/).

**Installation:**
```bash
# Clone or copy this directory to your Gemini skills directory
# The skill will be automatically discovered by Gemini

# Verify the skill is loaded
gemini skills list
```

**Example interactions:**
```
> Write a detection for credential dumping on macOS
> What Endpoint Security events show process execution?
> Create a Splunk query to detect unsigned binaries from /tmp
> How do I detect launch agent persistence in Sigma?
> Help me triage this alert for suspicious osascript execution
```

The skill will automatically reference the appropriate materials and guide you through detection development.

## Repository Structure

```
.
├── SKILL.md                    # Gemini skill definition for macOS detection engineering
├── references/                 # Reference documentation (knowledge sources)
│   ├── endpoint-security-framework.md
│   ├── attack-macos.md
│   ├── macos-telemetry-sources.md
│   ├── osquery-tables.md
│   ├── splunk-detection-patterns.md
│   ├── sigma-macos.md
│   └── triage-guidance.md
├── scripts/                    # (Reserved for future scripts)
└── assets/                     # (Reserved for diagrams/images)
```

## Quick Start

### Using the Knowledge Base

Browse the `references/` directory for specific topics:

**Want to understand macOS telemetry?**
- Start with `references/macos-telemetry-sources.md` for an overview
- Dive into `references/endpoint-security-framework.md` for kernel-level events

**Writing detections?**
- Check `references/attack-macos.md` to map adversary behavior to ATT&CK
- Use platform-specific guides:
  - Splunk: `references/splunk-detection-patterns.md`
  - Sigma: `references/sigma-macos.md`
  - osquery: `references/osquery-tables.md`

**Triaging alerts?**
- Consult `references/triage-guidance.md` for workflows and benign indicators

## Common Use Cases

### 1. Writing a Detection

**Scenario:** Detect unsigned binaries executing from /tmp

**Process:**
1. Identify telemetry source: `ES_EVENT_TYPE_NOTIFY_EXEC` (from `endpoint-security-framework.md`)
2. Map to ATT&CK: T1204.002 - User Execution: Malicious File (from `attack-macos.md`)
3. Write platform-specific query (using `splunk-detection-patterns.md` or `sigma-macos.md`)
4. Add false positive filters (exclude known benign processes)

**Example Splunk query:**
```spl
index=macos sourcetype="esf:json" event_type="ES_EVENT_TYPE_NOTIFY_EXEC"
| where isnull('process.signing_id') OR 'process.signing_id'=""
| where match('process.executable.path', "^/tmp/")
| table _time, host, user, process.executable.path, process.cmdline, process.parent.name
```

### 2. Understanding Telemetry

**Scenario:** What macOS logs show file modifications?

**Answer (from reference materials):**
- **Endpoint Security:** `ES_EVENT_TYPE_NOTIFY_WRITE`, `ES_EVENT_TYPE_NOTIFY_CLOSE`
- **File System Events:** FSEvents API for file system change tracking
- **osquery:** `file_events` table (requires FIM configuration)

See `references/macos-telemetry-sources.md` and `references/endpoint-security-framework.md` for details.

### 3. Triaging an Alert

**Scenario:** Alert triggered for new launch agent creation

**Triage steps (from `triage-guidance.md`):**
1. **Who created it?** Check the instigator process and user
2. **What's the target?** Examine the executable path and code signature
3. **Where is it?** User LaunchAgents vs system LaunchDaemons
4. **Benign indicators:** Apple-signed, created by known installer, well-known app
5. **Suspicious indicators:** Unsigned, executable in /tmp, unusual program arguments

## Detection Coverage by Tactic

The reference materials provide detection guidance across MITRE ATT&CK tactics:

| Tactic | Key Detection Opportunities |
|--------|---------------------------|
| **Initial Access** | Quarantine attribute removal, unsigned downloads |
| **Execution** | Process execution from unusual paths, scripting interpreters |
| **Persistence** | Launch agents/daemons, login items, shell profiles |
| **Privilege Escalation** | SETUID/SETGID events, TCC database modifications |
| **Defense Evasion** | Code signature invalidation, process injection, log deletion |
| **Credential Access** | Keychain access, browser credential file access |
| **Discovery** | System profiling commands, network enumeration |
| **Lateral Movement** | SSH/remote login, file sharing abuse |
| **Collection** | Screen capture, audio recording, clipboard access |
| **Exfiltration** | Unusual network connections, cloud sync abuse |

See `references/attack-macos.md` for comprehensive coverage.

## Supported Detection Platforms

This knowledge base provides guidance for multiple platforms:

- **Splunk** - SPL queries for ES events, unified logs, osquery results
- **Elastic Security** - Query DSL and detection rules
- **Microsoft Sentinel** - KQL queries for macOS telemetry
- **Sigma** - Platform-agnostic detection rules
- **osquery** - SQL queries for endpoint data
- **Jamf Protect** - Analytics for Jamf's EDR
- **CrowdStrike Falcon** - Query patterns for CrowdStrike
- **Santa** - Binary/certificate allow/deny rules

## Key Concepts

### Endpoint Security Framework

The macOS Endpoint Security (ES) framework provides kernel-level telemetry for security events. Key points:

- **AUTH vs NOTIFY events:** AUTH events require a response; NOTIFY events are informational
- **Userspace event limitation:** Events like `SUDO`, `BTM_*` only fire for Apple binaries
- **Code signing caveats:** `CS_VALID` doesn't mean "fully validated," just "valid so far"
- **Performance:** High-frequency events (OPEN, CLOSE) may require muting

See `references/endpoint-security-framework.md` for the complete event catalog.

### Detection Best Practices

1. **Start with ATT&CK** - Understand the adversary technique first
2. **Choose appropriate telemetry** - Kernel events for high-fidelity detection
3. **Write precise logic** - Use exact field matches and appropriate regex
4. **Filter false positives** - Exclude system paths, check code signing
5. **Test thoroughly** - Validate against production baselines
6. **Document limitations** - Note expected false positives and version requirements

## Known Limitations

- **Userspace ES events** can be bypassed by non-Apple implementations
- **Event drops** can occur under high load (monitor sequence numbers)
- **Version differences** - Not all events available on all macOS versions
- **Code signing** - Pages validated on-demand; invalid pages may load later

See individual reference files for detailed limitations.

## Use Cases

This skill is designed for:

- **Detection engineers** writing rules for macOS threats
- **Threat hunters** investigating suspicious macOS activity
- **Security analysts** triaging macOS alerts
- **Security architects** designing macOS monitoring solutions
- **Red teams** understanding detection coverage
- **Security researchers** studying macOS security instrumentation

## Additional Resources

- [Apple Endpoint Security Framework Documentation](https://developer.apple.com/documentation/endpointsecurity)
- [MITRE ATT&CK for macOS](https://attack.mitre.org/matrices/enterprise/macos/)
- [osquery Documentation](https://osquery.io/)
- [Sigma Rules Repository](https://github.com/SigmaHQ/sigma)
- [macOS Security and Privacy Guide](https://github.com/drduh/macOS-Security-and-Privacy-Guide)
- [Gemini CLI Documentation](https://geminicli.com/)

## Related Projects

- **Claude Code Skill** - Sister project with the same knowledge base for Claude Code: [macos-detect-and-respond](../macos-detect-and-respond/)

## License

[Specify license here]

---

**Note:** This is a reference skill, not a software project. There are no build processes, test suites, or deployment pipelines. Users interact with this skill through Gemini CLI by asking detection engineering questions.
