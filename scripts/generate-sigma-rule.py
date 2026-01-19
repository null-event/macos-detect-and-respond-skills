#!/usr/bin/env python3
"""
generate-sigma-rule.py - Interactive Sigma rule generator for macOS detections

Usage: ./generate-sigma-rule.py [options]

Description:
    Guides you through creating a properly formatted Sigma rule for macOS
    detections with ATT&CK mapping, field validation, and best practices.

Output:
    YAML-formatted Sigma rule file
"""

import sys
import os
import re
from datetime import datetime
from typing import Dict, List, Optional

# Color codes for terminal output
class Colors:
    RED = '\033[0;31m'
    GREEN = '\033[0;32m'
    YELLOW = '\033[1;33m'
    BLUE = '\033[0;34m'
    CYAN = '\033[0;36m'
    NC = '\033[0m'  # No Color

# Common macOS-specific Sigma logsources
LOGSOURCES = {
    '1': {
        'product': 'macos',
        'service': 'esf',
        'description': 'Endpoint Security Framework events'
    },
    '2': {
        'product': 'macos',
        'service': 'auditd',
        'description': 'macOS audit daemon (BSM)'
    },
    '3': {
        'product': 'macos',
        'service': 'syslog',
        'description': 'Unified logging system'
    },
    '4': {
        'product': 'macos',
        'service': 'osquery',
        'description': 'osquery event tables'
    }
}

# Common ATT&CK tactics for macOS
TACTICS = {
    '1': 'initial-access',
    '2': 'execution',
    '3': 'persistence',
    '4': 'privilege-escalation',
    '5': 'defense-evasion',
    '6': 'credential-access',
    '7': 'discovery',
    '8': 'lateral-movement',
    '9': 'collection',
    '10': 'exfiltration'
}

# Common field names for macOS ESF events
COMMON_FIELDS = {
    'process': [
        'process.executable.path',
        'process.signing_id',
        'process.team_id',
        'process.cmdline',
        'process.parent.name',
        'process.uid',
        'process.gid'
    ],
    'file': [
        'file.path',
        'file.name',
        'file.extension',
        'file.owner',
        'file.attributes'
    ],
    'network': [
        'network.local.address',
        'network.local.port',
        'network.remote.address',
        'network.remote.port',
        'network.protocol'
    ]
}

def print_header(text: str) -> None:
    """Print a colored header."""
    print(f"\n{Colors.BLUE}=== {text} ==={Colors.NC}\n")

def print_info(text: str) -> None:
    """Print info message."""
    print(f"{Colors.CYAN}{text}{Colors.NC}")

def print_success(text: str) -> None:
    """Print success message."""
    print(f"{Colors.GREEN}✓ {text}{Colors.NC}")

def print_warning(text: str) -> None:
    """Print warning message."""
    print(f"{Colors.YELLOW}⚠ {text}{Colors.NC}")

def print_error(text: str) -> None:
    """Print error message."""
    print(f"{Colors.RED}✗ {text}{Colors.NC}")

def get_input(prompt: str, default: Optional[str] = None) -> str:
    """Get user input with optional default."""
    if default:
        user_input = input(f"{prompt} [{default}]: ").strip()
        return user_input if user_input else default
    return input(f"{prompt}: ").strip()

def get_multiline_input(prompt: str) -> str:
    """Get multiline input from user."""
    print(f"{prompt}")
    print("(Enter empty line to finish)")
    lines = []
    while True:
        line = input()
        if not line:
            break
        lines.append(line)
    return '\n'.join(lines)

def select_from_menu(title: str, options: Dict[str, any], key: str = 'description') -> str:
    """Display menu and get user selection."""
    print(f"\n{title}")
    for num, option in options.items():
        if isinstance(option, dict):
            print(f"  {num}. {option.get(key, option)}")
        else:
            print(f"  {num}. {option}")

    while True:
        choice = get_input("\nSelect option")
        if choice in options:
            return choice
        print_error("Invalid selection. Please try again.")

def validate_attack_technique(technique: str) -> bool:
    """Validate ATT&CK technique ID format."""
    pattern = r'^T\d{4}(\.\d{3})?$'
    return bool(re.match(pattern, technique))

def generate_rule_id() -> str:
    """Generate a unique rule ID."""
    import uuid
    return str(uuid.uuid4())

def generate_sigma_rule() -> Dict:
    """Interactive generator for Sigma rule."""
    rule = {}

    print_header("Sigma Rule Generator for macOS")
    print_info("This tool will guide you through creating a Sigma rule for macOS detections.\n")

    # Title
    print_header("1. Basic Information")
    rule['title'] = get_input("Rule title (short, descriptive)")

    # ID
    use_generated_id = get_input("Generate UUID for rule ID? (y/n)", "y").lower()
    if use_generated_id == 'y':
        rule['id'] = generate_rule_id()
        print_success(f"Generated ID: {rule['id']}")
    else:
        rule['id'] = get_input("Enter custom rule ID")

    # Status
    print("\nRule status:")
    print("  1. test (under development)")
    print("  2. experimental (needs validation)")
    print("  3. stable (tested and validated)")
    status_choice = select_from_menu("", {'1': 'test', '2': 'experimental', '3': 'stable'})
    rule['status'] = {'1': 'test', '2': 'experimental', '3': 'stable'}[status_choice]

    # Description
    rule['description'] = get_multiline_input("\nRule description (explain what this detects)")

    # References
    print("\nReferences (e.g., blog posts, documentation):")
    print("Enter URLs one per line, empty line to finish:")
    references = []
    while True:
        ref = input()
        if not ref:
            break
        references.append(ref)
    if references:
        rule['references'] = references

    # Author
    rule['author'] = get_input("\nAuthor name")

    # Date
    rule['date'] = datetime.now().strftime('%Y/%m/%d')

    # Modified
    rule['modified'] = rule['date']

    # Tags - ATT&CK
    print_header("2. ATT&CK Mapping")
    print("\nSelect primary tactic:")
    tactic_choice = select_from_menu("", TACTICS)
    primary_tactic = TACTICS[tactic_choice]

    # Technique ID
    print("\nEnter ATT&CK technique ID (e.g., T1059.001):")
    while True:
        technique = get_input("Technique ID").upper()
        if validate_attack_technique(technique):
            break
        print_error("Invalid format. Use format: T1234 or T1234.001")

    rule['tags'] = [
        f'attack.{primary_tactic}',
        f'attack.{technique.lower()}'
    ]

    # Additional tags
    add_more = get_input("\nAdd additional tags? (y/n)", "n").lower()
    if add_more == 'y':
        print("Enter tags one per line (empty line to finish):")
        while True:
            tag = input()
            if not tag:
                break
            rule['tags'].append(tag)

    # Logsource
    print_header("3. Log Source")
    logsource_choice = select_from_menu("Select log source", LOGSOURCES)
    rule['logsource'] = {
        'product': LOGSOURCES[logsource_choice]['product'],
        'service': LOGSOURCES[logsource_choice]['service']
    }

    # Detection
    print_header("4. Detection Logic")
    print_info("Now we'll build the detection logic.\n")

    detection = {}

    # Selection
    print("Selection criteria (what to match):")
    print("\nCommon fields for this log source:")

    if logsource_choice == '1':  # ESF
        print("\nProcess fields:")
        for field in COMMON_FIELDS['process']:
            print(f"  - {field}")

    print("\nEnter field-value pairs (field: value)")
    print("Example: process.executable.path: /tmp/malware")
    print("Example: process.signing_id|contains: 'unsigned'")
    print("(Empty line to finish)\n")

    selection = {}
    while True:
        field_value = input()
        if not field_value:
            break

        if ':' in field_value:
            field, value = field_value.split(':', 1)
            field = field.strip()
            value = value.strip()

            # Handle modifiers (e.g., contains, startswith)
            if '|' in field:
                field_name, modifier = field.split('|', 1)
                selection[f"{field_name}|{modifier}"] = value
            else:
                selection[field] = value
        else:
            print_warning("Invalid format. Use 'field: value'")

    detection['selection'] = selection

    # Filters
    add_filter = get_input("\nAdd filter criteria (exclude false positives)? (y/n)", "n").lower()
    if add_filter == 'y':
        print("\nFilter criteria (what to exclude):")
        print("(Empty line to finish)\n")

        filter_dict = {}
        while True:
            field_value = input()
            if not field_value:
                break

            if ':' in field_value:
                field, value = field_value.split(':', 1)
                field = field.strip()
                value = value.strip()
                filter_dict[field] = value

        if filter_dict:
            detection['filter'] = filter_dict

    # Condition
    print("\nDetection condition:")
    if 'filter' in detection:
        default_condition = "selection and not filter"
    else:
        default_condition = "selection"

    rule['detection'] = detection
    rule['detection']['condition'] = get_input("Condition", default_condition)

    # False Positives
    print_header("5. False Positives")
    print("Describe expected false positives (empty line to finish):")
    fps = []
    while True:
        fp = input()
        if not fp:
            break
        fps.append(fp)
    if fps:
        rule['falsepositives'] = fps
    else:
        rule['falsepositives'] = ['Unknown']

    # Level
    print_header("6. Severity Level")
    print("\nSeverity levels:")
    print("  1. low")
    print("  2. medium")
    print("  3. high")
    print("  4. critical")
    level_choice = select_from_menu("", {
        '1': 'low',
        '2': 'medium',
        '3': 'high',
        '4': 'critical'
    })
    rule['level'] = {'1': 'low', '2': 'medium', '3': 'high', '4': 'critical'}[level_choice]

    return rule

def format_sigma_yaml(rule: Dict) -> str:
    """Format rule as YAML (simplified)."""
    yaml_lines = []

    # Title
    yaml_lines.append(f"title: {rule['title']}")

    # ID
    yaml_lines.append(f"id: {rule['id']}")

    # Status
    yaml_lines.append(f"status: {rule['status']}")

    # Description
    if 'description' in rule:
        desc_lines = rule['description'].split('\n')
        if len(desc_lines) == 1:
            yaml_lines.append(f"description: {desc_lines[0]}")
        else:
            yaml_lines.append("description: |")
            for line in desc_lines:
                yaml_lines.append(f"    {line}")

    # References
    if 'references' in rule and rule['references']:
        yaml_lines.append("references:")
        for ref in rule['references']:
            yaml_lines.append(f"    - {ref}")

    # Author
    yaml_lines.append(f"author: {rule['author']}")

    # Date
    yaml_lines.append(f"date: {rule['date']}")

    # Modified
    yaml_lines.append(f"modified: {rule['modified']}")

    # Tags
    if 'tags' in rule:
        yaml_lines.append("tags:")
        for tag in rule['tags']:
            yaml_lines.append(f"    - {tag}")

    # Logsource
    yaml_lines.append("logsource:")
    yaml_lines.append(f"    product: {rule['logsource']['product']}")
    yaml_lines.append(f"    service: {rule['logsource']['service']}")

    # Detection
    yaml_lines.append("detection:")

    # Selection
    yaml_lines.append("    selection:")
    for field, value in rule['detection']['selection'].items():
        yaml_lines.append(f"        {field}: '{value}'")

    # Filter
    if 'filter' in rule['detection']:
        yaml_lines.append("    filter:")
        for field, value in rule['detection']['filter'].items():
            yaml_lines.append(f"        {field}: '{value}'")

    # Condition
    yaml_lines.append(f"    condition: {rule['detection']['condition']}")

    # False positives
    yaml_lines.append("falsepositives:")
    for fp in rule['falsepositives']:
        yaml_lines.append(f"    - {fp}")

    # Level
    yaml_lines.append(f"level: {rule['level']}")

    return '\n'.join(yaml_lines)

def main():
    """Main function."""
    try:
        # Generate rule
        rule = generate_sigma_rule()

        # Format as YAML
        yaml_content = format_sigma_yaml(rule)

        # Output
        print_header("Generated Sigma Rule")
        print(yaml_content)

        # Save to file
        print("\n")
        save = get_input("Save to file? (y/n)", "y").lower()

        if save == 'y':
            # Generate filename from title
            filename = re.sub(r'[^a-z0-9]+', '_', rule['title'].lower())
            filename = f"{filename}.yml"
            filename = get_input("Filename", filename)

            with open(filename, 'w') as f:
                f.write(yaml_content)

            print_success(f"Saved to {filename}")

            print("\nNext steps:")
            print(f"  1. Review the rule: cat {filename}")
            print("  2. Validate with sigma-cli: sigma check " + filename)
            print("  3. Test against sample data")
            print("  4. Convert to target platform (Splunk, Elastic, etc.)")

    except KeyboardInterrupt:
        print("\n\nOperation cancelled by user.")
        sys.exit(0)
    except Exception as e:
        print_error(f"Error: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()
