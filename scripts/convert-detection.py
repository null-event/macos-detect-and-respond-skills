#!/usr/bin/env python3
"""
convert-detection.py - Convert detection formats between platforms

Usage: ./convert-detection.py [options] <input_file>

Description:
    Converts detection queries between different formats (Splunk SPL, Sigma, KQL, etc.)
    Handles field mapping and platform-specific syntax for macOS detections.

Supported Conversions:
    - Splunk SPL → Sigma YAML
    - Sigma YAML → Splunk SPL
    - Sigma YAML → KQL (Microsoft Sentinel)
    - Sigma YAML → Elastic Query DSL
    - SPL → KQL (basic conversion)
"""

import sys
import os
import re
import json
import argparse
from typing import Dict, List, Optional, Any
from datetime import datetime

# Color codes
class Colors:
    RED = '\033[0;31m'
    GREEN = '\033[0;32m'
    YELLOW = '\033[1;33m'
    BLUE = '\033[0;34m'
    CYAN = '\033[0;36m'
    NC = '\033[0m'

def print_header(text: str) -> None:
    print(f"\n{Colors.BLUE}=== {text} ==={Colors.NC}\n")

def print_success(text: str) -> None:
    print(f"{Colors.GREEN}✓ {text}{Colors.NC}")

def print_warning(text: str) -> None:
    print(f"{Colors.YELLOW}⚠ {text}{Colors.NC}")

def print_error(text: str) -> None:
    print(f"{Colors.RED}✗ {text}{Colors.NC}")

def print_info(text: str) -> None:
    print(f"{Colors.CYAN}{text}{Colors.NC}")

# Field mapping for macOS between different platforms
FIELD_MAPPINGS = {
    'splunk_to_sigma': {
        'process.executable.path': 'Image',
        'process.name': 'Image',
        'process.cmdline': 'CommandLine',
        'process.parent.name': 'ParentImage',
        'process.parent.cmdline': 'ParentCommandLine',
        'process.signing_id': 'SigningId',
        'process.team_id': 'TeamId',
        'process.uid': 'User',
        'file.path': 'TargetFilename',
        'file.name': 'TargetFilename',
        'event_type': 'EventType',
        'user': 'User',
        'host': 'Computer',
    },
    'sigma_to_splunk': {
        'Image': 'process.executable.path',
        'CommandLine': 'process.cmdline',
        'ParentImage': 'process.parent.name',
        'ParentCommandLine': 'process.parent.cmdline',
        'SigningId': 'process.signing_id',
        'TeamId': 'process.team_id',
        'User': 'user',
        'Computer': 'host',
        'TargetFilename': 'file.path',
    },
    'sigma_to_kql': {
        'Image': 'ProcessName',
        'CommandLine': 'ProcessCommandLine',
        'ParentImage': 'InitiatingProcessFileName',
        'ParentCommandLine': 'InitiatingProcessCommandLine',
        'User': 'AccountName',
        'Computer': 'DeviceName',
        'TargetFilename': 'FileName',
    }
}

# Sigma YAML parser (simplified)
def parse_sigma_yaml(content: str) -> Dict[str, Any]:
    """Parse Sigma YAML content into a dictionary."""
    result = {}
    current_section = None
    current_key = None
    indent_level = 0

    lines = content.split('\n')
    i = 0

    while i < len(lines):
        line = lines[i]
        stripped = line.lstrip()

        # Skip empty lines and comments
        if not stripped or stripped.startswith('#'):
            i += 1
            continue

        # Calculate indentation
        indent = len(line) - len(stripped)

        # Parse key-value pairs
        if ':' in stripped:
            key, value = stripped.split(':', 1)
            key = key.strip()
            value = value.strip()

            # Top-level keys
            if indent == 0:
                if value:
                    result[key] = value
                else:
                    result[key] = {}
                    current_section = key
                current_key = key

            # Nested keys
            elif current_section:
                if value:
                    if current_section not in result:
                        result[current_section] = {}
                    if isinstance(result[current_section], dict):
                        result[current_section][key] = value
                else:
                    if current_section not in result:
                        result[current_section] = {}
                    if isinstance(result[current_section], dict):
                        result[current_section][key] = {}

        # Parse list items
        elif stripped.startswith('-'):
            item = stripped[1:].strip()
            if current_section:
                if current_section not in result:
                    result[current_section] = []
                if not isinstance(result[current_section], list):
                    result[current_section] = []
                result[current_section].append(item)

        i += 1

    return result

def detect_format(content: str, filename: str) -> str:
    """Detect the format of the input detection."""
    # Check file extension first
    if filename.endswith('.yml') or filename.endswith('.yaml'):
        if 'title:' in content and 'detection:' in content:
            return 'sigma'

    if filename.endswith('.spl') or filename.endswith('.txt'):
        if 'index=' in content or 'sourcetype=' in content or '|' in content:
            return 'splunk'

    if filename.endswith('.kql'):
        return 'kql'

    # Content-based detection
    if 'title:' in content and 'detection:' in content and 'logsource:' in content:
        return 'sigma'

    if 'index=' in content or 'sourcetype=' in content:
        return 'splunk'

    if content.strip().startswith('DeviceProcessEvents') or 'DeviceFileEvents' in content:
        return 'kql'

    return 'unknown'

def splunk_to_sigma(spl_content: str, metadata: Dict[str, str]) -> str:
    """Convert Splunk SPL to Sigma YAML."""
    print_info("Converting Splunk SPL to Sigma YAML...")

    # Extract search criteria
    lines = spl_content.split('\n')
    search_parts = []
    filters = []

    for line in lines:
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        search_parts.append(line)

    # Parse SPL components
    index_pattern = re.search(r'index=(\S+)', spl_content)
    sourcetype_pattern = re.search(r'sourcetype=(\S+)', spl_content)

    # Build Sigma rule
    sigma_rule = {
        'title': metadata.get('title', 'Converted from Splunk SPL'),
        'id': metadata.get('id', 'auto-generated'),
        'status': metadata.get('status', 'experimental'),
        'description': metadata.get('description', 'Auto-converted from Splunk SPL query'),
        'author': metadata.get('author', 'convert-detection.py'),
        'date': datetime.now().strftime('%Y/%m/%d'),
        'logsource': {
            'product': 'macos',
            'service': 'esf'
        },
        'detection': {
            'selection': {},
            'condition': 'selection'
        },
        'falsepositives': ['Unknown'],
        'level': metadata.get('level', 'medium')
    }

    # Extract field conditions
    field_conditions = re.findall(r'(\w+(?:\.\w+)*)\s*=\s*"([^"]+)"', spl_content)
    field_conditions.extend(re.findall(r'(\w+(?:\.\w+)*)\s*=\s*(\S+)', spl_content))

    for field, value in field_conditions:
        # Skip index/sourcetype
        if field in ['index', 'sourcetype']:
            continue

        # Map Splunk field to Sigma field
        sigma_field = FIELD_MAPPINGS['splunk_to_sigma'].get(field, field)
        sigma_rule['detection']['selection'][sigma_field] = value.strip('"')

    # Extract where clauses
    where_patterns = re.findall(r'where\s+(.+?)(?:\||$)', spl_content)
    for where_clause in where_patterns:
        # Parse simple where conditions
        if 'match' in where_clause:
            match = re.search(r'match\(([^,]+),\s*"([^"]+)"\)', where_clause)
            if match:
                field = match.group(1).strip("'")
                pattern = match.group(2)
                sigma_field = FIELD_MAPPINGS['splunk_to_sigma'].get(field, field)
                sigma_rule['detection']['selection'][f"{sigma_field}|re"] = pattern

    # Format as YAML
    yaml_output = format_sigma_yaml(sigma_rule)

    return yaml_output

def sigma_to_splunk(sigma_content: str) -> str:
    """Convert Sigma YAML to Splunk SPL."""
    print_info("Converting Sigma YAML to Splunk SPL...")

    # Parse Sigma YAML
    sigma = parse_sigma_yaml(sigma_content)

    # Build SPL query
    spl_parts = []

    # Add index/sourcetype
    logsource = sigma.get('logsource', {})
    if isinstance(logsource, dict):
        service = logsource.get('service', 'esf')
        if service == 'esf':
            spl_parts.append('index=macos sourcetype="esf:json"')
        elif service == 'auditd':
            spl_parts.append('index=macos sourcetype="auditd"')
        else:
            spl_parts.append('index=macos')

    # Parse detection logic
    detection = sigma.get('detection', {})
    if isinstance(detection, dict):
        selection = detection.get('selection', {})

        if isinstance(selection, dict):
            for field, value in selection.items():
                # Handle field modifiers (contains, startswith, etc.)
                if '|' in field:
                    base_field, modifier = field.split('|', 1)
                    splunk_field = FIELD_MAPPINGS['sigma_to_splunk'].get(base_field, base_field)

                    if modifier == 'contains':
                        spl_parts.append(f'| search {splunk_field}="*{value}*"')
                    elif modifier == 'startswith':
                        spl_parts.append(f'| search {splunk_field}="{value}*"')
                    elif modifier == 'endswith':
                        spl_parts.append(f'| search {splunk_field}="*{value}"')
                    elif modifier == 're':
                        spl_parts.append(f'| regex {splunk_field}="{value}"')
                else:
                    # Direct field match
                    splunk_field = FIELD_MAPPINGS['sigma_to_splunk'].get(field, field)
                    spl_parts.append(f'| where \'{splunk_field}\'="{value}"')

    # Combine parts
    spl_query = '\n'.join(spl_parts)

    # Add comment header
    title = sigma.get('title', 'Converted Sigma Rule')
    description = sigma.get('description', '')

    header = f"""# {title}
# Description: {description}
# Converted from Sigma by convert-detection.py
# Original Sigma Rule ID: {sigma.get('id', 'unknown')}

"""

    return header + spl_query

def sigma_to_kql(sigma_content: str) -> str:
    """Convert Sigma YAML to KQL (Microsoft Sentinel)."""
    print_info("Converting Sigma YAML to KQL...")

    # Parse Sigma YAML
    sigma = parse_sigma_yaml(sigma_content)

    # Determine table based on logsource
    logsource = sigma.get('logsource', {})
    table = 'DeviceProcessEvents'  # Default for macOS process events

    # Build KQL query
    kql_parts = [table]

    # Parse detection logic
    detection = sigma.get('detection', {})
    if isinstance(detection, dict):
        selection = detection.get('selection', {})
        filters = []

        if isinstance(selection, dict):
            for field, value in selection.items():
                # Handle field modifiers
                if '|' in field:
                    base_field, modifier = field.split('|', 1)
                    kql_field = FIELD_MAPPINGS['sigma_to_kql'].get(base_field, base_field)

                    if modifier == 'contains':
                        filters.append(f'{kql_field} contains "{value}"')
                    elif modifier == 'startswith':
                        filters.append(f'{kql_field} startswith "{value}"')
                    elif modifier == 'endswith':
                        filters.append(f'{kql_field} endswith "{value}"')
                    elif modifier == 're':
                        filters.append(f'{kql_field} matches regex "{value}"')
                else:
                    kql_field = FIELD_MAPPINGS['sigma_to_kql'].get(field, field)
                    filters.append(f'{kql_field} == "{value}"')

        if filters:
            kql_parts.append('| where ' + ' and '.join(filters))

    # Add projection
    kql_parts.append('| project Timestamp, DeviceName, ProcessName, ProcessCommandLine, AccountName')

    kql_query = '\n'.join(kql_parts)

    # Add comment header
    title = sigma.get('title', 'Converted Sigma Rule')
    header = f"""// {title}
// Converted from Sigma by convert-detection.py
// Original Sigma Rule ID: {sigma.get('id', 'unknown')}

"""

    return header + kql_query

def format_sigma_yaml(rule: Dict[str, Any]) -> str:
    """Format a Sigma rule as YAML."""
    yaml_lines = []

    # Simple fields
    simple_fields = ['title', 'id', 'status', 'description', 'author', 'date', 'modified', 'level']

    for field in simple_fields:
        if field in rule:
            value = rule[field]
            if '\n' in str(value):
                yaml_lines.append(f"{field}: |")
                for line in value.split('\n'):
                    yaml_lines.append(f"    {line}")
            else:
                yaml_lines.append(f"{field}: {value}")

    # References
    if 'references' in rule and rule['references']:
        yaml_lines.append("references:")
        for ref in rule['references']:
            yaml_lines.append(f"    - {ref}")

    # Tags
    if 'tags' in rule and rule['tags']:
        yaml_lines.append("tags:")
        for tag in rule['tags']:
            yaml_lines.append(f"    - {tag}")

    # Logsource
    if 'logsource' in rule:
        yaml_lines.append("logsource:")
        for key, value in rule['logsource'].items():
            yaml_lines.append(f"    {key}: {value}")

    # Detection
    if 'detection' in rule:
        yaml_lines.append("detection:")
        detection = rule['detection']

        if 'selection' in detection:
            yaml_lines.append("    selection:")
            for field, value in detection['selection'].items():
                yaml_lines.append(f"        {field}: '{value}'")

        if 'filter' in detection:
            yaml_lines.append("    filter:")
            for field, value in detection['filter'].items():
                yaml_lines.append(f"        {field}: '{value}'")

        if 'condition' in detection:
            yaml_lines.append(f"    condition: {detection['condition']}")

    # False positives
    if 'falsepositives' in rule:
        yaml_lines.append("falsepositives:")
        for fp in rule['falsepositives']:
            yaml_lines.append(f"    - {fp}")

    return '\n'.join(yaml_lines)

def main():
    parser = argparse.ArgumentParser(
        description='Convert detection formats between platforms',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Auto-detect and convert to Sigma
  ./convert-detection.py -o sigma detection.spl

  # Convert Sigma to Splunk SPL
  ./convert-detection.py -i sigma -o splunk rule.yml

  # Convert Sigma to KQL
  ./convert-detection.py -i sigma -o kql rule.yml

  # Provide metadata for conversion
  ./convert-detection.py -o sigma -t "My Detection" detection.spl
        """
    )

    parser.add_argument('input_file', help='Input detection file')
    parser.add_argument('-i', '--input-format', choices=['sigma', 'splunk', 'kql', 'auto'],
                        default='auto', help='Input format (default: auto-detect)')
    parser.add_argument('-o', '--output-format', choices=['sigma', 'splunk', 'kql', 'elastic'],
                        required=True, help='Output format')
    parser.add_argument('-O', '--output-file', help='Output file (default: stdout)')
    parser.add_argument('-t', '--title', help='Detection title (for conversions to Sigma)')
    parser.add_argument('-d', '--description', help='Detection description')
    parser.add_argument('-a', '--author', help='Author name')
    parser.add_argument('-l', '--level', choices=['low', 'medium', 'high', 'critical'],
                        default='medium', help='Severity level')

    args = parser.parse_args()

    # Read input file
    if not os.path.exists(args.input_file):
        print_error(f"Input file not found: {args.input_file}")
        sys.exit(1)

    with open(args.input_file, 'r') as f:
        input_content = f.read()

    # Detect input format
    if args.input_format == 'auto':
        detected_format = detect_format(input_content, args.input_file)
        print_info(f"Detected input format: {detected_format}")
        input_format = detected_format
    else:
        input_format = args.input_format

    if input_format == 'unknown':
        print_error("Could not detect input format. Please specify with -i")
        sys.exit(1)

    print_header(f"Converting {input_format.upper()} → {args.output_format.upper()}")

    # Prepare metadata
    metadata = {
        'title': args.title,
        'description': args.description,
        'author': args.author,
        'level': args.level,
    }

    # Perform conversion
    try:
        if input_format == 'splunk' and args.output_format == 'sigma':
            output_content = splunk_to_sigma(input_content, metadata)

        elif input_format == 'sigma' and args.output_format == 'splunk':
            output_content = sigma_to_splunk(input_content)

        elif input_format == 'sigma' and args.output_format == 'kql':
            output_content = sigma_to_kql(input_content)

        elif input_format == 'sigma' and args.output_format == 'elastic':
            print_warning("Elastic Query DSL conversion not fully implemented")
            print_info("Please use sigma-cli for full Elastic conversion:")
            print_info(f"  sigma convert -t es-qs {args.input_file}")
            sys.exit(1)

        else:
            print_error(f"Conversion from {input_format} to {args.output_format} not supported")
            sys.exit(1)

        # Output result
        if args.output_file:
            with open(args.output_file, 'w') as f:
                f.write(output_content)
            print_success(f"Converted detection saved to: {args.output_file}")
        else:
            print("\n" + "="*60)
            print(output_content)
            print("="*60 + "\n")

        # Provide next steps
        print_header("Next Steps")
        print("1. Review the converted detection for accuracy")
        print("2. Validate field names match your data schema")
        print("3. Test against sample data in your environment")
        print("4. Tune for false positives")

        if args.output_format == 'sigma':
            print("\nValidate with sigma-cli:")
            print(f"  sigma check {args.output_file if args.output_file else 'output.yml'}")

    except Exception as e:
        print_error(f"Conversion failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == '__main__':
    main()
