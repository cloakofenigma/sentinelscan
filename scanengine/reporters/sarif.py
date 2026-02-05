"""
SARIF Output Format Reporter

Generates SARIF (Static Analysis Results Interchange Format) output
for integration with GitHub Security, GitLab SAST, and other tools.

SARIF Spec: https://sarifweb.azurewebsites.net/
"""

import json
from datetime import datetime
from typing import Any, Dict, List, Optional
from pathlib import Path

from ..models import Finding, ScanResult, Severity


SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"


def severity_to_sarif_level(severity: Severity) -> str:
    """Convert severity to SARIF level."""
    mapping = {
        'critical': 'error',
        'high': 'error',
        'medium': 'warning',
        'low': 'note',
        'info': 'note',
    }
    return mapping.get(severity.value, 'warning')


def severity_to_security_severity(severity: Severity) -> str:
    """Convert to GitHub security severity."""
    mapping = {
        'critical': 'critical',
        'high': 'high',
        'medium': 'medium',
        'low': 'low',
        'info': 'low',
    }
    return mapping.get(severity.value, 'medium')


def create_rule(finding: Finding) -> Dict[str, Any]:
    """Create a SARIF rule from a finding."""
    rule = {
        "id": finding.rule_id,
        "name": finding.rule_name,
        "shortDescription": {
            "text": finding.rule_name
        },
        "fullDescription": {
            "text": finding.description or finding.rule_name
        },
        "defaultConfiguration": {
            "level": severity_to_sarif_level(finding.severity)
        },
        "properties": {
            "security-severity": str(finding.severity.priority),
            "precision": "high" if (finding.confidence.value if hasattr(finding.confidence, 'value') else finding.confidence) == "high" else "medium",
            "tags": finding.tags or []
        }
    }

    # Add help/remediation
    if finding.remediation:
        rule["help"] = {
            "text": finding.remediation,
            "markdown": f"**Remediation:**\n\n{finding.remediation}"
        }

    # Add CWE if present
    if finding.cwe:
        cwe_id = finding.cwe.replace('CWE-', '')
        rule["properties"]["cwe"] = [finding.cwe]
        rule["helpUri"] = f"https://cwe.mitre.org/data/definitions/{cwe_id}.html"

    # Add OWASP if present
    if finding.owasp:
        if "tags" not in rule["properties"]:
            rule["properties"]["tags"] = []
        rule["properties"]["tags"].append(f"owasp-{finding.owasp}")

    return rule


def create_result(finding: Finding, rule_index: int, base_path: Optional[str] = None) -> Dict[str, Any]:
    """Create a SARIF result from a finding."""
    # Get relative path
    file_path = finding.location.file_path
    if base_path and file_path.startswith(base_path):
        file_path = file_path[len(base_path):].lstrip('/')

    result = {
        "ruleId": finding.rule_id,
        "ruleIndex": rule_index,
        "level": severity_to_sarif_level(finding.severity),
        "message": {
            "text": finding.description or finding.rule_name
        },
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": file_path,
                        "uriBaseId": "%SRCROOT%"
                    },
                    "region": {
                        "startLine": finding.location.line_number,
                        "startColumn": finding.location.column or 1
                    }
                }
            }
        ]
    }

    # Add end line if available
    if finding.location.end_line:
        result["locations"][0]["physicalLocation"]["region"]["endLine"] = finding.location.end_line

    # Add snippet if available (from location)
    if finding.location.snippet:
        result["locations"][0]["physicalLocation"]["region"]["snippet"] = {
            "text": finding.location.snippet[:500]  # Limit snippet size
        }

    # Add fingerprint for deduplication
    fingerprint = f"{finding.rule_id}:{file_path}:{finding.location.line_number}"
    result["fingerprints"] = {
        "primaryLocationLineHash": fingerprint
    }

    # Add partial fingerprint for GitHub
    result["partialFingerprints"] = {
        "primaryLocationLineHash": str(hash(fingerprint) & 0xFFFFFFFF)
    }

    # Add properties
    result["properties"] = {
        "security-severity": severity_to_security_severity(finding.severity),
        "confidence": finding.confidence.value if hasattr(finding.confidence, 'value') else str(finding.confidence)
    }

    if finding.cwe:
        result["properties"]["cwe"] = finding.cwe

    if finding.owasp:
        result["properties"]["owasp"] = finding.owasp

    return result


def generate_sarif(
    scan_result: ScanResult,
    tool_name: str = "SentinelScan",
    tool_version: str = "0.5.0",
    base_path: Optional[str] = None,
    include_suppressed: bool = False
) -> Dict[str, Any]:
    """
    Generate SARIF report from scan results.

    Args:
        scan_result: Scan results to convert
        tool_name: Name of the analysis tool
        tool_version: Version of the tool
        base_path: Base path to make paths relative
        include_suppressed: Include suppressed findings

    Returns:
        SARIF document as dictionary
    """
    # Collect unique rules
    rules_map: Dict[str, Dict[str, Any]] = {}
    rule_indices: Dict[str, int] = {}

    findings = scan_result.findings
    if not include_suppressed:
        findings = [f for f in findings if not getattr(f, 'suppressed', False)]

    for finding in findings:
        if finding.rule_id not in rules_map:
            rules_map[finding.rule_id] = create_rule(finding)
            rule_indices[finding.rule_id] = len(rules_map) - 1

    # Create results
    results = []
    for finding in findings:
        rule_index = rule_indices[finding.rule_id]
        results.append(create_result(finding, rule_index, base_path))

    # Build SARIF document
    sarif = {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": tool_name,
                        "version": tool_version,
                        "informationUri": "https://github.com/sentinelscan",
                        "rules": list(rules_map.values())
                    }
                },
                "results": results,
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "endTimeUtc": datetime.utcnow().isoformat() + "Z"
                    }
                ],
                "originalUriBaseIds": {
                    "%SRCROOT%": {
                        "uri": f"file://{base_path}/" if base_path else ""
                    }
                }
            }
        ]
    }

    # Add artifacts (scanned files)
    if hasattr(scan_result, 'scanned_files') and scan_result.scanned_files:
        artifacts = []
        for file_path in scan_result.scanned_files[:1000]:  # Limit
            rel_path = file_path
            if base_path and rel_path.startswith(base_path):
                rel_path = rel_path[len(base_path):].lstrip('/')
            artifacts.append({
                "location": {
                    "uri": rel_path,
                    "uriBaseId": "%SRCROOT%"
                }
            })
        sarif["runs"][0]["artifacts"] = artifacts

    return sarif


def write_sarif(
    scan_result: ScanResult,
    output_path: str,
    tool_name: str = "SentinelScan",
    tool_version: str = "0.5.0",
    base_path: Optional[str] = None,
    pretty: bool = True
) -> str:
    """
    Write SARIF report to file.

    Args:
        scan_result: Scan results
        output_path: Output file path
        tool_name: Tool name
        tool_version: Tool version
        base_path: Base path for relative paths
        pretty: Pretty print JSON

    Returns:
        Path to written file
    """
    sarif = generate_sarif(scan_result, tool_name, tool_version, base_path)

    with open(output_path, 'w') as f:
        if pretty:
            json.dump(sarif, f, indent=2)
        else:
            json.dump(sarif, f)

    return output_path


class SARIFReporter:
    """SARIF reporter class for integration."""

    def __init__(
        self,
        tool_name: str = "SentinelScan",
        tool_version: str = "0.5.0"
    ):
        self.tool_name = tool_name
        self.tool_version = tool_version

    def generate(
        self,
        scan_result: ScanResult,
        base_path: Optional[str] = None
    ) -> Dict[str, Any]:
        """Generate SARIF report."""
        return generate_sarif(
            scan_result,
            self.tool_name,
            self.tool_version,
            base_path
        )

    def write(
        self,
        scan_result: ScanResult,
        output_path: str,
        base_path: Optional[str] = None
    ) -> str:
        """Write SARIF to file."""
        return write_sarif(
            scan_result,
            output_path,
            self.tool_name,
            self.tool_version,
            base_path
        )

    def report(
        self,
        result: ScanResult,
        output: Optional[str] = None
    ) -> str:
        """Generate SARIF report and optionally write to file."""
        content = json.dumps(self.generate(result), indent=2)
        if output:
            with open(output, 'w', encoding='utf-8') as f:
                f.write(content)
        else:
            print(content)
        return content

    def to_json(
        self,
        scan_result: ScanResult,
        base_path: Optional[str] = None,
        pretty: bool = True
    ) -> str:
        """Get SARIF as JSON string."""
        sarif = self.generate(scan_result, base_path)
        if pretty:
            return json.dumps(sarif, indent=2)
        return json.dumps(sarif)
