"""
Report generators for security scan results
"""

import csv
import json
from pathlib import Path
from typing import Optional, TextIO
from datetime import datetime
import sys

from .models import ScanResult, Finding, Severity


class BaseReporter:
    """Base class for reporters"""

    def report(self, result: ScanResult, output: Optional[str] = None) -> str:
        """Generate report and optionally write to file"""
        raise NotImplementedError

    def _write_output(self, content: str, output: Optional[str]) -> None:
        """Write content to file or stdout"""
        if output:
            with open(output, 'w', encoding='utf-8') as f:
                f.write(content)
        else:
            print(content)


class ConsoleReporter(BaseReporter):
    """Console/terminal output reporter with colors"""

    # ANSI color codes
    COLORS = {
        'critical': '\033[91m',  # Red
        'high': '\033[93m',      # Yellow
        'medium': '\033[94m',    # Blue
        'low': '\033[96m',       # Cyan
        'info': '\033[90m',      # Gray
        'reset': '\033[0m',
        'bold': '\033[1m',
        'green': '\033[92m',
    }

    def __init__(self, use_colors: bool = True, verbose: bool = False):
        self.use_colors = use_colors and sys.stdout.isatty()
        self.verbose = verbose

    def _color(self, text: str, color: str) -> str:
        """Apply color to text if colors enabled"""
        if not self.use_colors:
            return text
        return f"{self.COLORS.get(color, '')}{text}{self.COLORS['reset']}"

    def report(self, result: ScanResult, output: Optional[str] = None) -> str:
        """Generate console report"""
        lines = []

        # Header
        lines.append("")
        lines.append(self._color("=" * 60, 'bold'))
        lines.append(self._color("  SECURITY SCAN RESULTS", 'bold'))
        lines.append(self._color("=" * 60, 'bold'))
        lines.append("")

        # Summary
        lines.append(f"Target: {result.target_path}")
        lines.append(f"Files scanned: {result.files_scanned}")
        lines.append(f"Rules applied: {result.rules_applied}")
        lines.append(f"Scan duration: {result.scan_duration_seconds:.2f} seconds")
        lines.append("")

        # Severity breakdown
        lines.append(self._color("SUMMARY BY SEVERITY:", 'bold'))
        summary = result.summary
        for severity in Severity:
            count = summary.get(severity.value, 0)
            if count > 0:
                color = severity.value
                lines.append(f"  {self._color(severity.value.upper(), color)}: {count}")
        lines.append("")

        total = len(result.findings)
        if total == 0:
            lines.append(self._color("No security issues found!", 'green'))
        else:
            lines.append(self._color(f"FINDINGS ({total} total):", 'bold'))
            lines.append("-" * 60)

            # Group by severity
            for severity in Severity:
                severity_findings = result.get_findings_by_severity(severity)
                if not severity_findings:
                    continue

                lines.append("")
                lines.append(self._color(f"[{severity.value.upper()}]", severity.value))

                for finding in severity_findings:
                    lines.append("")
                    lines.append(f"  {self._color(finding.rule_id, 'bold')}: {finding.rule_name}")
                    lines.append(f"  Location: {finding.location}")
                    if finding.location.snippet:
                        snippet = finding.location.snippet[:80]
                        lines.append(f"  Code: {snippet}...")

                    if self.verbose:
                        lines.append(f"  Description: {finding.description}")
                        if finding.cwe:
                            lines.append(f"  CWE: {finding.cwe}")
                        if finding.owasp:
                            lines.append(f"  OWASP: {finding.owasp}")
                        if finding.remediation:
                            lines.append(f"  Remediation: {finding.remediation[:100]}...")

        # Errors
        if result.errors:
            lines.append("")
            lines.append(self._color("ERRORS:", 'critical'))
            for error in result.errors:
                lines.append(f"  - {error}")

        lines.append("")
        lines.append(self._color("=" * 60, 'bold'))

        content = "\n".join(lines)
        self._write_output(content, output)
        return content


class CSVReporter(BaseReporter):
    """CSV format reporter"""

    COLUMNS = [
        'finding_id', 'rule_id', 'rule_name', 'severity', 'confidence',
        'file_path', 'line_number', 'cwe', 'owasp', 'description',
        'snippet', 'remediation', 'tags'
    ]

    def report(self, result: ScanResult, output: Optional[str] = None) -> str:
        """Generate CSV report"""
        import io

        buffer = io.StringIO()
        writer = csv.DictWriter(buffer, fieldnames=self.COLUMNS)
        writer.writeheader()

        for idx, finding in enumerate(result.findings, 1):
            row = {
                'finding_id': f"F{idx:04d}",
                'rule_id': finding.rule_id,
                'rule_name': finding.rule_name,
                'severity': finding.severity.value,
                'confidence': finding.confidence.value,
                'file_path': finding.location.file_path,
                'line_number': finding.location.line_number,
                'cwe': finding.cwe or '',
                'owasp': finding.owasp or '',
                'description': finding.description,
                'snippet': finding.location.snippet or '',
                'remediation': finding.remediation or '',
                'tags': ','.join(finding.tags),
            }
            writer.writerow(row)

        content = buffer.getvalue()

        if output:
            with open(output, 'w', encoding='utf-8', newline='') as f:
                f.write(content)

        return content


class JSONReporter(BaseReporter):
    """JSON format reporter"""

    def report(self, result: ScanResult, output: Optional[str] = None) -> str:
        """Generate JSON report"""
        report_data = {
            'scan_info': {
                'target': result.target_path,
                'timestamp': datetime.now().isoformat(),
                'files_scanned': result.files_scanned,
                'rules_applied': result.rules_applied,
                'duration_seconds': result.scan_duration_seconds,
            },
            'summary': result.summary,
            'total_findings': len(result.findings),
            'findings': [f.to_dict() for f in result.findings],
            'errors': result.errors,
        }

        content = json.dumps(report_data, indent=2)
        self._write_output(content, output)
        return content


class SARIFReporter(BaseReporter):
    """SARIF format reporter (Static Analysis Results Interchange Format)"""

    SARIF_VERSION = "2.1.0"
    SCHEMA_URI = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"

    def report(self, result: ScanResult, output: Optional[str] = None) -> str:
        """Generate SARIF report"""
        # Build rules list
        rules = {}
        for finding in result.findings:
            if finding.rule_id not in rules:
                rules[finding.rule_id] = {
                    'id': finding.rule_id,
                    'name': finding.rule_name,
                    'shortDescription': {'text': finding.rule_name},
                    'fullDescription': {'text': finding.description},
                    'help': {'text': finding.remediation or ''},
                    'properties': {
                        'tags': finding.tags,
                        'security-severity': self._severity_to_score(finding.severity),
                    }
                }
                if finding.cwe:
                    rules[finding.rule_id]['properties']['cwe'] = finding.cwe

        # Build results
        results = []
        for finding in result.findings:
            sarif_result = {
                'ruleId': finding.rule_id,
                'level': self._severity_to_level(finding.severity),
                'message': {'text': finding.description},
                'locations': [{
                    'physicalLocation': {
                        'artifactLocation': {
                            'uri': finding.location.file_path,
                        },
                        'region': {
                            'startLine': finding.location.line_number,
                        }
                    }
                }],
            }

            if finding.location.snippet:
                sarif_result['locations'][0]['physicalLocation']['region']['snippet'] = {
                    'text': finding.location.snippet
                }

            results.append(sarif_result)

        # Build SARIF document
        sarif = {
            '$schema': self.SCHEMA_URI,
            'version': self.SARIF_VERSION,
            'runs': [{
                'tool': {
                    'driver': {
                        'name': 'SentinelScan',
                        'version': '0.1.0',
                        'informationUri': 'https://github.com/sentinelscan',
                        'rules': list(rules.values()),
                    }
                },
                'results': results,
                'invocations': [{
                    'executionSuccessful': len(result.errors) == 0,
                    'toolExecutionNotifications': [
                        {'message': {'text': e}, 'level': 'error'}
                        for e in result.errors
                    ]
                }]
            }]
        }

        content = json.dumps(sarif, indent=2)
        self._write_output(content, output)
        return content

    def _severity_to_level(self, severity: Severity) -> str:
        """Convert severity to SARIF level"""
        mapping = {
            Severity.CRITICAL: 'error',
            Severity.HIGH: 'error',
            Severity.MEDIUM: 'warning',
            Severity.LOW: 'note',
            Severity.INFO: 'note',
        }
        return mapping.get(severity, 'warning')

    def _severity_to_score(self, severity: Severity) -> str:
        """Convert severity to security-severity score"""
        mapping = {
            Severity.CRITICAL: '9.0',
            Severity.HIGH: '7.0',
            Severity.MEDIUM: '5.0',
            Severity.LOW: '3.0',
            Severity.INFO: '1.0',
        }
        return mapping.get(severity, '5.0')


def get_reporter(format: str, **kwargs) -> BaseReporter:
    """Factory function to get reporter by format"""
    reporters = {
        'console': ConsoleReporter,
        'csv': CSVReporter,
        'json': JSONReporter,
        'sarif': SARIFReporter,
    }

    reporter_class = reporters.get(format.lower())
    if not reporter_class:
        raise ValueError(f"Unknown report format: {format}. Supported: {list(reporters.keys())}")

    return reporter_class(**kwargs)
