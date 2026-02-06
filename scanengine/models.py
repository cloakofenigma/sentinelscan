"""
Data models for SentinelScan.

This module defines all core data structures used throughout the scanner:

- Severity/Confidence: Enums for finding classification
- Rule/RulePattern: Security rule definitions
- Finding/Location: Detected vulnerability information
- ScanResult: Complete scan output

All classes are immutable dataclasses with full type annotations.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, List, Dict, Any, Iterator, TYPE_CHECKING
from pathlib import Path

if TYPE_CHECKING:
    from typing import Self


class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def priority(self) -> int:
        priorities = {
            Severity.CRITICAL: 5,
            Severity.HIGH: 4,
            Severity.MEDIUM: 3,
            Severity.LOW: 2,
            Severity.INFO: 1,
        }
        return priorities[self]


class Confidence(Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class RulePattern:
    """A single detection pattern within a rule"""
    pattern: str
    language: Optional[str] = None
    description: Optional[str] = None
    context: Optional[str] = None
    missing: Optional[str] = None  # Pattern that should NOT be present
    case_insensitive: bool = False


@dataclass
class Remediation:
    """Remediation guidance for a rule"""
    description: str
    code_examples: Dict[str, str] = field(default_factory=dict)


@dataclass
class Rule:
    """Security rule definition"""
    id: str
    name: str
    description: str
    severity: Severity
    confidence: Confidence
    cwe: Optional[str] = None
    owasp: Optional[str] = None
    cve: Optional[str] = None
    tags: List[str] = field(default_factory=list)
    languages: List[str] = field(default_factory=list)
    file_patterns: List[str] = field(default_factory=list)
    patterns: List[RulePattern] = field(default_factory=list)
    remediation: Optional[Remediation] = None
    references: List[str] = field(default_factory=list)
    enabled: bool = True

    def applies_to_file(self, filepath: Path) -> bool:
        """Check if rule applies to given file"""
        if not self.file_patterns and not self.languages:
            return True

        filename = filepath.name
        suffix = filepath.suffix.lower()

        # Check file patterns
        for pattern in self.file_patterns:
            if self._matches_glob(filename, pattern):
                return True

        # Check language by extension
        lang_extensions = {
            'java': ['.java'],
            'python': ['.py'],
            'javascript': ['.js', '.jsx', '.ts', '.tsx'],
            'php': ['.php'],
            'csharp': ['.cs'],
            'go': ['.go'],
            'ruby': ['.rb'],
            'xml': ['.xml'],
            'yaml': ['.yml', '.yaml'],
            'properties': ['.properties'],
            'html': ['.html', '.htm'],
        }

        for lang in self.languages:
            if lang.lower() in lang_extensions:
                if suffix in lang_extensions[lang.lower()]:
                    return True

        return bool(not self.file_patterns and not self.languages)

    def _matches_glob(self, filename: str, pattern: str) -> bool:
        """Simple glob matching"""
        import fnmatch
        return fnmatch.fnmatch(filename, pattern)


@dataclass
class Location:
    """Location of a finding in source code"""
    file_path: str
    line_number: int
    column: Optional[int] = None
    end_line: Optional[int] = None
    end_column: Optional[int] = None
    snippet: Optional[str] = None

    def __str__(self) -> str:
        return f"{self.file_path}:{self.line_number}"


@dataclass
class Finding:
    """A security finding/vulnerability detected"""
    rule_id: str
    rule_name: str
    description: str
    severity: Severity
    confidence: Confidence
    location: Location
    cwe: Optional[str] = None
    owasp: Optional[str] = None
    matched_pattern: Optional[str] = None
    remediation: Optional[str] = None
    references: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert finding to dictionary"""
        return {
            'rule_id': self.rule_id,
            'rule_name': self.rule_name,
            'description': self.description,
            'severity': self.severity.value,
            'confidence': self.confidence.value,
            'file_path': self.location.file_path,
            'line_number': self.location.line_number,
            'snippet': self.location.snippet,
            'cwe': self.cwe,
            'owasp': self.owasp,
            'remediation': self.remediation,
            'references': self.references,
            'tags': self.tags,
        }


@dataclass
class ScanResult:
    """Result of a security scan"""
    target_path: str
    findings: List[Finding] = field(default_factory=list)
    files_scanned: int = 0
    rules_applied: int = 0
    scan_duration_seconds: float = 0.0
    errors: List[str] = field(default_factory=list)

    @property
    def summary(self) -> Dict[str, int]:
        """Get count by severity"""
        counts = {s.value: 0 for s in Severity}
        for finding in self.findings:
            counts[finding.severity.value] += 1
        return counts

    def get_findings_by_severity(self, severity: Severity) -> List[Finding]:
        """Filter findings by severity"""
        return [f for f in self.findings if f.severity == severity]

    def sort_findings(self) -> None:
        """Sort findings by severity (critical first), then by file."""
        self.findings.sort(
            key=lambda f: (-f.severity.priority, f.location.file_path, f.location.line_number)
        )

    def filter_by_severity(self, min_severity: Severity) -> List[Finding]:
        """Get findings at or above a minimum severity level."""
        return [f for f in self.findings if f.severity.priority >= min_severity.priority]

    def filter_by_confidence(self, min_confidence: Confidence) -> List[Finding]:
        """Get findings at or above a minimum confidence level."""
        confidence_priority = {'high': 3, 'medium': 2, 'low': 1}
        min_priority = confidence_priority[min_confidence.value]
        return [
            f for f in self.findings
            if confidence_priority[f.confidence.value] >= min_priority
        ]

    def filter_by_cwe(self, cwe: str) -> List[Finding]:
        """Get findings matching a specific CWE."""
        return [f for f in self.findings if f.cwe == cwe]

    def filter_by_file(self, file_path: str) -> List[Finding]:
        """Get findings for a specific file."""
        return [f for f in self.findings if f.location.file_path == file_path]

    def get_affected_files(self) -> List[str]:
        """Get list of unique files with findings."""
        return list(set(f.location.file_path for f in self.findings))

    def has_critical_findings(self) -> bool:
        """Check if scan has any critical findings."""
        return any(f.severity == Severity.CRITICAL for f in self.findings)

    def __iter__(self) -> Iterator[Finding]:
        """Iterate over findings."""
        return iter(self.findings)

    def __len__(self) -> int:
        """Number of findings."""
        return len(self.findings)

    def to_dict(self) -> Dict[str, Any]:
        """Convert scan result to dictionary."""
        return {
            'target_path': self.target_path,
            'findings': [f.to_dict() for f in self.findings],
            'files_scanned': self.files_scanned,
            'rules_applied': self.rules_applied,
            'scan_duration_seconds': self.scan_duration_seconds,
            'errors': self.errors,
            'summary': self.summary,
        }
