"""
Deep Dataflow Analyzer - Main integration wrapper

Provides the public interface for the deep dataflow analysis engine,
integrating all components and returning results in the expected format.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional, Any
from pathlib import Path
import logging

from .engine import InterproceduralEngine, DetectedVulnerability
from .sanitizers import SanitizerRegistry
from .type_resolver import TypeResolver

import sys
sys.path.insert(0, str(__file__).rsplit('/', 2)[0])
from ..models import Finding, Severity, Confidence, Location
from ..dataflow_analyzer import SinkType, DataflowVulnerability

logger = logging.getLogger(__name__)


# Mapping from SinkType to Severity
SINK_SEVERITY = {
    SinkType.SQL_QUERY: Severity.CRITICAL,
    SinkType.COMMAND_EXEC: Severity.CRITICAL,
    SinkType.DESERIALIZATION: Severity.CRITICAL,
    SinkType.FILE_ACCESS: Severity.HIGH,
    SinkType.SSRF: Severity.HIGH,
    SinkType.XSS: Severity.HIGH,
    SinkType.LDAP_QUERY: Severity.HIGH,
    SinkType.XPATH_QUERY: Severity.MEDIUM,
    SinkType.LOG_OUTPUT: Severity.LOW,
}

# Mapping from SinkType to CWE
SINK_CWE = {
    SinkType.SQL_QUERY: 'CWE-89',
    SinkType.COMMAND_EXEC: 'CWE-78',
    SinkType.FILE_ACCESS: 'CWE-22',
    SinkType.SSRF: 'CWE-918',
    SinkType.XSS: 'CWE-79',
    SinkType.DESERIALIZATION: 'CWE-502',
    SinkType.LDAP_QUERY: 'CWE-90',
    SinkType.XPATH_QUERY: 'CWE-643',
    SinkType.LOG_OUTPUT: 'CWE-532',
}

# Mapping from SinkType to OWASP category
SINK_OWASP = {
    SinkType.SQL_QUERY: 'A03:2021-Injection',
    SinkType.COMMAND_EXEC: 'A03:2021-Injection',
    SinkType.FILE_ACCESS: 'A01:2021-Broken Access Control',
    SinkType.SSRF: 'A10:2021-SSRF',
    SinkType.XSS: 'A03:2021-Injection',
    SinkType.DESERIALIZATION: 'A08:2021-Software and Data Integrity Failures',
    SinkType.LDAP_QUERY: 'A03:2021-Injection',
    SinkType.XPATH_QUERY: 'A03:2021-Injection',
    SinkType.LOG_OUTPUT: 'A09:2021-Security Logging and Monitoring Failures',
}

# Remediation advice
SINK_REMEDIATION = {
    SinkType.SQL_QUERY: (
        "Use parameterized queries or prepared statements instead of string concatenation. "
        "Never build SQL queries by concatenating user input. "
        "Example: Use PreparedStatement with ? placeholders in Java."
    ),
    SinkType.COMMAND_EXEC: (
        "Avoid executing shell commands with user input. If necessary, use strict allowlists "
        "for permitted commands and arguments. Consider using ProcessBuilder with argument arrays "
        "instead of shell execution."
    ),
    SinkType.FILE_ACCESS: (
        "Validate and sanitize file paths. Use allowlists for permitted directories. "
        "Canonicalize paths and verify they remain within expected boundaries. "
        "Avoid using user input directly in file paths."
    ),
    SinkType.SSRF: (
        "Validate and restrict URLs to known safe destinations. Use allowlists for "
        "permitted hosts and protocols. Block requests to internal networks (127.0.0.1, "
        "10.x.x.x, 192.168.x.x, etc.)."
    ),
    SinkType.XSS: (
        "Encode output appropriately for the context (HTML, JavaScript, URL). "
        "Use framework-provided encoding functions like HtmlUtils.htmlEscape() in Spring. "
        "Implement Content-Security-Policy headers."
    ),
    SinkType.DESERIALIZATION: (
        "Avoid deserializing untrusted data. If necessary, use type-safe alternatives "
        "like JSON with strict schema validation. Never use ObjectInputStream with "
        "untrusted input."
    ),
    SinkType.LDAP_QUERY: (
        "Use parameterized LDAP queries. Escape special LDAP characters in user input. "
        "Avoid building LDAP filters through string concatenation."
    ),
    SinkType.XPATH_QUERY: (
        "Use parameterized XPath queries or precompiled XPath expressions. "
        "Escape special XML characters in user input."
    ),
    SinkType.LOG_OUTPUT: (
        "Sanitize user input before logging to prevent log injection. "
        "Avoid logging sensitive data like passwords, tokens, or PII. "
        "Use structured logging formats."
    ),
}


class DeepDataflowAnalyzer:
    """
    Deep dataflow analyzer with inter-procedural taint tracking.

    Provides:
    - SSA-based analysis
    - Sanitizer detection
    - Type-aware call resolution
    - Method summary propagation

    Usage:
        analyzer = DeepDataflowAnalyzer()
        analyzer.analyze_files(files, content_cache)
        findings = analyzer.get_findings()
    """

    def __init__(self,
                 sanitizer_config: Optional[List[Any]] = None,
                 max_iterations: int = 100,
                 max_call_depth: int = 10,
                 enable_interprocedural: bool = True):
        """
        Initialize the deep dataflow analyzer.

        Args:
            sanitizer_config: Custom sanitizer definitions
            max_iterations: Maximum fixed-point iterations
            max_call_depth: Maximum call chain depth
            enable_interprocedural: Enable inter-procedural analysis
        """
        self.sanitizer_registry = SanitizerRegistry(sanitizer_config)
        self.type_resolver = TypeResolver()

        self.engine = InterproceduralEngine(
            sanitizer_registry=self.sanitizer_registry,
            type_resolver=self.type_resolver,
            max_iterations=max_iterations,
            max_call_depth=max_call_depth
        )

        self.enable_interprocedural = enable_interprocedural
        self.vulnerabilities: List[DetectedVulnerability] = []
        self._findings: List[Finding] = []

    def analyze_files(self, files: List[Path],
                     content_cache: Dict[str, str]) -> List[DataflowVulnerability]:
        """
        Analyze files for dataflow vulnerabilities.

        Args:
            files: List of source files
            content_cache: File content cache

        Returns:
            List of detected vulnerabilities
        """
        # Filter to supported files
        supported_files = [f for f in files if f.suffix.lower() in ['.java']]

        if not supported_files:
            logger.debug("No supported files for deep dataflow analysis")
            return []

        logger.info(f"Deep dataflow analyzing {len(supported_files)} files")

        try:
            # Run analysis
            self.vulnerabilities = self.engine.analyze(supported_files, content_cache)

            # Convert to legacy format
            dataflow_vulns = self.engine.get_dataflow_vulnerabilities()

            # Build findings
            self._build_findings()

            logger.info(f"Deep dataflow found {len(self.vulnerabilities)} vulnerabilities")
            return dataflow_vulns

        except Exception as e:
            logger.error(f"Deep dataflow analysis failed: {e}")
            import traceback
            logger.debug(traceback.format_exc())
            return []

    def get_findings(self) -> List[Finding]:
        """
        Get analysis results as Finding objects.

        Returns:
            List of Finding objects for scanner integration
        """
        return self._findings

    def _build_findings(self) -> None:
        """Build Finding objects from vulnerabilities"""
        self._findings = []

        for vuln in self.vulnerabilities:
            finding = self._vulnerability_to_finding(vuln)
            self._findings.append(finding)

    def _vulnerability_to_finding(self, vuln: DetectedVulnerability) -> Finding:
        """Convert a DetectedVulnerability to a Finding"""
        sink_type = vuln.sink_type

        # Parse location
        sink_parts = vuln.sink_location.rsplit(':', 1)
        file_path = sink_parts[0]
        line_number = int(sink_parts[1]) if len(sink_parts) > 1 else 1

        # Build description
        source_desc = f"{vuln.source_label.source_type.value} at {vuln.source_label.source_location}"
        description = (
            f"Tainted data from {source_desc} flows to dangerous "
            f"{sink_type.value} sink at {vuln.sink_location}."
        )

        if vuln.propagation_path:
            description += f" Flow path: {' -> '.join(vuln.propagation_path)}"

        # Get rule ID
        rule_id = f"DATAFLOW-{sink_type.value.upper().replace('_', '-')}"

        # Get rule name
        rule_names = {
            SinkType.SQL_QUERY: 'SQL Injection via Tainted Data',
            SinkType.COMMAND_EXEC: 'Command Injection via Tainted Data',
            SinkType.FILE_ACCESS: 'Path Traversal via Tainted Data',
            SinkType.SSRF: 'SSRF via Tainted Data',
            SinkType.XSS: 'XSS via Tainted Data',
            SinkType.DESERIALIZATION: 'Insecure Deserialization',
            SinkType.LDAP_QUERY: 'LDAP Injection via Tainted Data',
            SinkType.XPATH_QUERY: 'XPath Injection via Tainted Data',
            SinkType.LOG_OUTPUT: 'Log Injection via Tainted Data',
        }
        rule_name = rule_names.get(sink_type, f'{sink_type.value} vulnerability')

        # Build snippet from source info
        snippet = f"Source: {vuln.source_label.original_variable}"
        if vuln.source_label.source_annotation:
            snippet += f" ({vuln.source_label.source_annotation})"

        return Finding(
            rule_id=rule_id,
            rule_name=rule_name,
            description=description,
            severity=SINK_SEVERITY.get(sink_type, Severity.MEDIUM),
            confidence=vuln.confidence,
            location=Location(
                file_path=file_path,
                line_number=line_number,
                snippet=snippet
            ),
            cwe=SINK_CWE.get(sink_type),
            owasp=SINK_OWASP.get(sink_type),
            remediation=SINK_REMEDIATION.get(sink_type),
            tags=['dataflow', 'taint-tracking', sink_type.value],
            references=[],
            metadata={
                'source_location': vuln.source_location,
                'source_type': vuln.source_label.source_type.value,
                'propagation_path': list(vuln.propagation_path),
                'analysis_type': 'deep_dataflow'
            }
        )

    def get_statistics(self) -> Dict[str, Any]:
        """Get analysis statistics"""
        return {
            'methods_analyzed': len(self.engine.ssa_methods),
            'summaries_computed': len(self.engine.summaries),
            'vulnerabilities_found': len(self.vulnerabilities),
            'by_sink_type': self._count_by_sink_type(),
        }

    def _count_by_sink_type(self) -> Dict[str, int]:
        """Count vulnerabilities by sink type"""
        counts: Dict[str, int] = {}
        for vuln in self.vulnerabilities:
            key = vuln.sink_type.value
            counts[key] = counts.get(key, 0) + 1
        return counts


def analyze_deep_dataflow(files: List[Path],
                         content_cache: Dict[str, str]) -> List[Finding]:
    """
    Convenience function for deep dataflow analysis.

    Args:
        files: Source files to analyze
        content_cache: File content cache

    Returns:
        List of findings
    """
    analyzer = DeepDataflowAnalyzer()
    analyzer.analyze_files(files, content_cache)
    return analyzer.get_findings()
