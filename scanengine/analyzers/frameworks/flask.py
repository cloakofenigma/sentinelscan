"""
Flask Framework Analyzer for SentinelScan.

Detects security vulnerabilities specific to Flask applications.
"""

import re
import logging
from typing import Dict, List, Set
from pathlib import Path

from ..base import FrameworkAnalyzer, AnalyzerCapabilities, Endpoint, SecurityConfig
from ..registry import AnalyzerRegistry
from ...models import Finding, Severity, Confidence, Location

logger = logging.getLogger(__name__)


@AnalyzerRegistry.register_framework('flask')
class FlaskAnalyzer(FrameworkAnalyzer):
    """Flask security analyzer."""

    @property
    def name(self) -> str:
        return "flask_analyzer"

    @property
    def framework_name(self) -> str:
        return "Flask"

    @property
    def base_language(self) -> str:
        return "python"

    @property
    def supported_extensions(self) -> Set[str]:
        return {'.py', '.html'}

    @property
    def framework_extensions(self) -> Set[str]:
        return {'.py', '.html'}

    @property
    def detection_patterns(self) -> List[str]:
        return [
            'import:from flask import',
            'import:import flask',
            'content:Flask\\(__name__\\)',
        ]

    @property
    def capabilities(self) -> AnalyzerCapabilities:
        return AnalyzerCapabilities(supports_ast=False, supports_taint_tracking=True)

    def is_framework_project(self, files: List[Path], content_cache: Dict[str, str]) -> bool:
        for content in content_cache.values():
            if 'from flask import' in content or 'Flask(__name__)' in content:
                return True
        return False

    def analyze_file(self, file_path: Path, content: str) -> List[Finding]:
        findings = []
        if file_path.suffix == '.py':
            findings.extend(self._check_debug_mode(file_path, content))
            findings.extend(self._check_secret_key(file_path, content))
            findings.extend(self._check_sql_injection(file_path, content))
            findings.extend(self._check_ssti(file_path, content))
            findings.extend(self._check_open_redirect(file_path, content))
        return findings

    def analyze_files(self, files: List[Path], content_cache: Dict[str, str]) -> List[Finding]:
        findings = []
        for file_path in files:
            if file_path.suffix.lower() in self.framework_extensions:
                content = content_cache.get(str(file_path), "")
                if content:
                    findings.extend(self.analyze_file(file_path, content))
        return findings

    def get_endpoints(self, files: List[Path], content_cache: Dict[str, str]) -> List[Endpoint]:
        endpoints = []
        for file_path in files:
            if file_path.suffix == '.py':
                content = content_cache.get(str(file_path), "")
                pattern = r'@\w+\.route\s*\(\s*["\']([^"\']+)["\']'
                for match in re.finditer(pattern, content):
                    endpoints.append(Endpoint(
                        path=match.group(1),
                        method='GET',
                        handler='',
                        file_path=str(file_path),
                        line_number=content[:match.start()].count('\n') + 1,
                    ))
        return endpoints

    def get_security_configs(self, files: List[Path], content_cache: Dict[str, str]) -> List[SecurityConfig]:
        return []

    def _check_debug_mode(self, file_path: Path, content: str) -> List[Finding]:
        findings = []
        patterns = [
            r'\.run\s*\([^)]*debug\s*=\s*True',
            r'DEBUG\s*=\s*True',
            r'app\.debug\s*=\s*True',
        ]
        for pattern in patterns:
            for match in re.finditer(pattern, content):
                line_num = content[:match.start()].count('\n') + 1
                findings.append(self._create_finding(
                    rule_id='FLASK-CONFIG-001',
                    title='Debug Mode Enabled',
                    description='Flask debug mode enabled in code',
                    file_path=file_path,
                    line_number=line_num,
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    cwe='CWE-215',
                    owasp='A05',
                ))
        return findings

    def _check_secret_key(self, file_path: Path, content: str) -> List[Finding]:
        findings = []
        patterns = [
            r'SECRET_KEY\s*=\s*["\'][^"\']{8,}["\']',
            r'app\.secret_key\s*=\s*["\'][^"\']+["\']',
        ]
        for pattern in patterns:
            for match in re.finditer(pattern, content):
                line_num = content[:match.start()].count('\n') + 1
                findings.append(self._create_finding(
                    rule_id='FLASK-SECRET-001',
                    title='Hardcoded Secret Key',
                    description='Secret key hardcoded in source code',
                    file_path=file_path,
                    line_number=line_num,
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    cwe='CWE-798',
                    owasp='A07',
                ))
        return findings

    def _check_sql_injection(self, file_path: Path, content: str) -> List[Finding]:
        findings = []
        patterns = [
            r'execute\s*\(\s*f["\']',
            r'execute\s*\([^)]*%',
            r'execute\s*\([^)]*\.format\(',
        ]
        for pattern in patterns:
            for match in re.finditer(pattern, content):
                line_num = content[:match.start()].count('\n') + 1
                findings.append(self._create_finding(
                    rule_id='FLASK-SQLI-001',
                    title='SQL Injection',
                    description='SQL query with string formatting',
                    file_path=file_path,
                    line_number=line_num,
                    severity=Severity.CRITICAL,
                    confidence=Confidence.HIGH,
                    cwe='CWE-89',
                    owasp='A03',
                ))
        return findings

    def _check_ssti(self, file_path: Path, content: str) -> List[Finding]:
        findings = []
        patterns = [
            r'render_template_string\s*\(',
            r'Template\s*\(\s*[^)]*request\.',
        ]
        for pattern in patterns:
            for match in re.finditer(pattern, content):
                line_num = content[:match.start()].count('\n') + 1
                findings.append(self._create_finding(
                    rule_id='FLASK-SSTI-001',
                    title='Server-Side Template Injection',
                    description='render_template_string may allow SSTI',
                    file_path=file_path,
                    line_number=line_num,
                    severity=Severity.CRITICAL,
                    confidence=Confidence.MEDIUM,
                    cwe='CWE-94',
                    owasp='A03',
                ))
        return findings

    def _check_open_redirect(self, file_path: Path, content: str) -> List[Finding]:
        findings = []
        patterns = [
            r'redirect\s*\(\s*request\.args',
            r'redirect\s*\(\s*request\.form',
        ]
        for pattern in patterns:
            for match in re.finditer(pattern, content):
                line_num = content[:match.start()].count('\n') + 1
                findings.append(self._create_finding(
                    rule_id='FLASK-REDIRECT-001',
                    title='Open Redirect',
                    description='Redirect with user-controlled URL',
                    file_path=file_path,
                    line_number=line_num,
                    severity=Severity.MEDIUM,
                    confidence=Confidence.MEDIUM,
                    cwe='CWE-601',
                    owasp='A01',
                ))
        return findings

    def _create_finding(self, rule_id: str, title: str, description: str,
                       file_path: Path, line_number: int, severity: Severity,
                       confidence: Confidence, cwe: str = "", owasp: str = "",
                       remediation: str = "") -> Finding:
        return Finding(
            rule_id=rule_id, rule_name=title, description=description,
            severity=severity, confidence=confidence,
            location=Location(file_path=str(file_path), line_number=line_number, column=0, snippet=""),
            cwe=cwe, owasp=owasp, remediation=remediation,
        )
