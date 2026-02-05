"""
React Framework Analyzer for SentinelScan.

Detects security vulnerabilities specific to React/Next.js applications.
"""

import re
import logging
from typing import Dict, List, Set, Optional
from pathlib import Path

from ..base import FrameworkAnalyzer, AnalyzerCapabilities, Endpoint, SecurityConfig
from ..registry import AnalyzerRegistry
from ...models import Finding, Severity, Confidence, Location

logger = logging.getLogger(__name__)


@AnalyzerRegistry.register_framework('react')
class ReactAnalyzer(FrameworkAnalyzer):
    """React/Next.js security analyzer."""

    @property
    def name(self) -> str:
        return "react_analyzer"

    @property
    def framework_name(self) -> str:
        return "React"

    @property
    def base_language(self) -> str:
        return "javascript"

    @property
    def supported_extensions(self) -> Set[str]:
        return {'.jsx', '.tsx', '.js', '.ts'}

    @property
    def framework_extensions(self) -> Set[str]:
        return {'.jsx', '.tsx', '.js', '.ts'}

    @property
    def detection_patterns(self) -> List[str]:
        return [
            'package:"react"',
            'package:"next"',
            'import:from ["\']react["\']',
            'import:from ["\']next',
        ]

    @property
    def capabilities(self) -> AnalyzerCapabilities:
        return AnalyzerCapabilities(supports_ast=False, supports_taint_tracking=True)

    def is_framework_project(self, files: List[Path], content_cache: Dict[str, str]) -> bool:
        for file_path, content in content_cache.items():
            if 'package.json' in file_path:
                if '"react"' in content or '"next"' in content:
                    return True
            if file_path.endswith(('.jsx', '.tsx')):
                if "from 'react'" in content or 'from "react"' in content:
                    return True
        return False

    def analyze_file(self, file_path: Path, content: str) -> List[Finding]:
        findings = []
        findings.extend(self._check_dangerous_html(file_path, content))
        findings.extend(self._check_unsafe_href(file_path, content))
        findings.extend(self._check_eval_usage(file_path, content))
        findings.extend(self._check_unsafe_target(file_path, content))
        findings.extend(self._check_localstorage_sensitive(file_path, content))
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
        # Next.js API routes
        for file_path in files:
            path_str = str(file_path)
            if '/pages/api/' in path_str or '/app/api/' in path_str:
                content = content_cache.get(path_str, "")
                # Extract HTTP methods
                methods = []
                if 'req.method' in content:
                    if "'GET'" in content or '"GET"' in content:
                        methods.append('GET')
                    if "'POST'" in content or '"POST"' in content:
                        methods.append('POST')
                if not methods:
                    methods = ['GET', 'POST']  # Default
                for method in methods:
                    endpoints.append(Endpoint(
                        path=path_str.split('/pages/api/')[-1].split('/app/api/')[-1],
                        method=method,
                        handler=file_path.stem,
                        file_path=str(file_path),
                        line_number=1,
                    ))
        return endpoints

    def get_security_configs(self, files: List[Path], content_cache: Dict[str, str]) -> List[SecurityConfig]:
        configs = []
        for file_path in files:
            if 'next.config' in str(file_path):
                content = content_cache.get(str(file_path), "")
                # Check for security headers
                if 'headers' not in content:
                    configs.append(SecurityConfig(
                        name='security_headers',
                        value=None,
                        file_path=str(file_path),
                        line_number=1,
                        is_secure=False,
                        recommendation='Add security headers in next.config.js',
                    ))
        return configs

    def _check_dangerous_html(self, file_path: Path, content: str) -> List[Finding]:
        findings = []
        patterns = [
            r'dangerouslySetInnerHTML\s*=\s*\{\s*\{',
            r'dangerouslySetInnerHTML=\{',
        ]
        for pattern in patterns:
            for match in re.finditer(pattern, content):
                line_num = content[:match.start()].count('\n') + 1
                # Check if it involves user input
                context = content[max(0, match.start()-100):match.end()+100]
                severity = Severity.HIGH if 'props' in context or 'state' in context else Severity.MEDIUM
                findings.append(self._create_finding(
                    rule_id='REACT-XSS-001',
                    title='Dangerous HTML Injection',
                    description='dangerouslySetInnerHTML may lead to XSS',
                    file_path=file_path,
                    line_number=line_num,
                    severity=severity,
                    confidence=Confidence.MEDIUM,
                    cwe='CWE-79',
                    owasp='A03',
                    remediation='Sanitize HTML with DOMPurify before rendering',
                ))
        return findings

    def _check_unsafe_href(self, file_path: Path, content: str) -> List[Finding]:
        findings = []
        patterns = [
            r'href\s*=\s*\{[^}]*\+',
            r'href\s*=\s*\{`[^`]*\$\{',
            r'href\s*=\s*["\']javascript:',
        ]
        for pattern in patterns:
            for match in re.finditer(pattern, content):
                line_num = content[:match.start()].count('\n') + 1
                findings.append(self._create_finding(
                    rule_id='REACT-XSS-002',
                    title='Unsafe href Attribute',
                    description='Dynamic href may allow javascript: protocol XSS',
                    file_path=file_path,
                    line_number=line_num,
                    severity=Severity.HIGH,
                    confidence=Confidence.MEDIUM,
                    cwe='CWE-79',
                    owasp='A03',
                    remediation='Validate URLs and block javascript: protocol',
                ))
        return findings

    def _check_eval_usage(self, file_path: Path, content: str) -> List[Finding]:
        findings = []
        patterns = [
            r'\beval\s*\(',
            r'new\s+Function\s*\(',
            r'setTimeout\s*\([^)]*["\']',
            r'setInterval\s*\([^)]*["\']',
        ]
        for pattern in patterns:
            for match in re.finditer(pattern, content):
                line_num = content[:match.start()].count('\n') + 1
                findings.append(self._create_finding(
                    rule_id='REACT-EVAL-001',
                    title='Code Execution via eval',
                    description='eval() or Function() constructor may execute arbitrary code',
                    file_path=file_path,
                    line_number=line_num,
                    severity=Severity.HIGH,
                    confidence=Confidence.MEDIUM,
                    cwe='CWE-94',
                    owasp='A03',
                ))
        return findings

    def _check_unsafe_target(self, file_path: Path, content: str) -> List[Finding]:
        findings = []
        # Check for target="_blank" without rel="noopener"
        pattern = r'target\s*=\s*["\']_blank["\']'
        for match in re.finditer(pattern, content):
            # Check surrounding context for rel="noopener"
            context_start = max(0, match.start() - 100)
            context_end = min(len(content), match.end() + 100)
            context = content[context_start:context_end]
            if 'noopener' not in context and 'noreferrer' not in context:
                line_num = content[:match.start()].count('\n') + 1
                findings.append(self._create_finding(
                    rule_id='REACT-LINK-001',
                    title='Unsafe External Link',
                    description='target="_blank" without rel="noopener" is vulnerable to tabnabbing',
                    file_path=file_path,
                    line_number=line_num,
                    severity=Severity.LOW,
                    confidence=Confidence.HIGH,
                    cwe='CWE-1022',
                    owasp='A05',
                    remediation='Add rel="noopener noreferrer" to external links',
                ))
        return findings

    def _check_localstorage_sensitive(self, file_path: Path, content: str) -> List[Finding]:
        findings = []
        patterns = [
            r'localStorage\.setItem\s*\([^)]*(?:token|password|secret|key)',
            r'sessionStorage\.setItem\s*\([^)]*(?:token|password|secret|key)',
        ]
        for pattern in patterns:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                line_num = content[:match.start()].count('\n') + 1
                findings.append(self._create_finding(
                    rule_id='REACT-STORAGE-001',
                    title='Sensitive Data in Browser Storage',
                    description='Storing sensitive data in localStorage/sessionStorage',
                    file_path=file_path,
                    line_number=line_num,
                    severity=Severity.MEDIUM,
                    confidence=Confidence.MEDIUM,
                    cwe='CWE-922',
                    owasp='A07',
                    remediation='Use httpOnly cookies for sensitive tokens',
                ))
        return findings

    def _create_finding(self, rule_id: str, title: str, description: str,
                       file_path: Path, line_number: int, severity: Severity,
                       confidence: Confidence, cwe: str = "", owasp: str = "",
                       remediation: str = "") -> Finding:
        return Finding(
            rule_id=rule_id,
            rule_name=title,
            description=description,
            severity=severity,
            confidence=confidence,
            location=Location(file_path=str(file_path), line_number=line_number, column=0, snippet=""),
            cwe=cwe,
            owasp=owasp,
            remediation=remediation,
        )
