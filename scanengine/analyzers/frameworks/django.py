"""
Django Framework Analyzer for SentinelScan.

Detects security vulnerabilities specific to Django applications.
"""

import re
import logging
from typing import Dict, List, Set
from pathlib import Path

from ..base import FrameworkAnalyzer, AnalyzerCapabilities, Endpoint, SecurityConfig
from ..registry import AnalyzerRegistry
from ...models import Finding, Severity, Confidence, Location

logger = logging.getLogger(__name__)


@AnalyzerRegistry.register_framework('django')
class DjangoAnalyzer(FrameworkAnalyzer):
    """Django security analyzer."""

    @property
    def name(self) -> str:
        return "django_analyzer"

    @property
    def framework_name(self) -> str:
        return "Django"

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
            'file:settings.py',
            'file:manage.py',
            'import:from django',
            'import:import django',
        ]

    @property
    def capabilities(self) -> AnalyzerCapabilities:
        return AnalyzerCapabilities(supports_ast=False, supports_taint_tracking=True, supports_cross_file=True)

    def is_framework_project(self, files: List[Path], content_cache: Dict[str, str]) -> bool:
        file_names = {f.name.lower() for f in files}
        if 'manage.py' in file_names or 'settings.py' in file_names:
            return True
        for content in content_cache.values():
            if 'from django' in content or 'import django' in content:
                return True
        return False

    def analyze_file(self, file_path: Path, content: str) -> List[Finding]:
        findings = []
        if file_path.suffix == '.py':
            findings.extend(self._check_sql_injection(file_path, content))
            findings.extend(self._check_debug_mode(file_path, content))
            findings.extend(self._check_secret_key(file_path, content))
            findings.extend(self._check_csrf(file_path, content))
            findings.extend(self._check_clickjacking(file_path, content))
        if file_path.suffix == '.html':
            findings.extend(self._check_template_xss(file_path, content))
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
            if 'urls.py' in str(file_path):
                content = content_cache.get(str(file_path), "")
                pattern = r'path\s*\(\s*["\']([^"\']+)["\']'
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
        configs = []
        for file_path in files:
            if 'settings.py' in str(file_path):
                content = content_cache.get(str(file_path), "")
                # Check DEBUG
                if 'DEBUG = True' in content:
                    line_num = content.find('DEBUG = True')
                    configs.append(SecurityConfig(
                        name='DEBUG',
                        value=True,
                        file_path=str(file_path),
                        line_number=content[:line_num].count('\n') + 1 if line_num >= 0 else 1,
                        is_secure=False,
                        recommendation='Set DEBUG = False in production',
                    ))
        return configs

    def _check_sql_injection(self, file_path: Path, content: str) -> List[Finding]:
        findings = []
        patterns = [
            (r'\.raw\s*\(\s*f["\']', 'raw() with f-string'),
            (r'\.raw\s*\([^)]*%', 'raw() with % formatting'),
            (r'\.extra\s*\([^)]*where\s*=', 'extra() with where clause'),
            (r'cursor\.execute\s*\([^)]*%', 'execute() with % formatting'),
            (r'cursor\.execute\s*\(\s*f["\']', 'execute() with f-string'),
        ]
        for pattern, desc in patterns:
            for match in re.finditer(pattern, content):
                line_num = content[:match.start()].count('\n') + 1
                findings.append(self._create_finding(
                    rule_id='DJANGO-SQLI-001',
                    title='SQL Injection',
                    description=f'{desc} may be vulnerable to SQL injection',
                    file_path=file_path,
                    line_number=line_num,
                    severity=Severity.CRITICAL,
                    confidence=Confidence.HIGH,
                    cwe='CWE-89',
                    owasp='A03',
                    remediation='Use parameterized queries: Model.objects.raw(sql, [params])',
                ))
        return findings

    def _check_debug_mode(self, file_path: Path, content: str) -> List[Finding]:
        findings = []
        if 'settings' in str(file_path).lower():
            if re.search(r'DEBUG\s*=\s*True', content):
                match = re.search(r'DEBUG\s*=\s*True', content)
                line_num = content[:match.start()].count('\n') + 1
                findings.append(self._create_finding(
                    rule_id='DJANGO-CONFIG-001',
                    title='Debug Mode Enabled',
                    description='DEBUG = True exposes sensitive information',
                    file_path=file_path,
                    line_number=line_num,
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    cwe='CWE-215',
                    owasp='A05',
                    remediation='Set DEBUG = False in production',
                ))
        return findings

    def _check_secret_key(self, file_path: Path, content: str) -> List[Finding]:
        findings = []
        if 'settings' in str(file_path).lower():
            pattern = r'SECRET_KEY\s*=\s*["\'][^"\']{20,}["\']'
            for match in re.finditer(pattern, content):
                line_num = content[:match.start()].count('\n') + 1
                findings.append(self._create_finding(
                    rule_id='DJANGO-SECRET-001',
                    title='Hardcoded SECRET_KEY',
                    description='SECRET_KEY hardcoded in settings file',
                    file_path=file_path,
                    line_number=line_num,
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    cwe='CWE-798',
                    owasp='A07',
                    remediation='Load SECRET_KEY from environment variable',
                ))
        return findings

    def _check_csrf(self, file_path: Path, content: str) -> List[Finding]:
        findings = []
        if '@csrf_exempt' in content:
            for match in re.finditer(r'@csrf_exempt', content):
                line_num = content[:match.start()].count('\n') + 1
                findings.append(self._create_finding(
                    rule_id='DJANGO-CSRF-001',
                    title='CSRF Protection Disabled',
                    description='@csrf_exempt disables CSRF protection',
                    file_path=file_path,
                    line_number=line_num,
                    severity=Severity.MEDIUM,
                    confidence=Confidence.HIGH,
                    cwe='CWE-352',
                    owasp='A01',
                    remediation='Remove @csrf_exempt or implement alternative CSRF protection',
                ))
        return findings

    def _check_clickjacking(self, file_path: Path, content: str) -> List[Finding]:
        findings = []
        if 'settings' in str(file_path).lower():
            if 'X_FRAME_OPTIONS' not in content and 'XFrameOptionsMiddleware' not in content:
                findings.append(self._create_finding(
                    rule_id='DJANGO-CLICK-001',
                    title='Missing Clickjacking Protection',
                    description='X_FRAME_OPTIONS not configured',
                    file_path=file_path,
                    line_number=1,
                    severity=Severity.MEDIUM,
                    confidence=Confidence.MEDIUM,
                    cwe='CWE-1021',
                    owasp='A05',
                    remediation='Add X_FRAME_OPTIONS = "DENY" to settings',
                ))
        return findings

    def _check_template_xss(self, file_path: Path, content: str) -> List[Finding]:
        findings = []
        # Check for |safe filter
        patterns = [
            (r'\{\{\s*\w+\s*\|\s*safe\s*\}\}', '|safe filter bypasses escaping'),
            (r'\{%\s*autoescape\s+off\s*%\}', 'autoescape off disables escaping'),
        ]
        for pattern, desc in patterns:
            for match in re.finditer(pattern, content):
                line_num = content[:match.start()].count('\n') + 1
                findings.append(self._create_finding(
                    rule_id='DJANGO-XSS-001',
                    title='Template XSS',
                    description=desc,
                    file_path=file_path,
                    line_number=line_num,
                    severity=Severity.HIGH,
                    confidence=Confidence.MEDIUM,
                    cwe='CWE-79',
                    owasp='A03',
                    remediation='Avoid |safe filter with user input; use mark_safe() carefully',
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
