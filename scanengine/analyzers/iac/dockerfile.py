"""
Dockerfile Analyzer for SentinelScan.

Detects security issues in Dockerfiles.
"""

import re
import logging
from typing import Dict, List, Set
from pathlib import Path

from ..base import IaCAnalyzer, AnalyzerCapabilities, IaCResource
from ..registry import AnalyzerRegistry
from ...models import Finding, Severity, Confidence, Location

logger = logging.getLogger(__name__)


@AnalyzerRegistry.register_iac('dockerfile')
class DockerfileAnalyzer(IaCAnalyzer):
    """Dockerfile security analyzer."""

    MISCONFIGURATIONS = {
        'run_as_root': {
            'pattern': r'^(?!.*USER\s+\S).*$',
            'check_type': 'missing',
            'severity': Severity.HIGH,
            'title': 'Running as Root',
            'description': 'No USER instruction - container runs as root',
            'cwe': 'CWE-250',
        },
        'latest_tag': {
            'pattern': r'FROM\s+\S+:latest',
            'severity': Severity.MEDIUM,
            'title': 'Using Latest Tag',
            'description': 'Using :latest tag is not reproducible',
            'cwe': 'CWE-1104',
        },
        'add_instead_of_copy': {
            'pattern': r'^ADD\s+(?!https?://)',
            'severity': Severity.LOW,
            'title': 'ADD Instead of COPY',
            'description': 'Use COPY for local files; ADD has extra features',
            'cwe': 'CWE-1188',
        },
        'hardcoded_secret': {
            'pattern': r'(?:ENV|ARG)\s+(?:\w*(?:PASSWORD|SECRET|KEY|TOKEN)\w*)\s*=\s*["\']?[^$\s][^\s"\']{8,}',
            'severity': Severity.CRITICAL,
            'title': 'Hardcoded Secret',
            'description': 'Secret value in Dockerfile',
            'cwe': 'CWE-798',
        },
        'expose_ssh': {
            'pattern': r'EXPOSE\s+22',
            'severity': Severity.MEDIUM,
            'title': 'SSH Port Exposed',
            'description': 'Exposing SSH port in container',
            'cwe': 'CWE-284',
        },
        'apt_no_clean': {
            'pattern': r'apt-get\s+install(?!.*&&.*rm\s+-rf)',
            'severity': Severity.LOW,
            'title': 'APT Cache Not Cleaned',
            'description': 'apt cache not removed after install',
            'cwe': 'CWE-1188',
        },
        'curl_bash': {
            'pattern': r'curl.*\|\s*(?:bash|sh)',
            'severity': Severity.HIGH,
            'title': 'Curl Pipe to Shell',
            'description': 'Downloading and executing scripts is risky',
            'cwe': 'CWE-494',
        },
        'sudo_usage': {
            'pattern': r'RUN\s+.*sudo\s+',
            'severity': Severity.MEDIUM,
            'title': 'Sudo in Dockerfile',
            'description': 'Using sudo is unnecessary and risky',
            'cwe': 'CWE-250',
        },
    }

    @property
    def name(self) -> str:
        return "dockerfile_analyzer"

    @property
    def iac_type(self) -> str:
        return "dockerfile"

    @property
    def providers(self) -> List[str]:
        return ['docker']

    @property
    def supported_extensions(self) -> Set[str]:
        return set()  # Dockerfiles don't have extensions

    @property
    def capabilities(self) -> AnalyzerCapabilities:
        return AnalyzerCapabilities(supports_ast=False)

    def can_analyze(self, file_path: Path) -> bool:
        name = file_path.name.lower()
        return name == 'dockerfile' or name.startswith('dockerfile.')

    def get_resources(self, file_path: Path, content: str) -> List[IaCResource]:
        resources = []
        # Extract FROM instructions as resources
        for match in re.finditer(r'FROM\s+(\S+)', content):
            resources.append(IaCResource(
                resource_type='base_image',
                name=match.group(1),
                file_path=str(file_path),
                line_number=content[:match.start()].count('\n') + 1,
                provider='docker',
            ))
        return resources

    def check_misconfigurations(self, resources: List[IaCResource]) -> List[Finding]:
        return []

    def analyze_file(self, file_path: Path, content: str) -> List[Finding]:
        findings = []

        # Check for USER instruction
        if 'USER' not in content:
            findings.append(Finding(
                rule_id='DOCKER-ROOT-001',
                rule_name='Running as Root',
                description='No USER instruction - container runs as root by default',
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                location=Location(str(file_path), 1, 0, ""),
                cwe='CWE-250',
                owasp='A05',
            ))

        for check_id, check in self.MISCONFIGURATIONS.items():
            if check.get('check_type') == 'missing':
                continue
            for match in re.finditer(check['pattern'], content, re.IGNORECASE | re.MULTILINE):
                line_num = content[:match.start()].count('\n') + 1
                findings.append(Finding(
                    rule_id=f'DOCKER-{check_id.upper()[:6]}',
                    rule_name=check['title'],
                    description=check['description'],
                    severity=check['severity'],
                    confidence=Confidence.HIGH,
                    location=Location(str(file_path), line_num, 0, match.group(0)[:60]),
                    cwe=check['cwe'],
                    owasp='A05',
                ))

        return findings

    def analyze_files(self, files: List[Path], content_cache: Dict[str, str]) -> List[Finding]:
        findings = []
        for file_path in files:
            if self.can_analyze(file_path):
                content = content_cache.get(str(file_path), "")
                if content:
                    findings.extend(self.analyze_file(file_path, content))
        return findings
