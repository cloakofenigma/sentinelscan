"""
AWS CloudFormation Analyzer for SentinelScan.

Detects security misconfigurations in CloudFormation templates.
"""

import re
import logging
from typing import Dict, List, Set
from pathlib import Path

from ..base import IaCAnalyzer, AnalyzerCapabilities, IaCResource
from ..registry import AnalyzerRegistry
from ...models import Finding, Severity, Confidence, Location

logger = logging.getLogger(__name__)


class CloudFormationAnalyzer(IaCAnalyzer):
    """CloudFormation template security analyzer."""

    MISCONFIGURATIONS = {
        'public_s3': {
            'pattern': r'AccessControl:\s*(?:PublicRead|PublicReadWrite)',
            'severity': Severity.CRITICAL,
            'title': 'Public S3 Bucket',
            'description': 'S3 bucket with public access',
            'cwe': 'CWE-284',
        },
        'open_security_group': {
            'pattern': r'CidrIp:\s*["\']?0\.0\.0\.0/0',
            'severity': Severity.HIGH,
            'title': 'Open Security Group',
            'description': 'Security group allows 0.0.0.0/0',
            'cwe': 'CWE-284',
        },
        'public_rds': {
            'pattern': r'PubliclyAccessible:\s*(?:true|["\']true["\'])',
            'severity': Severity.HIGH,
            'title': 'Public RDS',
            'description': 'RDS instance publicly accessible',
            'cwe': 'CWE-284',
        },
        'unencrypted_storage': {
            'pattern': r'StorageEncrypted:\s*(?:false|["\']false["\'])',
            'severity': Severity.HIGH,
            'title': 'Unencrypted Storage',
            'description': 'Storage encryption disabled',
            'cwe': 'CWE-311',
        },
        'hardcoded_secret': {
            'pattern': r'(?:Password|Secret|ApiKey):\s*["\'][^!][^"\']{8,}["\']',
            'severity': Severity.CRITICAL,
            'title': 'Hardcoded Secret',
            'description': 'Secret hardcoded in template',
            'cwe': 'CWE-798',
        },
    }

    @property
    def name(self) -> str:
        return "cloudformation_analyzer"

    @property
    def iac_type(self) -> str:
        return "cloudformation"

    @property
    def providers(self) -> List[str]:
        return ['aws']

    @property
    def supported_extensions(self) -> Set[str]:
        return {'.yaml', '.yml', '.json'}

    @property
    def capabilities(self) -> AnalyzerCapabilities:
        return AnalyzerCapabilities(supports_ast=False)

    def _is_cloudformation_file(self, content: str) -> bool:
        return 'AWSTemplateFormatVersion' in content or 'Resources:' in content

    def get_resources(self, file_path: Path, content: str) -> List[IaCResource]:
        resources = []
        pattern = r'(\w+):\s*\n\s*Type:\s*["\']?(AWS::[^\s"\']+)'
        for match in re.finditer(pattern, content):
            resources.append(IaCResource(
                resource_type=match.group(2),
                name=match.group(1),
                file_path=str(file_path),
                line_number=content[:match.start()].count('\n') + 1,
                provider='aws',
            ))
        return resources

    def check_misconfigurations(self, resources: List[IaCResource]) -> List[Finding]:
        return []

    def analyze_file(self, file_path: Path, content: str) -> List[Finding]:
        findings = []
        if not self._is_cloudformation_file(content):
            return findings

        for check_id, check in self.MISCONFIGURATIONS.items():
            for match in re.finditer(check['pattern'], content, re.IGNORECASE):
                line_num = content[:match.start()].count('\n') + 1
                findings.append(Finding(
                    rule_id=f'CFN-{check_id.upper()[:8]}',
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
            if file_path.suffix.lower() in self.supported_extensions:
                content = content_cache.get(str(file_path), "")
                if content and self._is_cloudformation_file(content):
                    findings.extend(self.analyze_file(file_path, content))
        return findings


AnalyzerRegistry._iac_analyzers['cfn'] = CloudFormationAnalyzer
