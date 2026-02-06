"""
Terraform/HCL Analyzer for SentinelScan.

Detects security misconfigurations in Terraform infrastructure code.
"""

import re
import logging
from typing import Dict, List, Set
from pathlib import Path

from ..base import IaCAnalyzer, AnalyzerCapabilities, IaCResource
from ..registry import AnalyzerRegistry
from ...models import Finding, Severity, Confidence, Location

logger = logging.getLogger(__name__)


@AnalyzerRegistry.register_iac('.tf', '.tfvars')
class TerraformAnalyzer(IaCAnalyzer):
    """Terraform security analyzer for AWS, GCP, Azure."""

    MISCONFIGURATIONS = {
        # S3 Bucket misconfigurations
        'public_s3': {
            'pattern': r'acl\s*=\s*["\']public-read',
            'severity': Severity.CRITICAL,
            'title': 'Public S3 Bucket',
            'description': 'S3 bucket has public read access',
            'cwe': 'CWE-284',
        },
        'unencrypted_s3': {
            'pattern': r'resource\s*"aws_s3_bucket"\s*"[^"]+"\s*\{[^}]*\}(?![^}]*server_side_encryption)',
            'severity': Severity.HIGH,
            'title': 'Unencrypted S3 Bucket',
            'description': 'S3 bucket without server-side encryption',
            'cwe': 'CWE-311',
        },
        # Security Group misconfigurations
        'open_ingress': {
            'pattern': r'cidr_blocks\s*=\s*\[\s*["\']0\.0\.0\.0/0["\']',
            'severity': Severity.HIGH,
            'title': 'Open Security Group',
            'description': 'Security group allows ingress from 0.0.0.0/0',
            'cwe': 'CWE-284',
        },
        'all_ports_open': {
            'pattern': r'from_port\s*=\s*0[^}]*to_port\s*=\s*65535',
            'severity': Severity.CRITICAL,
            'title': 'All Ports Open',
            'description': 'Security group allows all ports',
            'cwe': 'CWE-284',
        },
        # IAM misconfigurations (support both HCL and JSON formats)
        'permissive_iam': {
            'pattern': r'(?:"Action"\s*:\s*"\*"|Action\s*=\s*"\*")',
            'severity': Severity.HIGH,
            'title': 'Overly Permissive IAM',
            'description': 'IAM policy allows all actions',
            'cwe': 'CWE-269',
        },
        'iam_star_resource': {
            'pattern': r'(?:"Resource"\s*:\s*"\*"|Resource\s*=\s*"\*")',
            'severity': Severity.MEDIUM,
            'title': 'IAM Policy with Star Resource',
            'description': 'IAM policy applies to all resources',
            'cwe': 'CWE-269',
        },
        # RDS misconfigurations
        'public_rds': {
            'pattern': r'publicly_accessible\s*=\s*true',
            'severity': Severity.HIGH,
            'title': 'Public RDS Instance',
            'description': 'RDS instance is publicly accessible',
            'cwe': 'CWE-284',
        },
        'unencrypted_rds': {
            'pattern': r'storage_encrypted\s*=\s*false',
            'severity': Severity.HIGH,
            'title': 'Unencrypted RDS Storage',
            'description': 'RDS storage encryption disabled',
            'cwe': 'CWE-311',
        },
        # EBS Volume encryption
        'unencrypted_ebs': {
            'pattern': r'encrypted\s*=\s*false',
            'severity': Severity.HIGH,
            'title': 'Unencrypted EBS Volume',
            'description': 'EBS volume encryption disabled',
            'cwe': 'CWE-311',
        },
        # CloudTrail/Logging
        'cloudtrail_disabled': {
            'pattern': r'enable_logging\s*=\s*false',
            'severity': Severity.MEDIUM,
            'title': 'Logging Disabled',
            'description': 'CloudTrail or logging is disabled',
            'cwe': 'CWE-778',
        },
        # Hardcoded secrets
        'hardcoded_password': {
            'pattern': r'(?:password|secret|api_key)\s*=\s*["\'][^$][^"\']{8,}["\']',
            'severity': Severity.CRITICAL,
            'title': 'Hardcoded Secret',
            'description': 'Secret value hardcoded in Terraform',
            'cwe': 'CWE-798',
        },
    }

    @property
    def name(self) -> str:
        return "terraform_analyzer"

    @property
    def iac_type(self) -> str:
        return "terraform"

    @property
    def providers(self) -> List[str]:
        return ['aws', 'gcp', 'azure', 'kubernetes']

    @property
    def supported_extensions(self) -> Set[str]:
        return {'.tf', '.tfvars'}

    @property
    def capabilities(self) -> AnalyzerCapabilities:
        return AnalyzerCapabilities(supports_ast=False, supports_semantic_analysis=True)

    def get_resources(self, file_path: Path, content: str) -> List[IaCResource]:
        resources = []
        pattern = r'resource\s*"([^"]+)"\s*"([^"]+)"'
        for match in re.finditer(pattern, content):
            resource_type = match.group(1)
            resource_name = match.group(2)
            line_num = content[:match.start()].count('\n') + 1

            # Determine provider
            provider = 'unknown'
            if resource_type.startswith('aws_'):
                provider = 'aws'
            elif resource_type.startswith('google_') or resource_type.startswith('gcp_'):
                provider = 'gcp'
            elif resource_type.startswith('azurerm_'):
                provider = 'azure'

            resources.append(IaCResource(
                resource_type=resource_type,
                name=resource_name,
                file_path=str(file_path),
                line_number=line_num,
                provider=provider,
            ))
        return resources

    def check_misconfigurations(self, resources: List[IaCResource]) -> List[Finding]:
        # Note: This method is called by base class but we override analyze_file
        return []

    def analyze_file(self, file_path: Path, content: str) -> List[Finding]:
        findings = []

        for check_id, check in self.MISCONFIGURATIONS.items():
            for match in re.finditer(check['pattern'], content, re.IGNORECASE | re.DOTALL):
                line_num = content[:match.start()].count('\n') + 1
                findings.append(Finding(
                    rule_id=f'TF-{check_id.upper()[:8]}',
                    rule_name=check['title'],
                    description=check['description'],
                    severity=check['severity'],
                    confidence=Confidence.HIGH,
                    location=Location(
                        file_path=str(file_path),
                        line_number=line_num,
                        column=0,
                        snippet=match.group(0)[:80],
                    ),
                    cwe=check['cwe'],
                    owasp='A05',
                ))

        return findings

    def analyze_files(self, files: List[Path], content_cache: Dict[str, str]) -> List[Finding]:
        findings = []
        for file_path in files:
            if file_path.suffix.lower() in self.supported_extensions:
                content = content_cache.get(str(file_path), "")
                if content:
                    findings.extend(self.analyze_file(file_path, content))
        return findings
