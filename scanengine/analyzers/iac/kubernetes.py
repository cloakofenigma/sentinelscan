"""
Kubernetes Manifest Analyzer for SentinelScan.

Detects security misconfigurations in Kubernetes YAML manifests.
"""

import re
import logging
from typing import Dict, List, Set
from pathlib import Path
import yaml

from ..base import IaCAnalyzer, AnalyzerCapabilities, IaCResource
from ..registry import AnalyzerRegistry
from ...models import Finding, Severity, Confidence, Location

logger = logging.getLogger(__name__)


class KubernetesAnalyzer(IaCAnalyzer):
    """Kubernetes manifest security analyzer."""

    MISCONFIGURATIONS = {
        'privileged_container': {
            'pattern': r'privileged:\s*true',
            'severity': Severity.CRITICAL,
            'title': 'Privileged Container',
            'description': 'Container running in privileged mode',
            'cwe': 'CWE-250',
        },
        'run_as_root': {
            'pattern': r'runAsUser:\s*0',
            'severity': Severity.HIGH,
            'title': 'Container Running as Root',
            'description': 'Container configured to run as root user',
            'cwe': 'CWE-250',
        },
        'no_resource_limits': {
            'pattern': r'containers:\s*\n\s*-[^}]*(?!limits:)',
            'severity': Severity.MEDIUM,
            'title': 'Missing Resource Limits',
            'description': 'Container without CPU/memory limits',
            'cwe': 'CWE-770',
        },
        'host_network': {
            'pattern': r'hostNetwork:\s*true',
            'severity': Severity.HIGH,
            'title': 'Host Network Enabled',
            'description': 'Pod using host network namespace',
            'cwe': 'CWE-284',
        },
        'host_pid': {
            'pattern': r'hostPID:\s*true',
            'severity': Severity.HIGH,
            'title': 'Host PID Enabled',
            'description': 'Pod using host PID namespace',
            'cwe': 'CWE-284',
        },
        'host_path': {
            'pattern': r'hostPath:\s*\n\s*path:',
            'severity': Severity.MEDIUM,
            'title': 'HostPath Volume',
            'description': 'Pod mounting host filesystem',
            'cwe': 'CWE-284',
        },
        'allow_privilege_escalation': {
            'pattern': r'allowPrivilegeEscalation:\s*true',
            'severity': Severity.HIGH,
            'title': 'Privilege Escalation Allowed',
            'description': 'Container allows privilege escalation',
            'cwe': 'CWE-269',
        },
        'capabilities_all': {
            'pattern': r'capabilities:\s*\n\s*add:\s*\n\s*-\s*ALL',
            'severity': Severity.CRITICAL,
            'title': 'All Capabilities Added',
            'description': 'Container has all Linux capabilities',
            'cwe': 'CWE-250',
        },
        'no_readonly_root': {
            'pattern': r'readOnlyRootFilesystem:\s*false',
            'severity': Severity.LOW,
            'title': 'Writable Root Filesystem',
            'description': 'Container has writable root filesystem',
            'cwe': 'CWE-732',
        },
        'automount_token': {
            'pattern': r'automountServiceAccountToken:\s*true',
            'severity': Severity.LOW,
            'title': 'Service Account Token Auto-mounted',
            'description': 'Service account token automatically mounted',
            'cwe': 'CWE-269',
        },
        'default_namespace': {
            'pattern': r'namespace:\s*default',
            'severity': Severity.LOW,
            'title': 'Using Default Namespace',
            'description': 'Resource deployed to default namespace',
            'cwe': 'CWE-1188',
        },
        'latest_image': {
            'pattern': r'image:\s*[^\s:]+:latest',
            'severity': Severity.LOW,
            'title': 'Using Latest Image Tag',
            'description': 'Container using :latest image tag',
            'cwe': 'CWE-1104',
        },
        'hardcoded_secret': {
            'pattern': r'(?:password|secret|api_key|token):\s*["\']?[^$\s][^\s"\']{8,}',
            'severity': Severity.CRITICAL,
            'title': 'Hardcoded Secret',
            'description': 'Secret value hardcoded in manifest',
            'cwe': 'CWE-798',
        },
    }

    @property
    def name(self) -> str:
        return "kubernetes_analyzer"

    @property
    def iac_type(self) -> str:
        return "kubernetes"

    @property
    def providers(self) -> List[str]:
        return ['kubernetes']

    @property
    def supported_extensions(self) -> Set[str]:
        return {'.yaml', '.yml'}

    @property
    def capabilities(self) -> AnalyzerCapabilities:
        return AnalyzerCapabilities(supports_ast=False, supports_semantic_analysis=True)

    def _is_kubernetes_file(self, content: str) -> bool:
        """Check if file is a Kubernetes manifest."""
        return 'apiVersion:' in content and 'kind:' in content

    def get_resources(self, file_path: Path, content: str) -> List[IaCResource]:
        resources = []
        if not self._is_kubernetes_file(content):
            return resources

        try:
            docs = list(yaml.safe_load_all(content))
            for doc in docs:
                if doc and isinstance(doc, dict):
                    kind = doc.get('kind', 'Unknown')
                    metadata = doc.get('metadata', {})
                    name = metadata.get('name', 'unnamed')
                    resources.append(IaCResource(
                        resource_type=kind,
                        name=name,
                        file_path=str(file_path),
                        line_number=1,
                        provider='kubernetes',
                    ))
        except yaml.YAMLError:
            pass
        return resources

    def check_misconfigurations(self, resources: List[IaCResource]) -> List[Finding]:
        return []

    def analyze_file(self, file_path: Path, content: str) -> List[Finding]:
        findings = []

        if not self._is_kubernetes_file(content):
            return findings

        for check_id, check in self.MISCONFIGURATIONS.items():
            for match in re.finditer(check['pattern'], content, re.IGNORECASE | re.MULTILINE):
                line_num = content[:match.start()].count('\n') + 1
                findings.append(Finding(
                    rule_id=f'K8S-{check_id.upper()[:8]}',
                    rule_name=check['title'],
                    description=check['description'],
                    severity=check['severity'],
                    confidence=Confidence.HIGH,
                    location=Location(
                        file_path=str(file_path),
                        line_number=line_num,
                        column=0,
                        snippet=match.group(0)[:60],
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
                if content and self._is_kubernetes_file(content):
                    findings.extend(self.analyze_file(file_path, content))
        return findings


# Register for YAML files that are K8s manifests
# Note: We don't auto-register for .yaml/.yml since not all YAML is K8s
# The scanner will need to detect K8s files specially
AnalyzerRegistry._iac_analyzers['k8s'] = KubernetesAnalyzer
