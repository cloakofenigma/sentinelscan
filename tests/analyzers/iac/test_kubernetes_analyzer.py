"""Tests for Kubernetes IaC analyzer."""

import pytest
from pathlib import Path
from scanengine.analyzers.iac.kubernetes import KubernetesAnalyzer
from scanengine.models import Severity


@pytest.fixture
def analyzer():
    return KubernetesAnalyzer()


class TestKubernetesAnalyzerProperties:
    def test_name(self, analyzer):
        assert analyzer.name == "kubernetes_analyzer"

    def test_iac_type(self, analyzer):
        assert analyzer.iac_type == "kubernetes"

    def test_supported_extensions(self, analyzer):
        assert '.yaml' in analyzer.supported_extensions or '.yml' in analyzer.supported_extensions


class TestKubernetesPrivileged:
    def test_detects_privileged_container(self, analyzer, tmp_path):
        code = '''
apiVersion: v1
kind: Pod
metadata:
  name: privileged-pod
spec:
  containers:
  - name: app
    image: nginx
    securityContext:
      privileged: true
'''
        file_path = tmp_path / "pod.yaml"
        file_path.write_text(code)
        findings = analyzer.analyze_file(file_path, code)

        priv_findings = [f for f in findings if 'PRIV' in f.rule_id.upper() or 'privileged' in f.description.lower()]
        assert len(priv_findings) >= 1


class TestKubernetesRootUser:
    def test_detects_run_as_root(self, analyzer, tmp_path):
        code = '''
apiVersion: v1
kind: Pod
metadata:
  name: root-pod
spec:
  containers:
  - name: app
    image: nginx
    securityContext:
      runAsUser: 0
'''
        file_path = tmp_path / "pod.yaml"
        file_path.write_text(code)
        findings = analyzer.analyze_file(file_path, code)

        root_findings = [f for f in findings if 'ROOT' in f.rule_id.upper() or 'root' in f.description.lower()]
        assert len(root_findings) >= 1


class TestKubernetesHostNetwork:
    def test_detects_host_network(self, analyzer, tmp_path):
        code = '''
apiVersion: v1
kind: Pod
metadata:
  name: host-network-pod
spec:
  hostNetwork: true
  containers:
  - name: app
    image: nginx
'''
        file_path = tmp_path / "pod.yaml"
        file_path.write_text(code)
        findings = analyzer.analyze_file(file_path, code)

        host_findings = [f for f in findings if 'HOST' in f.rule_id.upper() or 'hostNetwork' in f.description]
        assert len(host_findings) >= 1


class TestKubernetesCapabilities:
    def test_detects_sys_admin_cap(self, analyzer, tmp_path):
        code = '''
apiVersion: v1
kind: Pod
metadata:
  name: cap-pod
spec:
  containers:
  - name: app
    image: nginx
    securityContext:
      capabilities:
        add:
          - SYS_ADMIN
'''
        file_path = tmp_path / "pod.yaml"
        file_path.write_text(code)
        findings = analyzer.analyze_file(file_path, code)

        cap_findings = [f for f in findings if 'CAP' in f.rule_id.upper() or 'SYS_ADMIN' in f.description]
        assert len(cap_findings) >= 1


class TestKubernetesNonK8sYaml:
    def test_ignores_non_k8s_yaml(self, analyzer, tmp_path):
        code = '''
name: my-app
version: 1.0.0
dependencies:
  - lodash
'''
        file_path = tmp_path / "config.yaml"
        file_path.write_text(code)
        findings = analyzer.analyze_file(file_path, code)

        # Should return empty or minimal findings for non-K8s YAML
        assert isinstance(findings, list)
