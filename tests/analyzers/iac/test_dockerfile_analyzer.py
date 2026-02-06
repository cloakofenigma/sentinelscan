"""Tests for Dockerfile analyzer."""

import pytest
from pathlib import Path
from scanengine.analyzers.iac.dockerfile import DockerfileAnalyzer
from scanengine.models import Severity


@pytest.fixture
def analyzer():
    return DockerfileAnalyzer()


class TestDockerfileAnalyzerProperties:
    def test_name(self, analyzer):
        assert analyzer.name == "dockerfile_analyzer"

    def test_iac_type(self, analyzer):
        assert analyzer.iac_type == "dockerfile"

    def test_can_analyze_dockerfile(self, analyzer):
        assert analyzer.can_analyze(Path("Dockerfile"))
        assert analyzer.can_analyze(Path("Dockerfile.prod"))
        assert not analyzer.can_analyze(Path("docker-compose.yml"))


class TestDockerfileRootUser:
    def test_detects_no_user_instruction(self, analyzer, tmp_path):
        code = '''FROM ubuntu:20.04
RUN apt-get update
CMD ["bash"]
'''
        file_path = tmp_path / "Dockerfile"
        file_path.write_text(code)
        findings = analyzer.analyze_file(file_path, code)

        root_findings = [f for f in findings if 'ROOT' in f.rule_id.upper() or 'root' in f.description.lower()]
        assert len(root_findings) >= 1


class TestDockerfileLatestTag:
    def test_detects_latest_tag(self, analyzer, tmp_path):
        code = '''FROM ubuntu:latest
RUN apt-get update
'''
        file_path = tmp_path / "Dockerfile"
        file_path.write_text(code)
        findings = analyzer.analyze_file(file_path, code)

        latest_findings = [f for f in findings if 'LATEST' in f.rule_id.upper() or 'latest' in f.description.lower()]
        assert len(latest_findings) >= 1


class TestDockerfileHardcodedSecrets:
    def test_detects_env_secret(self, analyzer, tmp_path):
        code = '''FROM python:3.9
ENV SECRET_KEY=mysupersecretkey123
ENV DATABASE_PASSWORD=password123
'''
        file_path = tmp_path / "Dockerfile"
        file_path.write_text(code)
        findings = analyzer.analyze_file(file_path, code)

        secret_findings = [f for f in findings if 'HARDCO' in f.rule_id.upper() or 'secret' in f.description.lower()]
        assert len(secret_findings) >= 1


class TestDockerfileCurlBash:
    def test_detects_curl_pipe_bash(self, analyzer, tmp_path):
        code = '''FROM ubuntu:20.04
RUN curl https://example.com/install.sh | bash
'''
        file_path = tmp_path / "Dockerfile"
        file_path.write_text(code)
        findings = analyzer.analyze_file(file_path, code)

        curl_findings = [f for f in findings if 'CURL' in f.rule_id.upper() or 'curl' in f.description.lower()]
        assert len(curl_findings) >= 1


class TestDockerfileSudo:
    def test_detects_sudo_usage(self, analyzer, tmp_path):
        code = '''FROM ubuntu:20.04
RUN sudo apt-get update
'''
        file_path = tmp_path / "Dockerfile"
        file_path.write_text(code)
        findings = analyzer.analyze_file(file_path, code)

        sudo_findings = [f for f in findings if 'SUDO' in f.rule_id.upper() or 'sudo' in f.description.lower()]
        assert len(sudo_findings) >= 1


class TestDockerfileSafeConfig:
    def test_minimal_findings_for_safe_dockerfile(self, analyzer, tmp_path):
        code = '''FROM python:3.9-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

USER nobody

CMD ["python", "app.py"]
'''
        file_path = tmp_path / "Dockerfile"
        file_path.write_text(code)
        findings = analyzer.analyze_file(file_path, code)

        # Should have no root user finding since USER is specified
        root_findings = [f for f in findings if 'ROOT' in f.rule_id.upper()]
        assert len(root_findings) == 0

        # Should have no critical findings
        critical_findings = [f for f in findings if f.severity == Severity.CRITICAL]
        assert len(critical_findings) == 0
