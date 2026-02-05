"""Shared test fixtures for SentinelScan test suite."""

import sys
import os
import pytest
from pathlib import Path

# Ensure scanengine is importable
sys.path.insert(0, str(Path(__file__).parent.parent))

from scanengine.models import (
    Finding, Rule, ScanResult, Severity, Confidence,
    Location, RulePattern, Remediation
)

FIXTURES_DIR = Path(__file__).parent / "fixtures"


@pytest.fixture
def fixtures_dir():
    """Path to test fixtures directory."""
    return FIXTURES_DIR


@pytest.fixture
def sample_location():
    """A sample code location."""
    return Location(
        file_path="/src/main/java/com/example/UserService.java",
        line_number=42,
        column=10,
        snippet='stmt.executeQuery("SELECT * FROM users WHERE id=" + userId);'
    )


@pytest.fixture
def sample_finding(sample_location):
    """A fully populated sample finding."""
    return Finding(
        rule_id="SQLI-001",
        rule_name="SQL Injection via String Concatenation",
        description="SQL query built using string concatenation with user input",
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        location=sample_location,
        cwe="CWE-89",
        owasp="A03",
        remediation="Use parameterized queries or prepared statements",
        tags=["sql-injection", "owasp-a03"],
    )


@pytest.fixture
def sample_finding_high():
    """A high severity finding."""
    return Finding(
        rule_id="CMD-001",
        rule_name="Command Injection",
        description="OS command execution with user input",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        location=Location(
            file_path="/src/main/java/com/example/ReportService.java",
            line_number=15,
            snippet='Runtime.getRuntime().exec("cmd " + userInput);'
        ),
        cwe="CWE-78",
        owasp="A03",
        tags=["command-injection"],
    )


@pytest.fixture
def sample_finding_low():
    """A low severity finding."""
    return Finding(
        rule_id="LOG-001",
        rule_name="Sensitive Data in Logs",
        description="Potential sensitive data written to log output",
        severity=Severity.LOW,
        confidence=Confidence.LOW,
        location=Location(
            file_path="/src/main/java/com/example/AuthService.java",
            line_number=88,
            snippet='logger.info("User login: " + username);'
        ),
        cwe="CWE-532",
        tags=["logging"],
    )


@pytest.fixture
def sample_rule():
    """A sample security rule with patterns."""
    return Rule(
        id="SQLI-001",
        name="SQL Injection via String Concatenation",
        description="SQL query built using string concatenation with user input",
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        cwe="CWE-89",
        owasp="A03",
        tags=["sql-injection", "owasp-a03"],
        languages=["java", "python"],
        patterns=[
            RulePattern(
                pattern=r'executeQuery\s*\(\s*.*\+\s*',
                language="java",
            ),
            RulePattern(
                pattern=r'execute\s*\(\s*["\']SELECT.*\+\s*',
                language="python",
            ),
        ],
        remediation=Remediation(
            description="Use parameterized queries or prepared statements"
        ),
    )


@pytest.fixture
def sample_scan_result(sample_finding, sample_finding_high, sample_finding_low):
    """A scan result with mixed severity findings."""
    return ScanResult(
        target_path="/src/main/java/com/example",
        findings=[sample_finding, sample_finding_high, sample_finding_low],
        files_scanned=25,
        rules_applied=50,
        scan_duration_seconds=1.5,
    )


@pytest.fixture
def sample_rules_dir(tmp_path):
    """Create a temporary rules directory with test rules."""
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()

    rule_content = (FIXTURES_DIR / "test_rules.yaml").read_text()
    (rules_dir / "test_rules.yaml").write_text(rule_content)

    return rules_dir


@pytest.fixture
def vulnerable_java_file(tmp_path):
    """Write vulnerable Java fixture to tmp and return path."""
    content = (FIXTURES_DIR / "vulnerable_java.java").read_text()
    target = tmp_path / "UserController.java"
    target.write_text(content)
    return target


@pytest.fixture
def vulnerable_python_file(tmp_path):
    """Write vulnerable Python fixture to tmp and return path."""
    content = (FIXTURES_DIR / "vulnerable_python.py").read_text()
    target = tmp_path / "vulnerable.py"
    target.write_text(content)
    return target


@pytest.fixture
def safe_java_file(tmp_path):
    """Write safe Java fixture to tmp and return path."""
    content = (FIXTURES_DIR / "safe_java.java").read_text()
    target = tmp_path / "SafeService.java"
    target.write_text(content)
    return target


@pytest.fixture
def mybatis_mapper_file(tmp_path):
    """Write MyBatis mapper fixture to tmp and return path."""
    content = (FIXTURES_DIR / "mybatis_mapper.xml").read_text()
    target = tmp_path / "UserMapper.xml"
    target.write_text(content)
    return target


@pytest.fixture
def spring_controller_file(tmp_path):
    """Write Spring controller fixture to tmp and return path."""
    content = (FIXTURES_DIR / "spring_controller.java").read_text()
    target = tmp_path / "UserController.java"
    target.write_text(content)
    return target


@pytest.fixture
def spring_security_config_file(tmp_path):
    """Write Spring security config fixture to tmp and return path."""
    content = (FIXTURES_DIR / "spring_security_config.java").read_text()
    target = tmp_path / "SecurityConfig.java"
    target.write_text(content)
    return target
