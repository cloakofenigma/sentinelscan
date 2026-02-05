"""Tests for scanengine.models"""

import pytest
from pathlib import Path
from scanengine.models import (
    Finding, Rule, ScanResult, Severity, Confidence,
    Location, RulePattern, Remediation
)


class TestSeverity:
    def test_priority_order(self):
        assert Severity.CRITICAL.priority > Severity.HIGH.priority
        assert Severity.HIGH.priority > Severity.MEDIUM.priority
        assert Severity.MEDIUM.priority > Severity.LOW.priority
        assert Severity.LOW.priority > Severity.INFO.priority

    def test_priority_values(self):
        assert Severity.CRITICAL.priority == 5
        assert Severity.HIGH.priority == 4
        assert Severity.MEDIUM.priority == 3
        assert Severity.LOW.priority == 2
        assert Severity.INFO.priority == 1

    def test_severity_values(self):
        assert Severity.CRITICAL.value == "critical"
        assert Severity.HIGH.value == "high"
        assert Severity.MEDIUM.value == "medium"
        assert Severity.LOW.value == "low"
        assert Severity.INFO.value == "info"


class TestConfidence:
    def test_confidence_values(self):
        assert Confidence.HIGH.value == "high"
        assert Confidence.MEDIUM.value == "medium"
        assert Confidence.LOW.value == "low"


class TestLocation:
    def test_str_format(self, sample_location):
        result = str(sample_location)
        assert "UserService.java" in result
        assert ":42" in result

    def test_defaults(self):
        loc = Location(file_path="test.java", line_number=1)
        assert loc.column is None
        assert loc.end_line is None
        assert loc.snippet is None


class TestFinding:
    def test_to_dict(self, sample_finding):
        d = sample_finding.to_dict()
        assert d["rule_id"] == "SQLI-001"
        assert d["rule_name"] == "SQL Injection via String Concatenation"
        assert d["severity"] == "critical"
        assert d["confidence"] == "high"
        assert d["cwe"] == "CWE-89"
        assert d["owasp"] == "A03"
        assert d["line_number"] == 42
        assert "UserService.java" in d["file_path"]
        assert isinstance(d["tags"], list)
        assert "sql-injection" in d["tags"]

    def test_to_dict_optional_fields(self):
        finding = Finding(
            rule_id="X-001",
            rule_name="Test",
            description="desc",
            severity=Severity.LOW,
            confidence=Confidence.LOW,
            location=Location(file_path="f.py", line_number=1),
        )
        d = finding.to_dict()
        assert d["cwe"] is None
        assert d["owasp"] is None
        assert d["remediation"] is None

    def test_default_collections(self):
        finding = Finding(
            rule_id="X-001",
            rule_name="Test",
            description="desc",
            severity=Severity.LOW,
            confidence=Confidence.LOW,
            location=Location(file_path="f.py", line_number=1),
        )
        assert finding.references == []
        assert finding.tags == []
        assert finding.metadata == {}


class TestRule:
    def test_applies_to_java_file(self, sample_rule):
        assert sample_rule.applies_to_file(Path("UserService.java"))

    def test_applies_to_python_file(self, sample_rule):
        assert sample_rule.applies_to_file(Path("service.py"))

    def test_not_applies_to_wrong_language(self, sample_rule):
        assert not sample_rule.applies_to_file(Path("script.rb"))

    def test_applies_to_xml_extension(self):
        rule = Rule(
            id="X-001", name="Test", description="d",
            severity=Severity.LOW, confidence=Confidence.LOW,
            languages=["xml"],
        )
        assert rule.applies_to_file(Path("config.xml"))

    def test_applies_when_no_constraints(self):
        rule = Rule(
            id="X-001", name="Test", description="d",
            severity=Severity.LOW, confidence=Confidence.LOW,
        )
        assert rule.applies_to_file(Path("anything.txt"))

    def test_file_pattern_matching(self):
        rule = Rule(
            id="X-001", name="Test", description="d",
            severity=Severity.LOW, confidence=Confidence.LOW,
            file_patterns=["*.config"],
        )
        assert rule.applies_to_file(Path("app.config"))
        assert not rule.applies_to_file(Path("app.java"))


class TestScanResult:
    def test_summary_counts(self, sample_scan_result):
        summary = sample_scan_result.summary
        assert summary["critical"] == 1
        assert summary["high"] == 1
        assert summary["low"] == 1
        assert summary["medium"] == 0

    def test_get_findings_by_severity(self, sample_scan_result):
        critical = sample_scan_result.get_findings_by_severity(Severity.CRITICAL)
        assert len(critical) == 1
        assert critical[0].rule_id == "SQLI-001"

        medium = sample_scan_result.get_findings_by_severity(Severity.MEDIUM)
        assert len(medium) == 0

    def test_sort_findings(self, sample_scan_result):
        sample_scan_result.sort_findings()
        severities = [f.severity for f in sample_scan_result.findings]
        assert severities[0] == Severity.CRITICAL
        assert severities[1] == Severity.HIGH
        assert severities[2] == Severity.LOW

    def test_empty_scan_result(self):
        result = ScanResult(target_path="/empty")
        assert result.findings == []
        assert result.files_scanned == 0
        assert result.summary["critical"] == 0
        assert len(result.get_findings_by_severity(Severity.HIGH)) == 0
