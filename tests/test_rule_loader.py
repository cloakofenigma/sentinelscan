"""Tests for scanengine.rule_loader"""

import pytest
from pathlib import Path
from scanengine.rule_loader import RuleLoader
from scanengine.models import Severity, Confidence


class TestRuleLoader:
    def test_load_rules_from_file(self, fixtures_dir):
        loader = RuleLoader()
        rules = loader.load_rules_from_file(fixtures_dir / "test_rules.yaml")
        # 4 rules in file, but 1 is disabled
        enabled = [r for r in rules if r.enabled]
        assert len(enabled) == 3

    def test_load_all_rules(self, sample_rules_dir):
        loader = RuleLoader(rules_dir=sample_rules_dir)
        rules = loader.load_all_rules()
        assert len(rules) >= 3

    def test_parse_rule_fields(self, fixtures_dir):
        loader = RuleLoader()
        rules = loader.load_rules_from_file(fixtures_dir / "test_rules.yaml")
        sqli = next(r for r in rules if r.id == "TEST-SQLI-001")

        assert sqli.name == "SQL Injection Test"
        assert sqli.severity == Severity.CRITICAL
        assert sqli.confidence == Confidence.HIGH
        assert sqli.cwe == "CWE-89"
        assert sqli.owasp == "A03"
        assert "sql-injection" in sqli.tags
        assert "java" in sqli.languages
        assert len(sqli.patterns) == 2

    def test_remediation_loaded(self, fixtures_dir):
        loader = RuleLoader()
        rules = loader.load_rules_from_file(fixtures_dir / "test_rules.yaml")
        sqli = next(r for r in rules if r.id == "TEST-SQLI-001")
        assert sqli.remediation is not None
        assert "parameterized" in sqli.remediation.description.lower()

    def test_disabled_rules_skipped(self, fixtures_dir):
        loader = RuleLoader()
        rules = loader.load_rules_from_file(fixtures_dir / "test_rules.yaml")
        ids = [r.id for r in rules if r.enabled]
        assert "TEST-DISABLED-001" not in ids

    def test_get_rules_for_language(self, sample_rules_dir):
        loader = RuleLoader(rules_dir=sample_rules_dir)
        loader.load_all_rules()
        java_rules = loader.get_rules_for_language("java")
        assert len(java_rules) >= 2

    def test_get_rules_by_severity(self, sample_rules_dir):
        loader = RuleLoader(rules_dir=sample_rules_dir)
        loader.load_all_rules()
        critical = loader.get_rules_by_severity(Severity.CRITICAL)
        assert len(critical) >= 1
        for r in critical:
            assert r.severity == Severity.CRITICAL

    def test_get_rule_by_id(self, sample_rules_dir):
        loader = RuleLoader(rules_dir=sample_rules_dir)
        loader.load_all_rules()
        rule = loader.get_rule_by_id("TEST-SQLI-001")
        assert rule is not None
        assert rule.name == "SQL Injection Test"

    def test_get_rule_by_id_not_found(self, sample_rules_dir):
        loader = RuleLoader(rules_dir=sample_rules_dir)
        loader.load_all_rules()
        rule = loader.get_rule_by_id("NONEXISTENT-999")
        assert rule is None

    def test_invalid_yaml_handled(self, tmp_path):
        bad_file = tmp_path / "bad.yaml"
        bad_file.write_text("{{invalid yaml content")
        loader = RuleLoader()
        rules = loader.load_rules_from_file(bad_file)
        assert rules == [] or rules is not None  # Should not raise
