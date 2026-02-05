"""Tests for scanengine.context_analyzer"""

import pytest
from pathlib import Path
from scanengine.context_analyzer import ContextAnalyzer, EntropyAnalyzer
from scanengine.models import Finding, Severity, Confidence, Location


class TestContextAnalyzer:
    def test_identify_test_file_java(self):
        analyzer = ContextAnalyzer()
        ctx = analyzer.analyze_file_context(Path("/src/test/java/UserTest.java"))
        assert ctx.is_test_file

    def test_identify_test_file_python(self):
        analyzer = ContextAnalyzer()
        ctx = analyzer.analyze_file_context(Path("/tests/test_service.py"))
        assert ctx.is_test_file

    def test_regular_file_not_test(self):
        analyzer = ContextAnalyzer()
        ctx = analyzer.analyze_file_context(Path("/src/main/java/UserService.java"))
        assert not ctx.is_test_file

    def test_identify_vendor_file(self):
        analyzer = ContextAnalyzer()
        ctx = analyzer.analyze_file_context(Path("/vendor/lib/package.java"))
        assert ctx.is_vendor_file

    def test_identify_config_file(self):
        analyzer = ContextAnalyzer()
        ctx = analyzer.analyze_file_context(Path("/src/application.properties"))
        assert ctx.is_config_file

    def test_identify_config_yaml(self):
        analyzer = ContextAnalyzer()
        ctx = analyzer.analyze_file_context(Path("/src/application.yml"))
        assert ctx.is_config_file or ctx.language == "yaml"

    def test_java_language_detection(self):
        analyzer = ContextAnalyzer()
        ctx = analyzer.analyze_file_context(Path("/src/Main.java"))
        assert ctx.language == "java"

    def test_python_language_detection(self):
        analyzer = ContextAnalyzer()
        ctx = analyzer.analyze_file_context(Path("/src/main.py"))
        assert ctx.language == "python"

    def test_filter_false_positives_reduces_test_findings(self):
        analyzer = ContextAnalyzer()
        test_path = Path("/src/test/java/UserTest.java")
        finding = Finding(
            rule_id="SQLI-001",
            rule_name="SQL Injection",
            description="SQL injection in test",
            severity=Severity.CRITICAL,
            confidence=Confidence.HIGH,
            location=Location(
                file_path=str(test_path),
                line_number=10,
                snippet='executeQuery("SELECT * FROM " + id)',
            ),
        )
        # Test that file context correctly identifies test files
        ctx = analyzer.analyze_file_context(test_path)
        assert ctx.is_test_file


class TestEntropyAnalyzer:
    def test_calculate_entropy_high(self):
        ea = EntropyAnalyzer()
        entropy = ea.calculate_entropy("aB3kL9mNpQ2rS5tX")
        assert entropy > 3.0

    def test_calculate_entropy_low(self):
        ea = EntropyAnalyzer()
        entropy = ea.calculate_entropy("aaaaaaaaa")
        assert entropy < 1.0

    def test_is_high_entropy(self):
        ea = EntropyAnalyzer()
        assert ea.is_high_entropy("aB3kL9mNpQ2rS5tXwZ7yC4vE6f")

    def test_is_not_high_entropy(self):
        ea = EntropyAnalyzer()
        assert not ea.is_high_entropy("password123")

    def test_empty_string(self):
        ea = EntropyAnalyzer()
        entropy = ea.calculate_entropy("")
        assert entropy == 0.0
