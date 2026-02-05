"""Tests for # nosec suppression and .sentinelscanignore support"""

import pytest
from pathlib import Path
from scanengine.pattern_matcher import PatternMatcher
from scanengine.scanner import SecurityScanner, create_scanner
from scanengine.models import Rule, RulePattern, Severity, Confidence


def make_rule(rule_id="SQLI-001", pattern=r'executeQuery\s*\(\s*.*\+\s*'):
    return Rule(
        id=rule_id, name=f"Test {rule_id}", description="Test rule",
        severity=Severity.HIGH, confidence=Confidence.HIGH,
        languages=["java"],
        patterns=[RulePattern(pattern=pattern)],
    )


# ── nosec inline suppression tests ──

class TestNosecParsing:
    def test_parse_nosec_python_comment(self):
        result = PatternMatcher.parse_nosec('dangerous_call()  # nosec')
        assert result is not None
        assert len(result) == 0  # Suppress all

    def test_parse_nosec_java_comment(self):
        result = PatternMatcher.parse_nosec('dangerous_call();  // nosec')
        assert result is not None
        assert len(result) == 0

    def test_parse_nosec_with_rule_id(self):
        result = PatternMatcher.parse_nosec('code()  # nosec SQLI-001')
        assert result == {"SQLI-001"}

    def test_parse_nosec_multiple_rules(self):
        result = PatternMatcher.parse_nosec('code()  # nosec SQLI-001, PATH-001')
        assert result == {"SQLI-001", "PATH-001"}

    def test_parse_nosec_not_present(self):
        result = PatternMatcher.parse_nosec('safe_code()')
        assert result is None

    def test_parse_nosec_case_insensitive(self):
        result = PatternMatcher.parse_nosec('code()  # NOSEC')
        assert result is not None


class TestNosecSuppression:
    def test_nosec_suppresses_finding(self):
        matcher = PatternMatcher()
        code = 'stmt.executeQuery("SELECT * FROM users WHERE id=" + userId);  // nosec'
        rule = make_rule()
        findings = matcher.match_file(Path("Test.java"), code, [rule])
        assert len(findings) == 0

    def test_nosec_python_hash_comment(self):
        matcher = PatternMatcher()
        rule = make_rule("CMD-001", r'os\.system\s*\(.*\+.*\)')
        code = 'os.system("ls " + user_input)  # nosec'
        findings = matcher.match_file(Path("test.py"), code, [rule])
        assert len(findings) == 0

    def test_nosec_specific_rule_suppressed(self):
        matcher = PatternMatcher()
        code = 'stmt.executeQuery("SELECT * FROM " + id);  // nosec SQLI-001'
        rule = make_rule("SQLI-001")
        findings = matcher.match_file(Path("Test.java"), code, [rule])
        assert len(findings) == 0

    def test_nosec_different_rule_not_suppressed(self):
        matcher = PatternMatcher()
        code = 'stmt.executeQuery("SELECT * FROM " + id);  // nosec CMD-001'
        rule = make_rule("SQLI-001")
        findings = matcher.match_file(Path("Test.java"), code, [rule])
        assert len(findings) >= 1  # SQLI-001 not in nosec list

    def test_nosec_does_not_affect_other_lines(self):
        matcher = PatternMatcher()
        code = '''stmt.executeQuery("SELECT * FROM " + id1);
stmt.executeQuery("SELECT * FROM " + id2);  // nosec
stmt.executeQuery("SELECT * FROM " + id3);'''
        rule = make_rule()
        findings = matcher.match_file(Path("Test.java"), code, [rule])
        # Line 1 and 3 should still be flagged, line 2 suppressed
        assert len(findings) == 2


# ── .sentinelscanignore tests ──

class TestSentinelscanignore:
    def test_ignore_file_patterns(self, sample_rules_dir, tmp_path):
        # Create files
        (tmp_path / "main.java").write_text(
            'stmt.executeQuery("SELECT * FROM " + id);'
        )
        (tmp_path / "generated.java").write_text(
            'stmt.executeQuery("SELECT * FROM " + id);'
        )

        # Create .sentinelscanignore
        (tmp_path / ".sentinelscanignore").write_text("*generated*\n")

        scanner = create_scanner(rules_dir=str(sample_rules_dir))
        result = scanner.scan(str(tmp_path))
        files_in_findings = {f.location.file_path for f in result.findings}
        assert not any("generated" in f for f in files_in_findings)

    def test_ignore_glob_patterns(self, sample_rules_dir, tmp_path):
        test_dir = tmp_path / "tests"
        test_dir.mkdir()
        (test_dir / "TestUser.java").write_text(
            'stmt.executeQuery("SELECT * FROM " + id);'
        )
        (tmp_path / "Service.java").write_text(
            'stmt.executeQuery("SELECT * FROM " + id);'
        )

        (tmp_path / ".sentinelscanignore").write_text("**/tests/**\n")

        scanner = create_scanner(rules_dir=str(sample_rules_dir))
        result = scanner.scan(str(tmp_path))
        files_in_findings = {f.location.file_path for f in result.findings}
        assert not any("tests" in f for f in files_in_findings)

    def test_ignore_comments_and_blanks(self, sample_rules_dir, tmp_path):
        (tmp_path / "main.java").write_text(
            'stmt.executeQuery("SELECT * FROM " + id);'
        )
        (tmp_path / ".sentinelscanignore").write_text(
            "# This is a comment\n\n# Another comment\n"
        )

        scanner = create_scanner(rules_dir=str(sample_rules_dir))
        result = scanner.scan(str(tmp_path))
        # No patterns to exclude, so main.java should be scanned
        assert result.files_scanned >= 1

    def test_no_ignore_file(self, sample_rules_dir, tmp_path):
        (tmp_path / "main.java").write_text("public class Main {}")
        scanner = create_scanner(rules_dir=str(sample_rules_dir))
        result = scanner.scan(str(tmp_path))
        # Should still work without .sentinelscanignore
        assert result.files_scanned >= 1
