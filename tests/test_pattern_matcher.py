"""Tests for scanengine.pattern_matcher"""

import pytest
from pathlib import Path
from scanengine.pattern_matcher import PatternMatcher, SecretMatcher
from scanengine.models import Rule, RulePattern, Severity, Confidence, Remediation


def make_rule(rule_id, pattern, language=None, severity=Severity.HIGH,
              missing=None, case_insensitive=False):
    """Helper to create a rule with a single pattern."""
    return Rule(
        id=rule_id,
        name=f"Test {rule_id}",
        description=f"Test rule {rule_id}",
        severity=severity,
        confidence=Confidence.HIGH,
        languages=[language] if language else [],
        patterns=[
            RulePattern(
                pattern=pattern,
                language=language,
                missing=missing,
                case_insensitive=case_insensitive,
            )
        ],
    )


class TestPatternMatcher:
    def test_match_sql_injection_java(self):
        matcher = PatternMatcher()
        code = 'stmt.executeQuery("SELECT * FROM users WHERE id=" + userId);'
        rule = make_rule("SQLI-001", r'executeQuery\s*\(\s*.*\+\s*', "java")
        findings = matcher.match_file(Path("Test.java"), code, [rule])
        assert len(findings) >= 1
        assert findings[0].rule_id == "SQLI-001"

    def test_match_command_injection_python(self):
        matcher = PatternMatcher()
        code = 'os.system("ls " + user_input)'
        rule = make_rule("CMD-001", r'os\.system\s*\(.*\+.*\)', "python")
        findings = matcher.match_file(Path("test.py"), code, [rule])
        assert len(findings) >= 1

    def test_match_path_traversal(self):
        matcher = PatternMatcher()
        code = 'File file = new File("/uploads/" + filename);'
        rule = make_rule("PATH-001", r'new File\s*\(.*\+\s*', "java")
        findings = matcher.match_file(Path("Test.java"), code, [rule])
        assert len(findings) >= 1

    def test_no_match_on_safe_code(self):
        matcher = PatternMatcher()
        code = '''
        PreparedStatement stmt = conn.prepareStatement("SELECT * FROM users WHERE id=?");
        stmt.setString(1, userId);
        '''
        rule = make_rule("SQLI-001", r'executeQuery\s*\(\s*.*\+\s*', "java")
        findings = matcher.match_file(Path("Safe.java"), code, [rule])
        assert len(findings) == 0

    def test_case_insensitive_match(self):
        matcher = PatternMatcher()
        code = 'log.INFO("password: " + pass);'
        rule = make_rule("LOG-001", r'log\.(info|debug).*password',
                         case_insensitive=True)
        findings = matcher.match_file(Path("Test.java"), code, [rule])
        assert len(findings) >= 1

    def test_case_sensitive_no_match(self):
        matcher = PatternMatcher()
        code = 'log.INFO("password: " + pass);'
        rule = make_rule("LOG-001", r'log\.info.*password',
                         case_insensitive=False)
        findings = matcher.match_file(Path("Test.java"), code, [rule])
        assert len(findings) == 0

    def test_missing_pattern_suppresses_finding(self):
        matcher = PatternMatcher()
        code = '''
        String query = "SELECT * FROM users WHERE id=" + userId;
        PreparedStatement safe = conn.prepareStatement(query);
        '''
        rule = make_rule(
            "SQLI-001",
            r'SELECT.*\+\s*',
            missing=r'prepareStatement',
        )
        findings = matcher.match_file(Path("Test.java"), code, [rule])
        # The missing pattern IS present so finding should be suppressed
        assert len(findings) == 0

    def test_missing_pattern_not_present(self):
        matcher = PatternMatcher()
        code = 'String query = "SELECT * FROM users WHERE id=" + userId;'
        rule = make_rule(
            "SQLI-001",
            r'SELECT.*\+\s*',
            missing=r'prepareStatement',
        )
        findings = matcher.match_file(Path("Test.java"), code, [rule])
        # Missing pattern NOT present so finding should be reported
        assert len(findings) >= 1

    def test_multiple_matches_in_file(self):
        matcher = PatternMatcher()
        code = '''
        os.system("cmd1 " + input1)
        safe_call()
        os.system("cmd2 " + input2)
        '''
        rule = make_rule("CMD-001", r'os\.system\s*\(.*\+.*\)', "python")
        findings = matcher.match_file(Path("test.py"), code, [rule])
        assert len(findings) == 2

    def test_language_filter(self):
        matcher = PatternMatcher()
        code = 'os.system("cmd " + input)'
        rule = make_rule("CMD-001", r'os\.system\s*\(.*\+.*\)', "python")
        # Scanning a Java file with a Python-only rule
        findings = matcher.match_file(Path("Test.java"), code, [rule])
        assert len(findings) == 0


class TestSecretMatcher:
    def test_entropy_calculation(self):
        sm = SecretMatcher()
        # High entropy string (random-looking)
        high = sm.calculate_entropy("aB3$kL9mNpQ2rS5t")
        # Low entropy string (repetitive)
        low = sm.calculate_entropy("aaaaaaaaaa")
        assert high > low

    def test_high_entropy_detection(self):
        sm = SecretMatcher()
        assert sm.is_high_entropy("aB3kL9mNpQ2rS5tXwZ7yC4vE6fH8jK0")

    def test_low_entropy_not_flagged(self):
        sm = SecretMatcher()
        assert not sm.is_high_entropy("password")
        assert not sm.is_high_entropy("hello")

    def test_is_likely_secret_api_key(self):
        sm = SecretMatcher()
        assert sm.is_likely_secret("AKIAIOSFODNN7EXAMP1E")

    def test_is_likely_secret_normal_string(self):
        sm = SecretMatcher()
        assert not sm.is_likely_secret("password123")  # contains "password"
        assert not sm.is_likely_secret("true")  # too short (< 8)
        assert not sm.is_likely_secret("localhost:8080")  # contains "localhost"
