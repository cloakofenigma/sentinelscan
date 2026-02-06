"""
Pattern matcher - performs regex-based pattern matching on source code.

Enhanced with context-aware analysis to reduce false positives:
- Comment/string detection
- Safe pattern recognition
- Sanitizer detection
- Test file awareness

Example:
    matcher = PatternMatcher(context_aware=True)
    findings = matcher.match_file(path, content, rules)
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import (
    List, Optional, Tuple, Generator, Set, Dict,
    Pattern, Match, Any, TYPE_CHECKING
)
import logging

from .models import Rule, RulePattern, Finding, Location, Severity, Confidence

if TYPE_CHECKING:
    from re import Pattern as RePattern

logger = logging.getLogger(__name__)


# Patterns that indicate safe usage (reduce false positives)
SAFE_PATTERNS: Dict[str, List[str]] = {
    'sql_injection': [
        r'PreparedStatement',
        r'createQuery\s*\([^+]*\)',  # JPA without concatenation
        r'@Param\s*\(',  # MyBatis parameter binding
        r'\?\s*[,)]',  # Parameterized placeholder
        r':\w+',  # Named parameters
        r'setString\s*\(',
        r'setInt\s*\(',
        r'setParameter\s*\(',
    ],
    'command_injection': [
        r'ProcessBuilder\s*\(\s*Arrays\.asList',  # Safe array form
        r'new\s+String\s*\[\s*\]\s*\{',  # String array (safer)
        r'escapeshellarg',  # PHP sanitizer
        r'shlex\.quote',  # Python sanitizer
    ],
    'xss': [
        r'htmlEscape',
        r'escapeHtml',
        r'sanitize',
        r'encodeForHTML',
        r'textContent\s*=',  # Safe DOM assignment
        r'innerText\s*=',  # Safe text assignment
    ],
    'path_traversal': [
        r'getCanonicalPath',
        r'normalize\s*\(',
        r'Paths\.get\s*\([^,)]+\)',  # Single-arg Paths.get
        r'realpath',
    ],
}

# Comment patterns for different languages
COMMENT_PATTERNS = {
    'java': [r'//.*$', r'/\*.*?\*/'],
    'python': [r'#.*$', r'""".*?"""', r"'''.*?'''"],
    'javascript': [r'//.*$', r'/\*.*?\*/'],
    'go': [r'//.*$', r'/\*.*?\*/'],
    'ruby': [r'#.*$', r'=begin.*?=end'],
    'php': [r'//.*$', r'#.*$', r'/\*.*?\*/'],
}

# String literal patterns
STRING_PATTERNS = {
    'java': [r'"(?:[^"\\]|\\.)*"', r"'(?:[^'\\]|\\.)*'"],
    'python': [r'""".*?"""', r"'''.*?'''", r'"(?:[^"\\]|\\.)*"', r"'(?:[^'\\]|\\.)*'"],
    'javascript': [r'`(?:[^`\\]|\\.)*`', r'"(?:[^"\\]|\\.)*"', r"'(?:[^'\\]|\\.)*'"],
}


class PatternMatcher:
    """
    Regex-based pattern matching engine with context awareness.

    Features:
    - Language-specific pattern matching
    - Comment and string detection to reduce false positives
    - Safe pattern recognition
    - Nosec directive support
    - Test file filtering
    """

    # File extensions to language mapping
    EXTENSION_LANGUAGE_MAP = {
        '.java': 'java',
        '.py': 'python',
        '.js': 'javascript',
        '.jsx': 'javascript',
        '.ts': 'typescript',
        '.tsx': 'typescript',
        '.php': 'php',
        '.cs': 'csharp',
        '.go': 'go',
        '.rb': 'ruby',
        '.xml': 'xml',
        '.yml': 'yaml',
        '.yaml': 'yaml',
        '.properties': 'properties',
        '.html': 'html',
        '.htm': 'html',
        '.json': 'json',
        '.gradle': 'gradle',
        '.kt': 'kotlin',
        '.scala': 'scala',
    }

    def __init__(self, context_aware: bool = True, skip_tests: bool = False):
        """
        Initialize pattern matcher.

        Args:
            context_aware: Enable context-aware analysis to reduce false positives
            skip_tests: Skip findings in test files
        """
        self._compiled_patterns: dict = {}
        self._context_aware = context_aware
        self._skip_tests = skip_tests
        self._comment_cache: Dict[str, Set[int]] = {}  # file -> set of comment line numbers

    def match_file(self, filepath: Path, content: str, rules: List[Rule]) -> List[Finding]:
        """Match all applicable rules against a file's content"""
        findings = []
        file_language = self._get_language(filepath)

        # Skip test files if configured
        if self._skip_tests and self._is_test_file(filepath):
            logger.debug(f"Skipping test file: {filepath}")
            return findings

        for rule in rules:
            if not rule.enabled:
                continue

            if not rule.applies_to_file(filepath):
                continue

            try:
                rule_findings = self._match_rule(filepath, content, rule, file_language)
                findings.extend(rule_findings)
            except Exception as e:
                logger.warning(f"Error matching rule {rule.id} against {filepath}: {e}")

        return findings

    def _match_rule(self, filepath: Path, content: str, rule: Rule,
                    file_language: str) -> List[Finding]:
        """Match a single rule against file content with context awareness"""
        findings = []
        lines = content.splitlines()
        vuln_type = self._get_vuln_type_from_rule(rule)

        for pattern in rule.patterns:
            # Check if pattern applies to this language
            if pattern.language and pattern.language.lower() != file_language:
                continue

            try:
                matches = self._find_matches(content, lines, pattern)

                for line_num, line_content, match_text in matches:
                    # Calculate match position for context checks
                    match_pos = sum(len(lines[i]) + 1 for i in range(line_num - 1)) if line_num > 0 else 0

                    # Check for "missing" condition - skip if the pattern that should be missing is found
                    if pattern.missing:
                        if self._check_missing_pattern(content, pattern.missing):
                            continue

                    # Check for nosec suppression
                    if self._is_nosec_suppressed(line_content, rule.id):
                        continue

                    # Context-aware false positive reduction
                    if self._context_aware:
                        # Skip if in comment
                        if self._is_in_comment(content, match_pos, file_language):
                            logger.debug(f"Skipping match in comment: {rule.id} at line {line_num}")
                            continue

                        # Skip if safe pattern is present nearby
                        if vuln_type and self._has_safe_pattern(content, line_num, vuln_type):
                            logger.debug(f"Skipping match with safe pattern: {rule.id} at line {line_num}")
                            continue

                    finding = Finding(
                        rule_id=rule.id,
                        rule_name=rule.name,
                        description=rule.description,
                        severity=rule.severity,
                        confidence=rule.confidence,
                        location=Location(
                            file_path=str(filepath),
                            line_number=line_num,
                            snippet=line_content.strip()[:200],
                        ),
                        cwe=rule.cwe,
                        owasp=rule.owasp,
                        matched_pattern=match_text[:100] if match_text else None,
                        remediation=rule.remediation.description if rule.remediation else None,
                        references=rule.references,
                        tags=rule.tags,
                    )
                    findings.append(finding)

            except re.error as e:
                logger.warning(f"Invalid regex pattern in rule {rule.id}: {e}")

        return findings

    def _find_matches(self, content: str, lines: List[str],
                      pattern: RulePattern) -> Generator[Tuple[int, str, str], None, None]:
        """Find all matches for a pattern in content"""
        regex_flags = re.MULTILINE
        if pattern.case_insensitive:
            regex_flags |= re.IGNORECASE

        compiled = self._get_compiled_pattern(pattern.pattern, regex_flags)
        if not compiled:
            return

        # Find all matches
        for match in compiled.finditer(content):
            match_start = match.start()
            match_text = match.group(0)

            # Calculate line number
            line_num = content[:match_start].count('\n') + 1

            # Get the line content
            if 0 < line_num <= len(lines):
                line_content = lines[line_num - 1]
            else:
                line_content = match_text

            yield line_num, line_content, match_text

    def _check_missing_pattern(self, content: str, missing_pattern: str) -> bool:
        """Check if a 'missing' pattern exists in content"""
        # The missing pattern can have multiple alternatives separated by |
        patterns = missing_pattern.split('|')
        for p in patterns:
            p = p.strip()
            if not p:
                continue
            try:
                if re.search(p, content, re.IGNORECASE):
                    return True
            except re.error:
                # Try as literal string
                if p in content:
                    return True
        return False

    def _get_compiled_pattern(self, pattern: str, flags: int) -> Optional[re.Pattern]:
        """Get or compile a regex pattern"""
        cache_key = (pattern, flags)
        if cache_key not in self._compiled_patterns:
            try:
                self._compiled_patterns[cache_key] = re.compile(pattern, flags)
            except re.error as e:
                logger.warning(f"Failed to compile pattern '{pattern}': {e}")
                self._compiled_patterns[cache_key] = None

        return self._compiled_patterns[cache_key]

    @staticmethod
    def parse_nosec(line: str) -> Optional[Set[str]]:
        """
        Parse nosec directive from a line.

        Returns:
            None if no nosec directive found.
            Empty set if nosec suppresses all rules.
            Set of rule IDs if nosec targets specific rules.
        """
        # Match # nosec, // nosec, /* nosec */
        m = re.search(r'(?:#|//|/\*)\s*nosec\b\s*([\w,\s-]*)', line, re.IGNORECASE)
        if not m:
            return None

        rule_str = m.group(1).strip().rstrip('*').rstrip('/').strip()
        if not rule_str:
            return set()  # Suppress all

        # Parse comma-separated rule IDs
        return {r.strip() for r in rule_str.split(',') if r.strip()}

    def _is_nosec_suppressed(self, line: str, rule_id: str) -> bool:
        """Check if a line has a nosec directive that suppresses the given rule."""
        result = self.parse_nosec(line)
        if result is None:
            return False
        if len(result) == 0:
            return True  # Suppress all
        return rule_id in result

    def _get_language(self, filepath: Path) -> str:
        """Determine the language from file extension"""
        suffix = filepath.suffix.lower()
        return self.EXTENSION_LANGUAGE_MAP.get(suffix, 'unknown')

    def _is_test_file(self, filepath: Path) -> bool:
        """Check if file is a test file"""
        name = filepath.name.lower()
        path_str = str(filepath).lower()
        test_indicators = [
            'test_', '_test.', 'test.', 'tests/', '/test/',
            'spec_', '_spec.', 'spec.', 'specs/', '/spec/',
            '__tests__', 'testing/', '/testing/',
        ]
        return any(ind in name or ind in path_str for ind in test_indicators)

    def _is_in_comment(self, content: str, position: int, language: str) -> bool:
        """Check if a position in content is inside a comment"""
        if not self._context_aware:
            return False

        patterns = COMMENT_PATTERNS.get(language, COMMENT_PATTERNS.get('java', []))
        line_start = content.rfind('\n', 0, position) + 1
        line_end = content.find('\n', position)
        if line_end == -1:
            line_end = len(content)
        line = content[line_start:line_end]

        # Check single-line comment
        for pattern in patterns:
            if '//' in pattern or '#' in pattern:
                try:
                    match = re.search(pattern, line)
                    if match and line_start + match.start() < position:
                        return True
                except re.error:
                    pass

        # Check multi-line comments
        for pattern in patterns:
            if '/*' in pattern or '"""' in pattern or "'''" in pattern:
                try:
                    for match in re.finditer(pattern, content, re.DOTALL):
                        if match.start() <= position <= match.end():
                            return True
                except re.error:
                    pass

        return False

    def _is_in_string_literal(self, content: str, position: int, language: str) -> bool:
        """Check if position is inside a string literal"""
        if not self._context_aware:
            return False

        patterns = STRING_PATTERNS.get(language, STRING_PATTERNS.get('java', []))

        for pattern in patterns:
            try:
                for match in re.finditer(pattern, content, re.DOTALL):
                    # Don't count match starting at position (the pattern itself might be a string)
                    if match.start() < position < match.end():
                        return True
            except re.error:
                pass

        return False

    def _has_safe_pattern(self, content: str, line_num: int, vuln_type: str) -> bool:
        """Check if the surrounding context contains safe patterns"""
        if not self._context_aware:
            return False

        safe_patterns = SAFE_PATTERNS.get(vuln_type, [])
        if not safe_patterns:
            return False

        lines = content.splitlines()
        # Check current line and nearby lines (context window of 5 lines)
        start = max(0, line_num - 3)
        end = min(len(lines), line_num + 2)
        context = '\n'.join(lines[start:end])

        for pattern in safe_patterns:
            try:
                if re.search(pattern, context, re.IGNORECASE):
                    return True
            except re.error:
                pass

        return False

    def _get_vuln_type_from_rule(self, rule: Rule) -> Optional[str]:
        """Extract vulnerability type from rule ID or tags"""
        rule_id_lower = rule.id.lower()
        tags_lower = [t.lower() for t in (rule.tags or [])]

        type_map = {
            'sqli': 'sql_injection',
            'sql': 'sql_injection',
            'cmdi': 'command_injection',
            'cmd': 'command_injection',
            'command': 'command_injection',
            'xss': 'xss',
            'cross-site': 'xss',
            'path': 'path_traversal',
            'traversal': 'path_traversal',
            'lfi': 'path_traversal',
        }

        for key, vuln_type in type_map.items():
            if key in rule_id_lower or any(key in t for t in tags_lower):
                return vuln_type

        return None


class SecretMatcher(PatternMatcher):
    """Specialized matcher for secrets with entropy checking"""

    # High-entropy character sets
    HEX_CHARS = set('0123456789abcdefABCDEF')
    BASE64_CHARS = set('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=')

    def __init__(self, entropy_threshold: float = 3.5):
        super().__init__()
        self.entropy_threshold = entropy_threshold

    def calculate_entropy(self, data: str) -> float:
        """Calculate Shannon entropy of a string"""
        import math
        if not data:
            return 0.0

        entropy = 0.0
        for char_count in [data.count(c) for c in set(data)]:
            if char_count > 0:
                freq = char_count / len(data)
                entropy -= freq * math.log2(freq)

        return entropy

    def is_high_entropy(self, data: str, min_length: int = 20) -> bool:
        """Check if string has high entropy (likely a secret)"""
        if len(data) < min_length:
            return False

        entropy = self.calculate_entropy(data)
        return entropy >= self.entropy_threshold

    def is_likely_secret(self, value: str) -> bool:
        """Determine if a value is likely a secret based on characteristics"""
        if len(value) < 8:
            return False

        # Check for common non-secret patterns
        non_secrets = [
            'example', 'sample', 'test', 'demo', 'placeholder',
            'your_', 'xxx', 'changeme', 'password', 'secret',
            'localhost', 'http://', 'https://',
        ]
        value_lower = value.lower()
        for ns in non_secrets:
            if ns in value_lower:
                return False

        # Check entropy for longer strings
        if len(value) >= 20:
            return self.is_high_entropy(value)

        return True

    def match_file(self, filepath: Path, content: str, rules: List[Rule]) -> List[Finding]:
        """Match with additional entropy-based filtering for secrets"""
        findings = super().match_file(filepath, content, rules)

        # Additional entropy-based secret detection for generic patterns
        filtered_findings = []
        for finding in findings:
            # For secret rules, verify entropy
            if 'secret' in finding.tags or 'credentials' in finding.tags:
                matched = finding.matched_pattern or ''
                # Extract potential secret value from match
                if '=' in matched:
                    value = matched.split('=', 1)[-1].strip().strip('"\'')
                    if not self.is_likely_secret(value):
                        continue

            filtered_findings.append(finding)

        return filtered_findings
