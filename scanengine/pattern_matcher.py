"""
Pattern matcher - performs regex-based pattern matching on source code
"""

import re
from pathlib import Path
from typing import List, Optional, Tuple, Generator, Set
import logging

from .models import Rule, RulePattern, Finding, Location, Severity, Confidence

logger = logging.getLogger(__name__)


class PatternMatcher:
    """Regex-based pattern matching engine"""

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

    def __init__(self):
        self._compiled_patterns: dict = {}

    def match_file(self, filepath: Path, content: str, rules: List[Rule]) -> List[Finding]:
        """Match all applicable rules against a file's content"""
        findings = []
        file_language = self._get_language(filepath)

        for rule in rules:
            if not rule.enabled:
                continue

            if not rule.applies_to_file(filepath):
                continue

            rule_findings = self._match_rule(filepath, content, rule, file_language)
            findings.extend(rule_findings)

        return findings

    def _match_rule(self, filepath: Path, content: str, rule: Rule,
                    file_language: str) -> List[Finding]:
        """Match a single rule against file content"""
        findings = []
        lines = content.splitlines()

        for pattern in rule.patterns:
            # Check if pattern applies to this language
            if pattern.language and pattern.language.lower() != file_language:
                continue

            try:
                matches = self._find_matches(content, lines, pattern)

                for line_num, line_content, match_text in matches:
                    # Check for "missing" condition - skip if the pattern that should be missing is found
                    if pattern.missing:
                        if self._check_missing_pattern(content, pattern.missing):
                            continue

                    # Check for nosec suppression
                    if self._is_nosec_suppressed(line_content, rule.id):
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
