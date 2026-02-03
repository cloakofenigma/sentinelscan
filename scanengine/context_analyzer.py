"""
Context Analyzer - Reduces false positives through context-aware filtering
"""

import re
from pathlib import Path
from typing import List, Set, Optional, Dict, Any
from dataclasses import dataclass, field

from .models import Finding, Severity, Confidence


@dataclass
class FileContext:
    """Context information about a file"""
    filepath: Path
    is_test_file: bool = False
    is_example_file: bool = False
    is_config_file: bool = False
    is_generated_file: bool = False
    is_vendor_file: bool = False
    language: str = "unknown"
    framework: Optional[str] = None


class ContextAnalyzer:
    """Analyzes file and code context to reduce false positives"""

    # Patterns indicating test files
    TEST_PATH_PATTERNS = [
        r'/test/', r'/tests/', r'/spec/', r'/specs/',
        r'/__tests__/', r'/testing/', r'/test_',
        r'_test\.', r'_spec\.', r'Test\.java$', r'Tests\.java$',
        r'test_.*\.py$', r'.*_test\.py$', r'.*_test\.go$',
        r'\.spec\.(js|ts)$', r'\.test\.(js|ts)$',
    ]

    # Patterns indicating example/sample files
    EXAMPLE_PATH_PATTERNS = [
        r'/example/', r'/examples/', r'/sample/', r'/samples/',
        r'/demo/', r'/demos/', r'/mock/', r'/mocks/',
        r'/fixture/', r'/fixtures/', r'/stub/', r'/stubs/',
        r'example\.', r'sample\.', r'demo\.',
    ]

    # Patterns indicating generated files
    GENERATED_PATTERNS = [
        r'/generated/', r'/gen/', r'/build/', r'/dist/',
        r'/target/', r'/out/', r'\.generated\.',
        r'# Generated', r'// Generated', r'/* Generated',
        r'# AUTO-GENERATED', r'// AUTO-GENERATED',
        r'@Generated', r'@javax\.annotation\.Generated',
    ]

    # Patterns indicating vendor/third-party files
    VENDOR_PATTERNS = [
        r'/vendor/', r'/node_modules/', r'/bower_components/',
        r'/third_party/', r'/thirdparty/', r'/external/',
        r'/lib/', r'/libs/', r'\.min\.(js|css)$',
    ]

    # File content patterns indicating non-production context
    NON_PROD_CONTENT_PATTERNS = [
        r'TODO:', r'FIXME:', r'XXX:', r'HACK:',
        r'for\s+testing', r'test\s+only', r'example\s+only',
        r'do\s+not\s+use\s+in\s+production',
        r'placeholder', r'dummy', r'fake',
    ]

    # Patterns for common false positive scenarios
    FALSE_POSITIVE_PATTERNS = {
        'secret': [
            # Documentation/comments about secrets
            r'//.*secret', r'#.*secret', r'/\*.*secret',
            r'\*.*secret', r'\'\'\'.*secret', r'""".*secret',
            # Variable names that are not actual secrets
            r'secret_?name', r'secret_?id', r'secret_?type',
            r'has_?secret', r'is_?secret', r'use_?secret',
            # Method/function definitions
            r'def\s+.*secret', r'function\s+.*secret',
            r'public\s+.*\s+.*[Ss]ecret',
        ],
        'password': [
            # Password field names, not values
            r'password_?field', r'password_?input', r'password_?label',
            r'password_?placeholder', r'password_?hint',
            r'password_?policy', r'password_?strength',
            r'password_?hash', r'password_?encoder',
            r'["\']password["\']', r'name=["\']password',
            # Reset/change password (not hardcoded)
            r'reset_?password', r'change_?password', r'forgot_?password',
        ],
        'sql-injection': [
            # MyBatis legitimate ${} usage for table/column names
            r'\$\{prefix\}', r'\$\{suffix\}', r'\$\{tableName\}',
            r'\$\{tablePrefix\}', r'\$\{schema\}', r'\$\{catalog\}',
            # Maven/Gradle properties
            r'\$\{project\.', r'\$\{maven\.', r'\$\{gradle\.',
            r'\$\{java\.', r'\$\{user\.', r'\$\{env\.',
        ],
    }

    def __init__(self):
        self._compiled_patterns: Dict[str, List[re.Pattern]] = {}
        self._compile_patterns()

    def _compile_patterns(self) -> None:
        """Pre-compile regex patterns for performance"""
        self._test_patterns = [re.compile(p, re.IGNORECASE) for p in self.TEST_PATH_PATTERNS]
        self._example_patterns = [re.compile(p, re.IGNORECASE) for p in self.EXAMPLE_PATH_PATTERNS]
        self._generated_patterns = [re.compile(p, re.IGNORECASE) for p in self.GENERATED_PATTERNS]
        self._vendor_patterns = [re.compile(p, re.IGNORECASE) for p in self.VENDOR_PATTERNS]
        self._non_prod_patterns = [re.compile(p, re.IGNORECASE) for p in self.NON_PROD_CONTENT_PATTERNS]

        for category, patterns in self.FALSE_POSITIVE_PATTERNS.items():
            self._compiled_patterns[category] = [
                re.compile(p, re.IGNORECASE) for p in patterns
            ]

    def analyze_file_context(self, filepath: Path, content: Optional[str] = None) -> FileContext:
        """Analyze file to determine its context"""
        filepath_str = str(filepath)

        context = FileContext(filepath=filepath)

        # Check path patterns
        context.is_test_file = any(p.search(filepath_str) for p in self._test_patterns)
        context.is_example_file = any(p.search(filepath_str) for p in self._example_patterns)
        context.is_vendor_file = any(p.search(filepath_str) for p in self._vendor_patterns)

        # Check content patterns if content provided
        if content:
            # Check for generated file markers
            content_preview = content[:2000]  # Only check first 2KB
            context.is_generated_file = any(
                p.search(content_preview) for p in self._generated_patterns
            )

        # Determine language
        context.language = self._detect_language(filepath)

        # Detect framework
        context.framework = self._detect_framework(filepath, content)

        # Check if config file
        context.is_config_file = self._is_config_file(filepath)

        return context

    def _detect_language(self, filepath: Path) -> str:
        """Detect programming language from file extension"""
        ext_map = {
            '.java': 'java',
            '.py': 'python',
            '.js': 'javascript',
            '.ts': 'typescript',
            '.jsx': 'javascript',
            '.tsx': 'typescript',
            '.php': 'php',
            '.rb': 'ruby',
            '.go': 'go',
            '.cs': 'csharp',
            '.kt': 'kotlin',
            '.scala': 'scala',
            '.xml': 'xml',
            '.yml': 'yaml',
            '.yaml': 'yaml',
            '.json': 'json',
            '.properties': 'properties',
        }
        return ext_map.get(filepath.suffix.lower(), 'unknown')

    def _detect_framework(self, filepath: Path, content: Optional[str] = None) -> Optional[str]:
        """Detect framework from file path and content"""
        filepath_str = str(filepath).lower()

        # Spring Boot indicators
        if any(x in filepath_str for x in ['spring', 'boot']):
            return 'spring'
        if filepath.name in ['application.properties', 'application.yml', 'application.yaml']:
            return 'spring'

        # Django indicators
        if any(x in filepath_str for x in ['django', 'settings.py', 'urls.py', 'views.py']):
            return 'django'

        # Express/Node indicators
        if 'express' in filepath_str or filepath.name == 'app.js':
            return 'express'

        # Laravel indicators
        if any(x in filepath_str for x in ['laravel', 'artisan']):
            return 'laravel'

        # Check content for framework imports
        if content:
            content_preview = content[:5000]
            if 'org.springframework' in content_preview:
                return 'spring'
            if 'from django' in content_preview or 'import django' in content_preview:
                return 'django'
            if "require('express')" in content_preview or 'from "express"' in content_preview:
                return 'express'

        return None

    def _is_config_file(self, filepath: Path) -> bool:
        """Check if file is a configuration file"""
        config_names = {
            'application.properties', 'application.yml', 'application.yaml',
            'config.yml', 'config.yaml', 'config.json',
            '.env', '.env.example', '.env.local', '.env.development',
            'settings.py', 'settings.json',
            'docker-compose.yml', 'docker-compose.yaml',
            'Dockerfile', 'Jenkinsfile', 'Makefile',
            'pom.xml', 'build.gradle', 'package.json',
            'requirements.txt', 'Pipfile', 'Gemfile',
        }
        return filepath.name in config_names

    def filter_false_positives(self, findings: List[Finding],
                                file_contexts: Dict[str, FileContext],
                                content_cache: Dict[str, str]) -> List[Finding]:
        """Filter out likely false positives from findings"""
        filtered = []

        for finding in findings:
            if self._is_likely_false_positive(finding, file_contexts, content_cache):
                continue
            filtered.append(finding)

        return filtered

    def _is_likely_false_positive(self, finding: Finding,
                                   file_contexts: Dict[str, FileContext],
                                   content_cache: Dict[str, str]) -> bool:
        """Determine if a finding is likely a false positive"""
        filepath = finding.location.file_path
        context = file_contexts.get(filepath)

        # Get the matched line content
        snippet = finding.location.snippet or ""
        line_num = finding.location.line_number

        # Get surrounding context if available
        content = content_cache.get(filepath, "")
        surrounding = self._get_surrounding_lines(content, line_num, context_lines=3)

        # Rule-specific false positive checks
        for tag in finding.tags:
            if tag in self._compiled_patterns:
                for pattern in self._compiled_patterns[tag]:
                    if pattern.search(snippet) or pattern.search(surrounding):
                        return True

        # Check for comment context (finding in a comment)
        if self._is_in_comment(snippet, context.language if context else 'unknown'):
            # Lower severity findings in comments are likely FPs
            if finding.severity in [Severity.LOW, Severity.MEDIUM]:
                return True

        # Test file context - be more lenient
        if context and context.is_test_file:
            # Hardcoded credentials in test files are often intentional test data
            if 'credentials' in finding.tags or 'secret' in finding.tags:
                # Check if it's clearly test data
                if self._is_test_data(snippet):
                    return True

        # Example/sample files - very lenient
        if context and context.is_example_file:
            return True

        # Generated files - skip most findings
        if context and context.is_generated_file:
            return True

        # Vendor files - skip
        if context and context.is_vendor_file:
            return True

        return False

    def _get_surrounding_lines(self, content: str, line_num: int, context_lines: int = 3) -> str:
        """Get lines surrounding the finding"""
        if not content:
            return ""

        lines = content.splitlines()
        start = max(0, line_num - context_lines - 1)
        end = min(len(lines), line_num + context_lines)

        return "\n".join(lines[start:end])

    def _is_in_comment(self, line: str, language: str) -> bool:
        """Check if line is a comment"""
        line = line.strip()

        # Single line comments
        if language in ['java', 'javascript', 'typescript', 'csharp', 'go', 'kotlin', 'scala']:
            if line.startswith('//') or line.startswith('/*') or line.startswith('*'):
                return True
        elif language in ['python', 'ruby', 'yaml', 'properties']:
            if line.startswith('#'):
                return True
        elif language == 'xml':
            if line.startswith('<!--'):
                return True

        return False

    def _is_test_data(self, snippet: str) -> bool:
        """Check if snippet contains obvious test data"""
        test_data_indicators = [
            'test', 'mock', 'fake', 'dummy', 'sample', 'example',
            'fixture', 'stub', '123456', 'abcdef', 'foobar',
            'lorem', 'ipsum', 'xxx', 'yyy', 'zzz',
        ]
        snippet_lower = snippet.lower()
        return any(ind in snippet_lower for ind in test_data_indicators)

    def adjust_confidence(self, finding: Finding, context: Optional[FileContext]) -> Finding:
        """Adjust finding confidence based on context"""
        if not context:
            return finding

        # Lower confidence for test files
        if context.is_test_file:
            if finding.confidence == Confidence.HIGH:
                finding.confidence = Confidence.MEDIUM
            elif finding.confidence == Confidence.MEDIUM:
                finding.confidence = Confidence.LOW

        # Lower confidence for example files
        if context.is_example_file:
            finding.confidence = Confidence.LOW

        return finding


class EntropyAnalyzer:
    """Analyzes entropy to validate potential secrets"""

    def __init__(self, threshold: float = 4.0):
        self.threshold = threshold

    def calculate_entropy(self, data: str) -> float:
        """Calculate Shannon entropy"""
        import math
        if not data:
            return 0.0

        entropy = 0.0
        for char_count in [data.count(c) for c in set(data)]:
            if char_count > 0:
                freq = char_count / len(data)
                entropy -= freq * math.log2(freq)

        return entropy

    def is_high_entropy(self, value: str, min_length: int = 16) -> bool:
        """Check if value has high entropy (likely a real secret)"""
        if len(value) < min_length:
            return False
        return self.calculate_entropy(value) >= self.threshold

    def extract_secret_value(self, snippet: str) -> Optional[str]:
        """Extract potential secret value from code snippet"""
        # Common patterns for extracting values
        patterns = [
            r'["\']([A-Za-z0-9+/=_-]{20,})["\']',  # Quoted string
            r'=\s*["\']?([A-Za-z0-9+/=_-]{20,})["\']?',  # Assignment
        ]

        for pattern in patterns:
            match = re.search(pattern, snippet)
            if match:
                return match.group(1)

        return None

    def validate_secret_finding(self, finding: Finding) -> bool:
        """Validate if a secret finding is likely real"""
        snippet = finding.location.snippet or ""

        # Extract the potential secret value
        value = self.extract_secret_value(snippet)
        if not value:
            return True  # Can't validate, keep the finding

        # Check for obvious non-secrets
        non_secrets = [
            'example', 'sample', 'test', 'demo', 'placeholder',
            'your_', 'xxx', 'changeme', 'password', 'secret',
            'localhost', 'undefined', 'null', 'none',
        ]
        value_lower = value.lower()
        if any(ns in value_lower for ns in non_secrets):
            return False

        # Check entropy for longer strings
        if len(value) >= 20:
            return self.is_high_entropy(value)

        return True
