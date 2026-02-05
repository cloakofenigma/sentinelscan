"""
PHP Language Analyzer for SentinelScan.

Provides security analysis for PHP applications.
"""

import re
import logging
from typing import Dict, List, Set, Optional, Tuple
from pathlib import Path

from ..base import LanguageAnalyzer, AnalyzerCapabilities, ClassInfo, FunctionInfo, MethodCall
from ..registry import AnalyzerRegistry
from ...models import Finding, Severity, Confidence

logger = logging.getLogger(__name__)


@AnalyzerRegistry.register_language('.php', '.phtml', '.php5', '.php7')
class PHPAnalyzer(LanguageAnalyzer):
    """PHP-specific security analyzer."""

    DANGEROUS_SINKS = {
        'sql_injection': [
            'mysql_query', 'mysqli_query', 'pg_query', 'sqlite_query',
            'query', 'exec', 'prepare',
            'DB::raw', 'whereRaw', 'selectRaw', 'orderByRaw',
        ],
        'command_injection': [
            'exec', 'shell_exec', 'system', 'passthru', 'popen', 'proc_open',
            'pcntl_exec', 'backticks',
        ],
        'path_traversal': [
            'file_get_contents', 'file_put_contents', 'fopen', 'readfile',
            'include', 'include_once', 'require', 'require_once',
            'file', 'fread', 'fwrite', 'unlink', 'copy', 'rename',
        ],
        'ssrf': [
            'file_get_contents', 'curl_exec', 'fopen',
            'Http::get', 'Http::post',
        ],
        'deserialization': [
            'unserialize', 'maybe_unserialize',
        ],
        'xss': [
            'echo', 'print', 'printf',
        ],
        'code_injection': [
            'eval', 'assert', 'create_function', 'preg_replace',
        ],
    }

    TAINT_SOURCES = [
        r'\$_GET',
        r'\$_POST',
        r'\$_REQUEST',
        r'\$_COOKIE',
        r'\$_SERVER',
        r'\$_FILES',
        r'\$_ENV',
        r'request\(\)',
        r'input\(',
        r'\$request->',
    ]

    @property
    def name(self) -> str:
        return "php_analyzer"

    @property
    def language_name(self) -> str:
        return "php"

    @property
    def tree_sitter_module(self) -> Optional[str]:
        return "tree_sitter_php"

    @property
    def supported_extensions(self) -> Set[str]:
        return {'.php', '.phtml', '.php5', '.php7'}

    @property
    def capabilities(self) -> AnalyzerCapabilities:
        return AnalyzerCapabilities(supports_ast=self._tree_sitter_available, supports_taint_tracking=True)

    @property
    def dangerous_sinks(self) -> Dict[str, List[str]]:
        return self.DANGEROUS_SINKS

    @property
    def taint_sources(self) -> List[str]:
        return self.TAINT_SOURCES

    def analyze_file(self, file_path: Path, content: str) -> List[Finding]:
        findings = []
        findings.extend(self._check_sql_injection(file_path, content))
        findings.extend(self._check_command_injection(file_path, content))
        findings.extend(self._check_xss(file_path, content))
        findings.extend(self._check_file_inclusion(file_path, content))
        findings.extend(self._check_deserialization(file_path, content))
        findings.extend(self._check_code_injection(file_path, content))
        return findings

    def analyze_files(self, files: List[Path], content_cache: Dict[str, str]) -> List[Finding]:
        findings = []
        for file_path in files:
            if self.can_analyze(file_path):
                content = content_cache.get(str(file_path), "")
                if content:
                    findings.extend(self.analyze_file(file_path, content))
        return findings

    def get_classes(self, code: str) -> List[ClassInfo]:
        classes = []
        pattern = r'class\s+(\w+)'
        for match in re.finditer(pattern, code):
            classes.append(ClassInfo(name=match.group(1), file_path="", line_number=code[:match.start()].count('\n') + 1))
        return classes

    def get_functions(self, code: str) -> List[FunctionInfo]:
        functions = []
        pattern = r'function\s+(\w+)\s*\('
        for match in re.finditer(pattern, code):
            functions.append(FunctionInfo(name=match.group(1), file_path="", line_number=code[:match.start()].count('\n') + 1))
        return functions

    def get_method_calls(self, code: str) -> List[MethodCall]:
        calls = []
        pattern = r'(\$?\w+(?:->|\:\:)\w+)\s*\(([^)]*)\)'
        for match in re.finditer(pattern, code):
            calls.append(MethodCall(
                name=match.group(1),
                object_name=None,
                arguments=[match.group(2)] if match.group(2) else [],
                line_number=code[:match.start()].count('\n') + 1,
                file_path="",
                full_expression=match.group(0),
            ))
        return calls

    def get_string_literals(self, code: str) -> List[Tuple[str, int]]:
        strings = []
        pattern = r'["\']([^"\']*)["\']'
        for match in re.finditer(pattern, code):
            strings.append((match.group(1), code[:match.start()].count('\n') + 1))
        return strings

    def _check_sql_injection(self, file_path: Path, content: str) -> List[Finding]:
        findings = []
        patterns = [
            r'(?:mysql_query|mysqli_query|pg_query)\s*\([^)]*\$_(?:GET|POST|REQUEST)',
            r'->(?:query|exec)\s*\([^)]*\$_(?:GET|POST|REQUEST)',
            r'(?:whereRaw|selectRaw|orderByRaw|DB::raw)\s*\([^)]*\$',
        ]
        for pattern in patterns:
            for match in re.finditer(pattern, content):
                line_num = content[:match.start()].count('\n') + 1
                findings.append(self._create_finding(
                    rule_id='PHP-SQLI-001',
                    title='SQL Injection',
                    description='SQL query with user input',
                    file_path=file_path,
                    line_number=line_num,
                    severity=Severity.CRITICAL,
                    confidence=Confidence.HIGH,
                    cwe='CWE-89',
                    owasp='A03',
                ))
        return findings

    def _check_command_injection(self, file_path: Path, content: str) -> List[Finding]:
        findings = []
        patterns = [
            r'(?:exec|shell_exec|system|passthru|popen)\s*\([^)]*\$_(?:GET|POST|REQUEST)',
            r'`[^`]*\$_(?:GET|POST|REQUEST)',
        ]
        for pattern in patterns:
            for match in re.finditer(pattern, content):
                line_num = content[:match.start()].count('\n') + 1
                findings.append(self._create_finding(
                    rule_id='PHP-CMDI-001',
                    title='Command Injection',
                    description='Command execution with user input',
                    file_path=file_path,
                    line_number=line_num,
                    severity=Severity.CRITICAL,
                    confidence=Confidence.HIGH,
                    cwe='CWE-78',
                    owasp='A03',
                ))
        return findings

    def _check_xss(self, file_path: Path, content: str) -> List[Finding]:
        findings = []
        patterns = [
            r'echo\s+\$_(?:GET|POST|REQUEST)\[',
            r'print\s+\$_(?:GET|POST|REQUEST)\[',
            r'<?=\s*\$_(?:GET|POST|REQUEST)\[',
        ]
        for pattern in patterns:
            for match in re.finditer(pattern, content):
                line_num = content[:match.start()].count('\n') + 1
                findings.append(self._create_finding(
                    rule_id='PHP-XSS-001',
                    title='Cross-Site Scripting (XSS)',
                    description='Unescaped user input in output',
                    file_path=file_path,
                    line_number=line_num,
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    cwe='CWE-79',
                    owasp='A03',
                    remediation='Use htmlspecialchars() or htmlentities() to escape output',
                ))
        return findings

    def _check_file_inclusion(self, file_path: Path, content: str) -> List[Finding]:
        findings = []
        patterns = [
            r'(?:include|require)(?:_once)?\s*\([^)]*\$_(?:GET|POST|REQUEST)',
            r'(?:include|require)(?:_once)?\s+\$_(?:GET|POST|REQUEST)',
        ]
        for pattern in patterns:
            for match in re.finditer(pattern, content):
                line_num = content[:match.start()].count('\n') + 1
                findings.append(self._create_finding(
                    rule_id='PHP-LFI-001',
                    title='Local/Remote File Inclusion',
                    description='File inclusion with user-controlled path',
                    file_path=file_path,
                    line_number=line_num,
                    severity=Severity.CRITICAL,
                    confidence=Confidence.HIGH,
                    cwe='CWE-98',
                    owasp='A03',
                ))
        return findings

    def _check_deserialization(self, file_path: Path, content: str) -> List[Finding]:
        findings = []
        if 'unserialize' in content:
            patterns = [
                r'unserialize\s*\([^)]*\$_(?:GET|POST|REQUEST|COOKIE)',
                r'unserialize\s*\(\s*\$',
            ]
            for pattern in patterns:
                for match in re.finditer(pattern, content):
                    line_num = content[:match.start()].count('\n') + 1
                    findings.append(self._create_finding(
                        rule_id='PHP-DESER-001',
                        title='Insecure Deserialization',
                        description='unserialize() with untrusted data',
                        file_path=file_path,
                        line_number=line_num,
                        severity=Severity.CRITICAL,
                        confidence=Confidence.HIGH,
                        cwe='CWE-502',
                        owasp='A08',
                    ))
        return findings

    def _check_code_injection(self, file_path: Path, content: str) -> List[Finding]:
        findings = []
        patterns = [
            r'eval\s*\([^)]*\$',
            r'assert\s*\([^)]*\$',
            r'create_function\s*\(',
            r'preg_replace\s*\([^)]*["\']/[^/]*e[^"\']*["\']',  # /e modifier
        ]
        for pattern in patterns:
            for match in re.finditer(pattern, content):
                line_num = content[:match.start()].count('\n') + 1
                findings.append(self._create_finding(
                    rule_id='PHP-CODEINJ-001',
                    title='Code Injection',
                    description='Dynamic code execution detected',
                    file_path=file_path,
                    line_number=line_num,
                    severity=Severity.CRITICAL,
                    confidence=Confidence.MEDIUM,
                    cwe='CWE-94',
                    owasp='A03',
                ))
        return findings
