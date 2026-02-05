"""
Kotlin Language Analyzer for SentinelScan.

Provides security analysis for Kotlin/Android code.
"""

import re
import logging
from typing import Dict, List, Set, Optional, Tuple
from pathlib import Path

from ..base import (
    LanguageAnalyzer,
    AnalyzerCapabilities,
    ClassInfo,
    FunctionInfo,
    MethodCall,
)
from ..registry import AnalyzerRegistry
from ...models import Finding, Severity, Confidence, Location

logger = logging.getLogger(__name__)


@AnalyzerRegistry.register_language('.kt', '.kts')
class KotlinAnalyzer(LanguageAnalyzer):
    """Kotlin-specific AST analyzer with Android security focus."""

    DANGEROUS_SINKS = {
        'sql_injection': [
            'rawQuery', 'execSQL', 'query', 'compileStatement',
            'RawQuery',  # Room
        ],
        'command_injection': [
            'exec', 'Runtime.getRuntime', 'ProcessBuilder',
        ],
        'path_traversal': [
            'File', 'FileInputStream', 'FileOutputStream',
            'openFileInput', 'openFileOutput',
        ],
        'intent_injection': [
            'startActivity', 'startService', 'sendBroadcast',
            'startActivityForResult', 'setComponent', 'setClassName',
        ],
        'webview_xss': [
            'loadUrl', 'loadData', 'loadDataWithBaseURL',
            'evaluateJavascript', 'addJavascriptInterface',
        ],
        'deserialization': [
            'ObjectInputStream', 'readObject', 'Parcel',
        ],
    }

    TAINT_SOURCES = [
        r'intent\.getStringExtra',
        r'intent\.getIntExtra',
        r'intent\.get\w+Extra',
        r'intent\.data',
        r'intent\.extras',
        r'getSharedPreferences',
        r'getIntent\(\)',
        r'Uri\.parse',
        r'request\.',
    ]

    @property
    def name(self) -> str:
        return "kotlin_analyzer"

    @property
    def language_name(self) -> str:
        return "kotlin"

    @property
    def tree_sitter_module(self) -> Optional[str]:
        return "tree_sitter_kotlin"

    @property
    def supported_extensions(self) -> Set[str]:
        return {'.kt', '.kts'}

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
        findings.extend(self._check_intent_vulnerabilities(file_path, content))
        findings.extend(self._check_webview_security(file_path, content))
        findings.extend(self._check_insecure_storage(file_path, content))
        findings.extend(self._check_hardcoded_secrets(file_path, content))
        findings.extend(self._check_weak_crypto(file_path, content))
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
        pattern = r'(?:class|object|interface)\s+(\w+)'
        for match in re.finditer(pattern, code):
            line_num = code[:match.start()].count('\n') + 1
            classes.append(ClassInfo(name=match.group(1), file_path="", line_number=line_num))
        return classes

    def get_functions(self, code: str) -> List[FunctionInfo]:
        functions = []
        pattern = r'fun\s+(\w+)\s*\([^)]*\)'
        for match in re.finditer(pattern, code):
            line_num = code[:match.start()].count('\n') + 1
            functions.append(FunctionInfo(name=match.group(1), file_path="", line_number=line_num))
        return functions

    def get_method_calls(self, code: str) -> List[MethodCall]:
        calls = []
        pattern = r'(\w+(?:\.\w+)*)\s*\(([^)]*)\)'
        for match in re.finditer(pattern, code):
            line_num = code[:match.start()].count('\n') + 1
            parts = match.group(1).split('.')
            calls.append(MethodCall(
                name=parts[-1],
                object_name='.'.join(parts[:-1]) if len(parts) > 1 else None,
                arguments=[match.group(2)] if match.group(2) else [],
                line_number=line_num,
                file_path="",
                full_expression=match.group(0),
            ))
        return calls

    def get_string_literals(self, code: str) -> List[Tuple[str, int]]:
        strings = []
        pattern = r'"([^"\\]*(?:\\.[^"\\]*)*)"'
        for match in re.finditer(pattern, code):
            strings.append((match.group(1), code[:match.start()].count('\n') + 1))
        return strings

    def _check_sql_injection(self, file_path: Path, content: str) -> List[Finding]:
        findings = []
        patterns = [
            r'rawQuery\s*\([^)]*\$',
            r'rawQuery\s*\([^)]*\+',
            r'execSQL\s*\([^)]*\$',
            r'@RawQuery',
        ]
        for pattern in patterns:
            for match in re.finditer(pattern, content):
                line_num = content[:match.start()].count('\n') + 1
                findings.append(self._create_finding(
                    rule_id='KT-SQLI-001',
                    title='Potential SQL Injection',
                    description='SQL query with string interpolation or concatenation',
                    file_path=file_path,
                    line_number=line_num,
                    severity=Severity.HIGH,
                    confidence=Confidence.MEDIUM,
                    cwe='CWE-89',
                    owasp='A03',
                ))
        return findings

    def _check_intent_vulnerabilities(self, file_path: Path, content: str) -> List[Finding]:
        findings = []
        # Check for implicit intents with sensitive data
        if 'startActivity' in content or 'sendBroadcast' in content:
            patterns = [
                r'Intent\s*\(\s*\)',  # Empty intent
                r'Intent\s*\([^)]*\)\s*\.apply\s*\{[^}]*putExtra',
            ]
            for pattern in patterns:
                for match in re.finditer(pattern, content, re.DOTALL):
                    line_num = content[:match.start()].count('\n') + 1
                    findings.append(self._create_finding(
                        rule_id='KT-INTENT-001',
                        title='Potential Intent Vulnerability',
                        description='Intent may be intercepted by malicious apps',
                        file_path=file_path,
                        line_number=line_num,
                        severity=Severity.MEDIUM,
                        confidence=Confidence.LOW,
                        cwe='CWE-927',
                        owasp='A01',
                    ))
        return findings

    def _check_webview_security(self, file_path: Path, content: str) -> List[Finding]:
        findings = []
        # Check for JavaScript enabled
        if 'setJavaScriptEnabled(true)' in content:
            for match in re.finditer(r'setJavaScriptEnabled\s*\(\s*true\s*\)', content):
                line_num = content[:match.start()].count('\n') + 1
                findings.append(self._create_finding(
                    rule_id='KT-WEBVIEW-001',
                    title='WebView JavaScript Enabled',
                    description='WebView with JavaScript enabled may be vulnerable to XSS',
                    file_path=file_path,
                    line_number=line_num,
                    severity=Severity.MEDIUM,
                    confidence=Confidence.MEDIUM,
                    cwe='CWE-79',
                    owasp='A03',
                ))

        # Check for addJavascriptInterface
        if 'addJavascriptInterface' in content:
            for match in re.finditer(r'addJavascriptInterface', content):
                line_num = content[:match.start()].count('\n') + 1
                findings.append(self._create_finding(
                    rule_id='KT-WEBVIEW-002',
                    title='WebView JavaScript Bridge',
                    description='addJavascriptInterface can expose native methods to JavaScript',
                    file_path=file_path,
                    line_number=line_num,
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    cwe='CWE-749',
                    owasp='A03',
                ))
        return findings

    def _check_insecure_storage(self, file_path: Path, content: str) -> List[Finding]:
        findings = []
        # Check for MODE_WORLD_READABLE/WRITABLE (deprecated but still used)
        patterns = [
            r'MODE_WORLD_READABLE',
            r'MODE_WORLD_WRITEABLE',
            r'Context\.MODE_PRIVATE.*0',
        ]
        for pattern in patterns:
            for match in re.finditer(pattern, content):
                line_num = content[:match.start()].count('\n') + 1
                findings.append(self._create_finding(
                    rule_id='KT-STORAGE-001',
                    title='Insecure File Storage',
                    description='File created with world-readable/writable permissions',
                    file_path=file_path,
                    line_number=line_num,
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    cwe='CWE-276',
                    owasp='A01',
                ))
        return findings

    def _check_hardcoded_secrets(self, file_path: Path, content: str) -> List[Finding]:
        findings = []
        patterns = [
            r'(?:API_KEY|SECRET|PASSWORD|TOKEN)\s*=\s*"[^"]{8,}"',
            r'val\s+(?:apiKey|secret|password|token)\s*=\s*"[^"]{8,}"',
        ]
        for pattern in patterns:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                line_num = content[:match.start()].count('\n') + 1
                findings.append(self._create_finding(
                    rule_id='KT-SECRET-001',
                    title='Hardcoded Secret',
                    description='Potential hardcoded credential in source code',
                    file_path=file_path,
                    line_number=line_num,
                    severity=Severity.HIGH,
                    confidence=Confidence.MEDIUM,
                    cwe='CWE-798',
                    owasp='A07',
                ))
        return findings

    def _check_weak_crypto(self, file_path: Path, content: str) -> List[Finding]:
        findings = []
        weak_algos = {
            'MD5': 'MD5 is cryptographically broken',
            'SHA1': 'SHA1 is cryptographically weak',
            'DES': 'DES is insecure',
            'ECB': 'ECB mode is insecure',
        }
        for algo, reason in weak_algos.items():
            if algo in content:
                for match in re.finditer(rf'{algo}', content):
                    line_num = content[:match.start()].count('\n') + 1
                    findings.append(self._create_finding(
                        rule_id='KT-CRYPTO-001',
                        title='Weak Cryptographic Algorithm',
                        description=reason,
                        file_path=file_path,
                        line_number=line_num,
                        severity=Severity.MEDIUM,
                        confidence=Confidence.MEDIUM,
                        cwe='CWE-327',
                        owasp='A02',
                    ))
        return findings
