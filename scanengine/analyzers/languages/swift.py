"""
Swift Language Analyzer for SentinelScan.

Provides security analysis for Swift/iOS applications.
"""

import re
import logging
from typing import Dict, List, Set, Optional, Tuple
from pathlib import Path

from ..base import LanguageAnalyzer, AnalyzerCapabilities, ClassInfo, FunctionInfo, MethodCall
from ..registry import AnalyzerRegistry
from ...models import Finding, Severity, Confidence

logger = logging.getLogger(__name__)


@AnalyzerRegistry.register_language('.swift')
class SwiftAnalyzer(LanguageAnalyzer):
    """Swift/iOS-specific security analyzer."""

    DANGEROUS_SINKS = {
        'sql_injection': [
            'sqlite3_exec', 'sqlite3_prepare', 'execute', 'executeQuery',
        ],
        'command_injection': [
            'Process', 'NSTask', 'launchPath',
        ],
        'path_traversal': [
            'FileManager', 'contentsOfFile', 'write', 'createFile',
            'removeItem', 'copyItem', 'moveItem',
        ],
        'ssrf': [
            'URLSession', 'dataTask', 'downloadTask',
            'NSURLConnection', 'sendSynchronousRequest',
        ],
        'deserialization': [
            'NSKeyedUnarchiver', 'unarchiveObject', 'JSONDecoder',
            'PropertyListDecoder',
        ],
        'webview': [
            'WKWebView', 'UIWebView', 'loadHTMLString', 'evaluateJavaScript',
        ],
        'keychain': [
            'SecItemAdd', 'SecItemCopyMatching', 'SecItemUpdate',
        ],
    }

    TAINT_SOURCES = [
        r'UserDefaults',
        r'ProcessInfo\.processInfo\.environment',
        r'Bundle\.main',
        r'URLComponents',
        r'request\.',
        r'UIPasteboard',
        r'openURL',
    ]

    @property
    def name(self) -> str:
        return "swift_analyzer"

    @property
    def language_name(self) -> str:
        return "swift"

    @property
    def tree_sitter_module(self) -> Optional[str]:
        return "tree_sitter_swift"

    @property
    def supported_extensions(self) -> Set[str]:
        return {'.swift'}

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
        findings.extend(self._check_ats_bypass(file_path, content))
        findings.extend(self._check_insecure_keychain(file_path, content))
        findings.extend(self._check_webview_security(file_path, content))
        findings.extend(self._check_url_scheme(file_path, content))
        findings.extend(self._check_hardcoded_secrets(file_path, content))
        findings.extend(self._check_weak_crypto(file_path, content))
        findings.extend(self._check_insecure_random(file_path, content))
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
        pattern = r'(?:class|struct|enum)\s+(\w+)'
        for match in re.finditer(pattern, code):
            classes.append(ClassInfo(name=match.group(1), file_path="", line_number=code[:match.start()].count('\n') + 1))
        return classes

    def get_functions(self, code: str) -> List[FunctionInfo]:
        functions = []
        pattern = r'func\s+(\w+)'
        for match in re.finditer(pattern, code):
            functions.append(FunctionInfo(name=match.group(1), file_path="", line_number=code[:match.start()].count('\n') + 1))
        return functions

    def get_method_calls(self, code: str) -> List[MethodCall]:
        calls = []
        pattern = r'(\w+(?:\.\w+)*)\s*\(([^)]*)\)'
        for match in re.finditer(pattern, code):
            parts = match.group(1).split('.')
            calls.append(MethodCall(
                name=parts[-1],
                object_name='.'.join(parts[:-1]) if len(parts) > 1 else None,
                arguments=[match.group(2)] if match.group(2) else [],
                line_number=code[:match.start()].count('\n') + 1,
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

    def _check_ats_bypass(self, file_path: Path, content: str) -> List[Finding]:
        findings = []
        # Check for ATS bypass indicators in code
        patterns = [
            r'NSAllowsArbitraryLoads',
            r'NSExceptionAllowsInsecureHTTPLoads',
            r'NSTemporaryExceptionAllowsInsecureHTTPLoads',
        ]
        for pattern in patterns:
            if pattern in content:
                for match in re.finditer(pattern, content):
                    line_num = content[:match.start()].count('\n') + 1
                    findings.append(self._create_finding(
                        rule_id='SWIFT-ATS-001',
                        title='App Transport Security Bypass',
                        description=f'ATS bypass detected: {pattern}',
                        file_path=file_path,
                        line_number=line_num,
                        severity=Severity.HIGH,
                        confidence=Confidence.HIGH,
                        cwe='CWE-319',
                        owasp='A02',
                        remediation='Enable ATS and use HTTPS for all connections',
                    ))
        return findings

    def _check_insecure_keychain(self, file_path: Path, content: str) -> List[Finding]:
        findings = []
        # Check for insecure keychain access
        if 'SecItemAdd' in content or 'SecItemUpdate' in content:
            # Check if kSecAttrAccessible is set to a weak value
            weak_accessible = [
                'kSecAttrAccessibleAlways',
                'kSecAttrAccessibleAlwaysThisDeviceOnly',
            ]
            for weak in weak_accessible:
                if weak in content:
                    for match in re.finditer(weak, content):
                        line_num = content[:match.start()].count('\n') + 1
                        findings.append(self._create_finding(
                            rule_id='SWIFT-KEYCHAIN-001',
                            title='Insecure Keychain Access',
                            description=f'Weak keychain accessibility: {weak}',
                            file_path=file_path,
                            line_number=line_num,
                            severity=Severity.HIGH,
                            confidence=Confidence.HIGH,
                            cwe='CWE-522',
                            owasp='A07',
                            remediation='Use kSecAttrAccessibleWhenUnlockedThisDeviceOnly',
                        ))
        return findings

    def _check_webview_security(self, file_path: Path, content: str) -> List[Finding]:
        findings = []
        # Check for UIWebView (deprecated, insecure)
        if 'UIWebView' in content:
            for match in re.finditer(r'UIWebView', content):
                line_num = content[:match.start()].count('\n') + 1
                findings.append(self._create_finding(
                    rule_id='SWIFT-WEBVIEW-001',
                    title='Deprecated UIWebView',
                    description='UIWebView is deprecated and has security issues',
                    file_path=file_path,
                    line_number=line_num,
                    severity=Severity.MEDIUM,
                    confidence=Confidence.HIGH,
                    cwe='CWE-829',
                    owasp='A06',
                    remediation='Migrate to WKWebView',
                ))

        # Check for JavaScript bridge
        if 'evaluateJavaScript' in content:
            for match in re.finditer(r'evaluateJavaScript\s*\([^)]*\\\(', content):
                line_num = content[:match.start()].count('\n') + 1
                findings.append(self._create_finding(
                    rule_id='SWIFT-WEBVIEW-002',
                    title='WebView JavaScript Injection',
                    description='JavaScript evaluation with interpolated string',
                    file_path=file_path,
                    line_number=line_num,
                    severity=Severity.HIGH,
                    confidence=Confidence.MEDIUM,
                    cwe='CWE-79',
                    owasp='A03',
                ))
        return findings

    def _check_url_scheme(self, file_path: Path, content: str) -> List[Finding]:
        findings = []
        # Check for URL scheme handling without validation
        if 'application(_:open:' in content or 'handleOpenURL' in content:
            patterns = [
                r'func\s+application\s*\([^)]*open\s+url:',
                r'handleOpenURL',
            ]
            for pattern in patterns:
                for match in re.finditer(pattern, content):
                    line_num = content[:match.start()].count('\n') + 1
                    # Check if there's URL validation
                    context_end = min(len(content), match.end() + 500)
                    context = content[match.start():context_end]
                    if 'scheme' not in context.lower() and 'host' not in context.lower():
                        findings.append(self._create_finding(
                            rule_id='SWIFT-URL-001',
                            title='URL Scheme Handler',
                            description='URL scheme handler may lack validation',
                            file_path=file_path,
                            line_number=line_num,
                            severity=Severity.MEDIUM,
                            confidence=Confidence.LOW,
                            cwe='CWE-939',
                            owasp='A01',
                            remediation='Validate URL scheme and host before processing',
                        ))
        return findings

    def _check_hardcoded_secrets(self, file_path: Path, content: str) -> List[Finding]:
        findings = []
        patterns = [
            r'(?:let|var)\s+(?:apiKey|secret|password|token)\s*=\s*"[^"]{8,}"',
            r'API_KEY\s*=\s*"[^"]{8,}"',
        ]
        for pattern in patterns:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                line_num = content[:match.start()].count('\n') + 1
                findings.append(self._create_finding(
                    rule_id='SWIFT-SECRET-001',
                    title='Hardcoded Secret',
                    description='Potential hardcoded credential',
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
        weak_crypto = {
            'CC_MD5': 'MD5 is cryptographically broken',
            'CC_SHA1': 'SHA1 is cryptographically weak',
            'kCCAlgorithmDES': 'DES is insecure',
            'kCCAlgorithm3DES': '3DES is deprecated',
        }
        for pattern, reason in weak_crypto.items():
            if pattern in content:
                for match in re.finditer(pattern, content):
                    line_num = content[:match.start()].count('\n') + 1
                    findings.append(self._create_finding(
                        rule_id='SWIFT-CRYPTO-001',
                        title='Weak Cryptographic Algorithm',
                        description=reason,
                        file_path=file_path,
                        line_number=line_num,
                        severity=Severity.MEDIUM,
                        confidence=Confidence.HIGH,
                        cwe='CWE-327',
                        owasp='A02',
                    ))
        return findings

    def _check_insecure_random(self, file_path: Path, content: str) -> List[Finding]:
        findings = []
        if 'arc4random' in content and 'arc4random_uniform' not in content:
            for match in re.finditer(r'arc4random\(\)', content):
                line_num = content[:match.start()].count('\n') + 1
                findings.append(self._create_finding(
                    rule_id='SWIFT-RANDOM-001',
                    title='Insecure Random',
                    description='arc4random() may have bias; use arc4random_uniform() or SecRandomCopyBytes()',
                    file_path=file_path,
                    line_number=line_num,
                    severity=Severity.LOW,
                    confidence=Confidence.MEDIUM,
                    cwe='CWE-330',
                    owasp='A02',
                ))
        return findings
