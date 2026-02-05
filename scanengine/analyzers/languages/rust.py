"""
Rust Language Analyzer for SentinelScan.

Provides security analysis for Rust code with focus on unsafe code and memory safety.
"""

import re
import logging
from typing import Dict, List, Set, Optional, Tuple
from pathlib import Path

from ..base import LanguageAnalyzer, AnalyzerCapabilities, ClassInfo, FunctionInfo, MethodCall
from ..registry import AnalyzerRegistry
from ...models import Finding, Severity, Confidence

logger = logging.getLogger(__name__)


@AnalyzerRegistry.register_language('.rs')
class RustAnalyzer(LanguageAnalyzer):
    """Rust-specific security analyzer with focus on unsafe code."""

    DANGEROUS_SINKS = {
        'sql_injection': [
            'query', 'execute', 'query_as', 'fetch_one', 'fetch_all',
            'sql', 'raw_sql',  # Diesel
        ],
        'command_injection': [
            'Command::new', 'spawn', 'output', 'status',
        ],
        'path_traversal': [
            'read_to_string', 'read', 'write', 'create', 'open',
            'read_dir', 'remove_file', 'remove_dir',
        ],
        'ssrf': [
            'get', 'post', 'request', 'send',  # reqwest
            'Client::new',
        ],
        'deserialization': [
            'from_str', 'from_slice', 'from_reader', 'deserialize',
        ],
        'unsafe_code': [
            'unsafe', 'transmute', 'from_raw_parts',
            'as_mut_ptr', 'as_ptr',
        ],
    }

    TAINT_SOURCES = [
        r'std::env::args',
        r'std::env::var',
        r'std::io::stdin',
        r'request\.',
        r'Query\(',
        r'Path\(',
        r'Json\(',
    ]

    @property
    def name(self) -> str:
        return "rust_analyzer"

    @property
    def language_name(self) -> str:
        return "rust"

    @property
    def tree_sitter_module(self) -> Optional[str]:
        return "tree_sitter_rust"

    @property
    def supported_extensions(self) -> Set[str]:
        return {'.rs'}

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
        findings.extend(self._check_unsafe_blocks(file_path, content))
        findings.extend(self._check_sql_injection(file_path, content))
        findings.extend(self._check_command_injection(file_path, content))
        findings.extend(self._check_unwrap_usage(file_path, content))
        findings.extend(self._check_format_vulnerabilities(file_path, content))
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
        pattern = r'(?:pub\s+)?struct\s+(\w+)'
        for match in re.finditer(pattern, code):
            classes.append(ClassInfo(name=match.group(1), file_path="", line_number=code[:match.start()].count('\n') + 1))
        return classes

    def get_functions(self, code: str) -> List[FunctionInfo]:
        functions = []
        pattern = r'(?:pub\s+)?(?:async\s+)?fn\s+(\w+)'
        for match in re.finditer(pattern, code):
            functions.append(FunctionInfo(name=match.group(1), file_path="", line_number=code[:match.start()].count('\n') + 1))
        return functions

    def get_method_calls(self, code: str) -> List[MethodCall]:
        calls = []
        pattern = r'(\w+(?:::\w+)*)\s*\(([^)]*)\)'
        for match in re.finditer(pattern, code):
            parts = match.group(1).split('::')
            calls.append(MethodCall(
                name=parts[-1],
                object_name='::'.join(parts[:-1]) if len(parts) > 1 else None,
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

    def _check_unsafe_blocks(self, file_path: Path, content: str) -> List[Finding]:
        findings = []
        # Find unsafe blocks and functions
        patterns = [
            (r'unsafe\s+\{', 'unsafe block'),
            (r'unsafe\s+fn\s+', 'unsafe function'),
            (r'unsafe\s+impl\s+', 'unsafe impl'),
        ]
        for pattern, desc in patterns:
            for match in re.finditer(pattern, content):
                line_num = content[:match.start()].count('\n') + 1
                findings.append(self._create_finding(
                    rule_id='RUST-UNSAFE-001',
                    title='Unsafe Code Block',
                    description=f'Found {desc} - requires manual review for memory safety',
                    file_path=file_path,
                    line_number=line_num,
                    severity=Severity.MEDIUM,
                    confidence=Confidence.HIGH,
                    cwe='CWE-119',
                    owasp='A06',
                    remediation='Review unsafe code for memory safety violations',
                ))

        # Check for dangerous unsafe operations
        dangerous_ops = [
            (r'std::mem::transmute', 'transmute can cause undefined behavior'),
            (r'from_raw_parts', 'from_raw_parts requires valid pointer and length'),
            (r'std::ptr::read', 'raw pointer read may cause UB'),
            (r'std::ptr::write', 'raw pointer write may cause UB'),
        ]
        for pattern, reason in dangerous_ops:
            for match in re.finditer(pattern, content):
                line_num = content[:match.start()].count('\n') + 1
                findings.append(self._create_finding(
                    rule_id='RUST-UNSAFE-002',
                    title='Dangerous Unsafe Operation',
                    description=reason,
                    file_path=file_path,
                    line_number=line_num,
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    cwe='CWE-119',
                    owasp='A06',
                ))
        return findings

    def _check_sql_injection(self, file_path: Path, content: str) -> List[Finding]:
        findings = []
        patterns = [
            r'(?:query|execute)\s*\(\s*&?format!',
            r'sql!\s*\([^)]*\{',
            r'\.query\s*\([^)]*\+',
        ]
        for pattern in patterns:
            for match in re.finditer(pattern, content):
                line_num = content[:match.start()].count('\n') + 1
                findings.append(self._create_finding(
                    rule_id='RUST-SQLI-001',
                    title='Potential SQL Injection',
                    description='SQL query with string formatting',
                    file_path=file_path,
                    line_number=line_num,
                    severity=Severity.HIGH,
                    confidence=Confidence.MEDIUM,
                    cwe='CWE-89',
                    owasp='A03',
                    remediation='Use parameterized queries with bind parameters',
                ))
        return findings

    def _check_command_injection(self, file_path: Path, content: str) -> List[Finding]:
        findings = []
        patterns = [
            r'Command::new\s*\(\s*&?format!',
            r'Command::new\s*\([^)]*\)',
            r'\.arg\s*\(\s*&?format!',
        ]
        for pattern in patterns:
            for match in re.finditer(pattern, content):
                # Check if it involves user input
                context_start = max(0, match.start() - 200)
                context = content[context_start:match.end()]
                if any(src in context for src in ['args', 'env::var', 'stdin', 'request']):
                    line_num = content[:match.start()].count('\n') + 1
                    findings.append(self._create_finding(
                        rule_id='RUST-CMDI-001',
                        title='Potential Command Injection',
                        description='Command execution may use user input',
                        file_path=file_path,
                        line_number=line_num,
                        severity=Severity.HIGH,
                        confidence=Confidence.MEDIUM,
                        cwe='CWE-78',
                        owasp='A03',
                    ))
        return findings

    def _check_unwrap_usage(self, file_path: Path, content: str) -> List[Finding]:
        findings = []
        # Check for unwrap() in non-test code
        if '#[cfg(test)]' not in content and '#[test]' not in content:
            pattern = r'\.unwrap\(\)'
            count = len(re.findall(pattern, content))
            if count > 5:  # Only flag if excessive
                findings.append(self._create_finding(
                    rule_id='RUST-PANIC-001',
                    title='Excessive unwrap() Usage',
                    description=f'Found {count} uses of unwrap() which may panic',
                    file_path=file_path,
                    line_number=1,
                    severity=Severity.LOW,
                    confidence=Confidence.LOW,
                    cwe='CWE-754',
                    owasp='A06',
                    remediation='Use ? operator or handle errors explicitly',
                ))
        return findings

    def _check_format_vulnerabilities(self, file_path: Path, content: str) -> List[Finding]:
        findings = []
        # Check for format string from user input
        patterns = [
            r'format!\s*\(\s*[^"]+\)',  # format! with non-literal first arg
            r'println!\s*\(\s*[^"]+\)',
        ]
        for pattern in patterns:
            for match in re.finditer(pattern, content):
                line_num = content[:match.start()].count('\n') + 1
                # Verify it's not a constant or static string
                expr = match.group(0)
                if '&' in expr or 'var' in expr.lower():
                    findings.append(self._create_finding(
                        rule_id='RUST-FMT-001',
                        title='Potential Format String Vulnerability',
                        description='Format macro with non-literal format string',
                        file_path=file_path,
                        line_number=line_num,
                        severity=Severity.MEDIUM,
                        confidence=Confidence.LOW,
                        cwe='CWE-134',
                        owasp='A03',
                    ))
        return findings
