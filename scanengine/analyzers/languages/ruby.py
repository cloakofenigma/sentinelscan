"""
Ruby Language Analyzer for SentinelScan.

Provides security analysis for Ruby/Rails applications.
"""

import re
import logging
from typing import Dict, List, Set, Optional, Tuple
from pathlib import Path

from ..base import LanguageAnalyzer, AnalyzerCapabilities, ClassInfo, FunctionInfo, MethodCall
from ..registry import AnalyzerRegistry
from ...models import Finding, Severity, Confidence

logger = logging.getLogger(__name__)


@AnalyzerRegistry.register_language('.rb', '.rake', '.gemspec')
class RubyAnalyzer(LanguageAnalyzer):
    """Ruby-specific security analyzer."""

    DANGEROUS_SINKS = {
        'sql_injection': [
            'find_by_sql', 'execute', 'select_all', 'where', 'order',
            'pluck', 'group', 'having', 'joins', 'from',
        ],
        'command_injection': [
            'system', 'exec', 'spawn', 'Open3', 'popen', 'backticks',
            '%x', 'IO.popen', 'Kernel.system',
        ],
        'path_traversal': [
            'File.open', 'File.read', 'File.write', 'File.delete',
            'FileUtils', 'Dir.glob', 'send_file',
        ],
        'xss': [
            'raw', 'html_safe', 'content_tag',
        ],
        'deserialization': [
            'YAML.load', 'Marshal.load', 'JSON.load',
        ],
        'mass_assignment': [
            'update_attributes', 'assign_attributes', 'new', 'create',
        ],
    }

    TAINT_SOURCES = [
        r'params\[',
        r'request\.',
        r'cookies\[',
        r'session\[',
        r'ENV\[',
        r'ARGV',
        r'gets',
        r'STDIN',
    ]

    @property
    def name(self) -> str:
        return "ruby_analyzer"

    @property
    def language_name(self) -> str:
        return "ruby"

    @property
    def tree_sitter_module(self) -> Optional[str]:
        return "tree_sitter_ruby"

    @property
    def supported_extensions(self) -> Set[str]:
        return {'.rb', '.rake', '.gemspec'}

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
        findings.extend(self._check_deserialization(file_path, content))
        findings.extend(self._check_mass_assignment(file_path, content))
        findings.extend(self._check_open_redirect(file_path, content))
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
        pattern = r'def\s+(\w+)'
        for match in re.finditer(pattern, code):
            functions.append(FunctionInfo(name=match.group(1), file_path="", line_number=code[:match.start()].count('\n') + 1))
        return functions

    def get_method_calls(self, code: str) -> List[MethodCall]:
        calls = []
        pattern = r'(\w+(?:\.\w+)*)\s*(?:\(([^)]*)\)|(?=\s+\w))'
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
        pattern = r'["\']([^"\']*)["\']'
        for match in re.finditer(pattern, code):
            strings.append((match.group(1), code[:match.start()].count('\n') + 1))
        return strings

    def _check_sql_injection(self, file_path: Path, content: str) -> List[Finding]:
        findings = []
        patterns = [
            r'find_by_sql\s*\([^)]*#\{',
            r'\.where\s*\([^)]*#\{',
            r'\.where\s*\(\s*"[^"]*#\{',
            r'execute\s*\([^)]*#\{',
            r'\.order\s*\([^)]*params\[',
        ]
        for pattern in patterns:
            for match in re.finditer(pattern, content):
                line_num = content[:match.start()].count('\n') + 1
                findings.append(self._create_finding(
                    rule_id='RUBY-SQLI-001',
                    title='SQL Injection',
                    description='SQL query with string interpolation',
                    file_path=file_path,
                    line_number=line_num,
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    cwe='CWE-89',
                    owasp='A03',
                    remediation='Use parameterized queries: User.where(id: params[:id])',
                ))
        return findings

    def _check_command_injection(self, file_path: Path, content: str) -> List[Finding]:
        findings = []
        patterns = [
            r'system\s*\([^)]*#\{',
            r'system\s*\([^)]*params\[',
            r'`[^`]*#\{[^`]*params',
            r'exec\s*\([^)]*#\{',
            r'%x\[[^\]]*#\{',
        ]
        for pattern in patterns:
            for match in re.finditer(pattern, content):
                line_num = content[:match.start()].count('\n') + 1
                findings.append(self._create_finding(
                    rule_id='RUBY-CMDI-001',
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
            r'\.html_safe',
            r'raw\s*\([^)]*params\[',
            r'<%=\s*raw',
        ]
        for pattern in patterns:
            for match in re.finditer(pattern, content):
                line_num = content[:match.start()].count('\n') + 1
                findings.append(self._create_finding(
                    rule_id='RUBY-XSS-001',
                    title='Cross-Site Scripting (XSS)',
                    description='Bypassing HTML escaping may lead to XSS',
                    file_path=file_path,
                    line_number=line_num,
                    severity=Severity.HIGH,
                    confidence=Confidence.MEDIUM,
                    cwe='CWE-79',
                    owasp='A03',
                ))
        return findings

    def _check_deserialization(self, file_path: Path, content: str) -> List[Finding]:
        findings = []
        patterns = [
            r'YAML\.load\s*\(',
            r'Marshal\.load\s*\(',
        ]
        for pattern in patterns:
            for match in re.finditer(pattern, content):
                line_num = content[:match.start()].count('\n') + 1
                findings.append(self._create_finding(
                    rule_id='RUBY-DESER-001',
                    title='Insecure Deserialization',
                    description='Unsafe deserialization method',
                    file_path=file_path,
                    line_number=line_num,
                    severity=Severity.HIGH,
                    confidence=Confidence.MEDIUM,
                    cwe='CWE-502',
                    owasp='A08',
                    remediation='Use YAML.safe_load instead of YAML.load',
                ))
        return findings

    def _check_mass_assignment(self, file_path: Path, content: str) -> List[Finding]:
        findings = []
        if 'permit!' in content:
            for match in re.finditer(r'permit!', content):
                line_num = content[:match.start()].count('\n') + 1
                findings.append(self._create_finding(
                    rule_id='RUBY-MASS-001',
                    title='Mass Assignment Vulnerability',
                    description='permit! allows all parameters',
                    file_path=file_path,
                    line_number=line_num,
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    cwe='CWE-915',
                    owasp='A01',
                    remediation='Use permit(:specific, :params) instead',
                ))
        return findings

    def _check_open_redirect(self, file_path: Path, content: str) -> List[Finding]:
        findings = []
        patterns = [
            r'redirect_to\s+params\[',
            r'redirect_to\s+request\.',
        ]
        for pattern in patterns:
            for match in re.finditer(pattern, content):
                line_num = content[:match.start()].count('\n') + 1
                findings.append(self._create_finding(
                    rule_id='RUBY-REDIRECT-001',
                    title='Open Redirect',
                    description='Redirect with user-controlled URL',
                    file_path=file_path,
                    line_number=line_num,
                    severity=Severity.MEDIUM,
                    confidence=Confidence.MEDIUM,
                    cwe='CWE-601',
                    owasp='A01',
                ))
        return findings
