"""
C# Language Analyzer for SentinelScan.

Provides AST-based security analysis for C#/.NET code using tree-sitter-c-sharp.
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


@AnalyzerRegistry.register_language('.cs')
class CSharpAnalyzer(LanguageAnalyzer):
    """C#/.NET-specific AST analyzer."""

    DANGEROUS_SINKS = {
        'sql_injection': [
            'ExecuteReader', 'ExecuteNonQuery', 'ExecuteScalar',
            'SqlCommand', 'OleDbCommand', 'OdbcCommand',
            'FromSql', 'FromSqlRaw', 'ExecuteSqlCommand', 'ExecuteSqlRaw',
        ],
        'command_injection': [
            'Start', 'Process', 'ProcessStartInfo',
            'Shell', 'CreateProcess',
        ],
        'path_traversal': [
            'ReadAllText', 'ReadAllBytes', 'ReadAllLines',
            'WriteAllText', 'WriteAllBytes', 'WriteAllLines',
            'Open', 'OpenRead', 'OpenWrite', 'Create',
            'Delete', 'Move', 'Copy', 'GetFiles', 'GetDirectories',
        ],
        'ssrf': [
            'GetAsync', 'PostAsync', 'SendAsync',
            'GetStringAsync', 'GetByteArrayAsync',
            'DownloadString', 'DownloadFile',
        ],
        'deserialization': [
            'Deserialize', 'BinaryFormatter', 'ObjectStateFormatter',
            'NetDataContractSerializer', 'SoapFormatter',
            'XmlSerializer', 'DataContractSerializer',
            'JsonConvert.DeserializeObject',
        ],
        'xxe': [
            'XmlDocument', 'XmlReader', 'XDocument',
            'LoadXml', 'Load', 'Parse',
        ],
        'ldap_injection': [
            'DirectorySearcher', 'FindOne', 'FindAll',
            'DirectoryEntry',
        ],
    }

    TAINT_SOURCES = [
        r'Request\.QueryString',
        r'Request\.Form',
        r'Request\.Params',
        r'Request\.Headers',
        r'Request\.Cookies',
        r'Request\.Body',
        r'Request\.Path',
        r'HttpContext\.Request',
        r'\[FromQuery\]',
        r'\[FromBody\]',
        r'\[FromForm\]',
        r'\[FromRoute\]',
        r'\[FromHeader\]',
        r'args\[',
        r'Environment\.GetEnvironmentVariable',
        r'Console\.ReadLine',
    ]

    WEAK_CRYPTO = {
        'MD5': 'MD5 is cryptographically broken',
        'SHA1': 'SHA1 is cryptographically weak',
        'DES': 'DES is insecure, use AES',
        'TripleDES': 'TripleDES is deprecated',
        'RC2': 'RC2 is insecure',
    }

    @property
    def name(self) -> str:
        return "csharp_analyzer"

    @property
    def language_name(self) -> str:
        return "csharp"

    @property
    def tree_sitter_module(self) -> Optional[str]:
        return "tree_sitter_c_sharp"

    @property
    def supported_extensions(self) -> Set[str]:
        return {'.cs'}

    @property
    def capabilities(self) -> AnalyzerCapabilities:
        return AnalyzerCapabilities(
            supports_ast=self._tree_sitter_available,
            supports_dataflow=False,
            supports_taint_tracking=True,
        )

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
        findings.extend(self._check_deserialization(file_path, content))
        findings.extend(self._check_xxe(file_path, content))
        findings.extend(self._check_weak_crypto(file_path, content))
        findings.extend(self._check_hardcoded_secrets(file_path, content))
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
        pattern = r'(?:public|private|internal|protected)?\s*(?:partial\s+)?class\s+(\w+)'
        for match in re.finditer(pattern, code):
            line_num = code[:match.start()].count('\n') + 1
            classes.append(ClassInfo(name=match.group(1), file_path="", line_number=line_num))
        return classes

    def get_functions(self, code: str) -> List[FunctionInfo]:
        functions = []
        pattern = r'(?:public|private|protected|internal)\s+(?:static\s+)?(?:async\s+)?[\w<>\[\],\s]+\s+(\w+)\s*\([^)]*\)'
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
        pattern = r'@?"([^"\\]*(?:\\.[^"\\]*)*)"'
        for match in re.finditer(pattern, code):
            strings.append((match.group(1), code[:match.start()].count('\n') + 1))
        return strings

    def _check_sql_injection(self, file_path: Path, content: str) -> List[Finding]:
        findings = []
        patterns = [
            r'(?:ExecuteReader|ExecuteNonQuery|ExecuteScalar|SqlCommand)\s*\([^)]*\+',
            r'(?:FromSql|FromSqlRaw)\s*\(\s*\$',
            r'(?:ExecuteSqlCommand|ExecuteSqlRaw)\s*\([^)]*\+',
            r'new\s+SqlCommand\s*\([^)]*\+',
        ]
        for pattern in patterns:
            for match in re.finditer(pattern, content):
                line_num = content[:match.start()].count('\n') + 1
                findings.append(self._create_finding(
                    rule_id='CS-SQLI-001',
                    title='Potential SQL Injection',
                    description='SQL query constructed with string concatenation',
                    file_path=file_path,
                    line_number=line_num,
                    severity=Severity.HIGH,
                    confidence=Confidence.MEDIUM,
                    cwe='CWE-89',
                    owasp='A03',
                ))
        return findings

    def _check_command_injection(self, file_path: Path, content: str) -> List[Finding]:
        findings = []
        patterns = [
            r'Process\.Start\s*\([^)]*\+',
            r'ProcessStartInfo\s*\{[^}]*Arguments\s*=\s*[^}]*\+',
        ]
        for pattern in patterns:
            for match in re.finditer(pattern, content, re.DOTALL):
                line_num = content[:match.start()].count('\n') + 1
                findings.append(self._create_finding(
                    rule_id='CS-CMDI-001',
                    title='Potential Command Injection',
                    description='Process started with dynamic arguments',
                    file_path=file_path,
                    line_number=line_num,
                    severity=Severity.CRITICAL,
                    confidence=Confidence.MEDIUM,
                    cwe='CWE-78',
                    owasp='A03',
                ))
        return findings

    def _check_deserialization(self, file_path: Path, content: str) -> List[Finding]:
        findings = []
        dangerous = ['BinaryFormatter', 'ObjectStateFormatter', 'NetDataContractSerializer', 'SoapFormatter']
        for cls in dangerous:
            if cls in content:
                for match in re.finditer(rf'{cls}', content):
                    line_num = content[:match.start()].count('\n') + 1
                    findings.append(self._create_finding(
                        rule_id='CS-DESER-001',
                        title='Insecure Deserialization',
                        description=f'Use of unsafe deserializer: {cls}',
                        file_path=file_path,
                        line_number=line_num,
                        severity=Severity.CRITICAL,
                        confidence=Confidence.HIGH,
                        cwe='CWE-502',
                        owasp='A08',
                        remediation='Use JsonSerializer or DataContractSerializer with known types',
                    ))
        return findings

    def _check_xxe(self, file_path: Path, content: str) -> List[Finding]:
        findings = []
        if 'XmlDocument' in content or 'XmlReader' in content:
            if 'DtdProcessing.Prohibit' not in content and 'XmlResolver = null' not in content:
                for match in re.finditer(r'(?:XmlDocument|XmlReader)', content):
                    line_num = content[:match.start()].count('\n') + 1
                    findings.append(self._create_finding(
                        rule_id='CS-XXE-001',
                        title='Potential XXE Vulnerability',
                        description='XML parser without DTD processing disabled',
                        file_path=file_path,
                        line_number=line_num,
                        severity=Severity.HIGH,
                        confidence=Confidence.MEDIUM,
                        cwe='CWE-611',
                        owasp='A05',
                        remediation='Set XmlResolver = null and DtdProcessing = Prohibit',
                    ))
                    break
        return findings

    def _check_weak_crypto(self, file_path: Path, content: str) -> List[Finding]:
        findings = []
        for algo, reason in self.WEAK_CRYPTO.items():
            pattern = rf'{algo}\.Create|{algo}CryptoServiceProvider|{algo}Managed'
            for match in re.finditer(pattern, content):
                line_num = content[:match.start()].count('\n') + 1
                findings.append(self._create_finding(
                    rule_id='CS-CRYPTO-001',
                    title='Weak Cryptographic Algorithm',
                    description=f'{algo}: {reason}',
                    file_path=file_path,
                    line_number=line_num,
                    severity=Severity.MEDIUM,
                    confidence=Confidence.HIGH,
                    cwe='CWE-327',
                    owasp='A02',
                ))
        return findings

    def _check_hardcoded_secrets(self, file_path: Path, content: str) -> List[Finding]:
        findings = []
        patterns = [
            r'(?:password|pwd|secret|apikey|api_key|connectionstring)\s*=\s*["\'][^"\']{8,}["\']',
            r'(?:BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY)',
        ]
        for pattern in patterns:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                line_num = content[:match.start()].count('\n') + 1
                findings.append(self._create_finding(
                    rule_id='CS-SECRET-001',
                    title='Hardcoded Secret',
                    description='Potential hardcoded credential detected',
                    file_path=file_path,
                    line_number=line_num,
                    severity=Severity.HIGH,
                    confidence=Confidence.MEDIUM,
                    cwe='CWE-798',
                    owasp='A07',
                ))
        return findings
