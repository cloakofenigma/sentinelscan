"""
Go Language Analyzer for SentinelScan.

Provides AST-based security analysis for Go code using tree-sitter-go.
Detects common vulnerabilities including:
- SQL injection
- Command injection
- Path traversal
- SSRF
- Insecure deserialization
- Weak cryptography
"""

import re
import logging
from typing import Dict, List, Set, Optional, Tuple, Any
from pathlib import Path

from ..base import (
    LanguageAnalyzer,
    AnalyzerCapabilities,
    ClassInfo,
    FunctionInfo,
    MethodCall,
    VulnerabilityType,
)
from ..registry import AnalyzerRegistry
from ...models import Finding, Severity, Confidence, Location

logger = logging.getLogger(__name__)


@AnalyzerRegistry.register_language('.go')
class GoAnalyzer(LanguageAnalyzer):
    """
    Go-specific AST analyzer.

    Uses tree-sitter-go for parsing and provides comprehensive
    security analysis for Go applications.
    """

    # Dangerous sinks by vulnerability type
    DANGEROUS_SINKS = {
        'sql_injection': [
            'Query', 'QueryRow', 'QueryContext', 'QueryRowContext',
            'Exec', 'ExecContext', 'Prepare', 'PrepareContext',
            'Raw', 'RawQuery',  # GORM
        ],
        'command_injection': [
            'Command', 'CommandContext',
            'Run', 'Start', 'Output', 'CombinedOutput',
        ],
        'path_traversal': [
            'Open', 'OpenFile', 'Create', 'Remove', 'RemoveAll',
            'ReadFile', 'WriteFile', 'ReadDir', 'Stat', 'Lstat',
            'MkdirAll', 'Mkdir', 'Rename', 'Chmod', 'Chown',
        ],
        'ssrf': [
            'Get', 'Post', 'PostForm', 'Head', 'Do',
            'NewRequest', 'NewRequestWithContext',
        ],
        'deserialization': [
            'Unmarshal', 'Decode', 'NewDecoder',
            'UnmarshalJSON', 'UnmarshalXML', 'UnmarshalYAML',
        ],
        'weak_crypto': [
            'NewCipher',  # des, rc4
            'New',  # md5, sha1
        ],
        'template_injection': [
            'Parse', 'ParseFiles', 'ParseGlob',
            'Execute', 'ExecuteTemplate',
        ],
    }

    # Taint sources - user input patterns
    TAINT_SOURCES = [
        # net/http
        r'r\.URL\.Query',
        r'r\.FormValue',
        r'r\.PostFormValue',
        r'r\.Header\.Get',
        r'r\.Body',
        r'r\.PathValue',
        r'r\.Cookie',
        # gin
        r'c\.Query',
        r'c\.Param',
        r'c\.PostForm',
        r'c\.GetHeader',
        r'c\.BindJSON',
        r'c\.ShouldBindJSON',
        # echo
        r'c\.QueryParam',
        r'c\.FormValue',
        r'c\.Param',
        # fiber
        r'c\.Query',
        r'c\.Params',
        r'c\.FormValue',
        r'c\.Body',
        # general
        r'os\.Args',
        r'os\.Getenv',
        r'bufio\.NewReader',
    ]

    # Weak crypto packages
    WEAK_CRYPTO_PACKAGES = {
        'crypto/md5': 'MD5 is cryptographically broken',
        'crypto/sha1': 'SHA1 is cryptographically weak',
        'crypto/des': 'DES is insecure, use AES',
        'crypto/rc4': 'RC4 is insecure',
    }

    # Dangerous patterns (regex-based fallback)
    DANGEROUS_PATTERNS = {
        'sql_injection': [
            r'(?:Query|Exec|Prepare)\s*\(\s*(?:fmt\.Sprintf|.*\+)',
            r'db\.\w+\(\s*"[^"]*"\s*\+',
            r'Raw\s*\(\s*(?:fmt\.Sprintf|.*\+)',
        ],
        'command_injection': [
            r'exec\.Command\s*\([^)]*(?:\+|fmt\.Sprintf)',
            r'exec\.CommandContext\s*\([^)]*(?:\+|fmt\.Sprintf)',
        ],
        'path_traversal': [
            r'(?:Open|ReadFile|WriteFile)\s*\([^)]*(?:\+|filepath\.Join\s*\([^)]*r\.)',
            r'filepath\.Join\s*\([^)]*(?:r\.|c\.)',
        ],
        'ssrf': [
            r'http\.(?:Get|Post|PostForm)\s*\([^)]*(?:\+|fmt\.Sprintf)',
            r'NewRequest(?:WithContext)?\s*\([^)]*(?:\+|fmt\.Sprintf)',
        ],
        'hardcoded_secret': [
            r'(?:password|secret|apikey|api_key|token)\s*[=:]\s*["\'][^"\']{8,}["\']',
            r'(?:BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY)',
        ],
    }

    @property
    def name(self) -> str:
        return "go_analyzer"

    @property
    def language_name(self) -> str:
        return "go"

    @property
    def tree_sitter_module(self) -> Optional[str]:
        return "tree_sitter_go"

    @property
    def supported_extensions(self) -> Set[str]:
        return {'.go'}

    @property
    def capabilities(self) -> AnalyzerCapabilities:
        return AnalyzerCapabilities(
            supports_ast=self._tree_sitter_available,
            supports_dataflow=False,
            supports_taint_tracking=True,
            supports_semantic_analysis=True,
        )

    @property
    def dangerous_sinks(self) -> Dict[str, List[str]]:
        return self.DANGEROUS_SINKS

    @property
    def taint_sources(self) -> List[str]:
        return self.TAINT_SOURCES

    def analyze_file(self, file_path: Path, content: str) -> List[Finding]:
        """Analyze a single Go file for security vulnerabilities."""
        findings = []

        # AST-based analysis if available
        if self._tree_sitter_available:
            findings.extend(self._ast_analysis(file_path, content))

        # Pattern-based analysis (fallback or supplement)
        findings.extend(self._pattern_analysis(file_path, content))

        # Check imports for weak crypto
        findings.extend(self._check_imports(file_path, content))

        return findings

    def analyze_files(self, files: List[Path], content_cache: Dict[str, str]) -> List[Finding]:
        """Analyze multiple Go files."""
        findings = []
        for file_path in files:
            if not self.can_analyze(file_path):
                continue
            content = content_cache.get(str(file_path), "")
            if content:
                findings.extend(self.analyze_file(file_path, content))
        return findings

    def get_classes(self, code: str) -> List[ClassInfo]:
        """Extract struct definitions (Go's equivalent of classes)."""
        classes = []
        if not self._tree_sitter_available:
            return self._get_classes_regex(code)

        tree = self._parse(code)
        if not tree:
            return classes

        # Find type_declaration nodes
        type_decls = self._find_nodes_by_type(tree.root_node, 'type_declaration')
        for decl in type_decls:
            # Look for type_spec with struct_type
            for child in decl.children:
                if child.type == 'type_spec':
                    name_node = child.child_by_field_name('name')
                    type_node = child.child_by_field_name('type')
                    if name_node and type_node and type_node.type == 'struct_type':
                        name = self._get_node_text(name_node, code)
                        classes.append(ClassInfo(
                            name=name,
                            file_path="",
                            line_number=decl.start_point[0] + 1,
                            methods=[],
                            fields=self._extract_struct_fields(type_node, code),
                        ))

        return classes

    def get_functions(self, code: str) -> List[FunctionInfo]:
        """Extract function and method definitions."""
        functions = []
        if not self._tree_sitter_available:
            return self._get_functions_regex(code)

        tree = self._parse(code)
        if not tree:
            return functions

        # Find function declarations
        func_decls = self._find_nodes_by_type(tree.root_node, 'function_declaration')
        for decl in func_decls:
            name_node = decl.child_by_field_name('name')
            if name_node:
                name = self._get_node_text(name_node, code)
                params = self._extract_parameters(decl, code)
                functions.append(FunctionInfo(
                    name=name,
                    file_path="",
                    line_number=decl.start_point[0] + 1,
                    end_line=decl.end_point[0] + 1,
                    parameters=params,
                ))

        # Find method declarations
        method_decls = self._find_nodes_by_type(tree.root_node, 'method_declaration')
        for decl in method_decls:
            name_node = decl.child_by_field_name('name')
            if name_node:
                name = self._get_node_text(name_node, code)
                params = self._extract_parameters(decl, code)
                functions.append(FunctionInfo(
                    name=name,
                    file_path="",
                    line_number=decl.start_point[0] + 1,
                    end_line=decl.end_point[0] + 1,
                    parameters=params,
                ))

        return functions

    def get_method_calls(self, code: str) -> List[MethodCall]:
        """Extract method and function calls."""
        calls = []
        if not self._tree_sitter_available:
            return self._get_method_calls_regex(code)

        tree = self._parse(code)
        if not tree:
            return calls

        call_exprs = self._find_nodes_by_type(tree.root_node, 'call_expression')
        for call in call_exprs:
            func_node = call.child_by_field_name('function')
            if func_node:
                full_expr = self._get_node_text(call, code)

                if func_node.type == 'selector_expression':
                    # Method call: obj.method()
                    operand = func_node.child_by_field_name('operand')
                    field = func_node.child_by_field_name('field')
                    if operand and field:
                        obj_name = self._get_node_text(operand, code)
                        method_name = self._get_node_text(field, code)
                        calls.append(MethodCall(
                            name=method_name,
                            object_name=obj_name,
                            arguments=self._extract_call_arguments(call, code),
                            line_number=call.start_point[0] + 1,
                            file_path="",
                            full_expression=full_expr,
                        ))
                else:
                    # Function call: func()
                    func_name = self._get_node_text(func_node, code)
                    calls.append(MethodCall(
                        name=func_name,
                        object_name=None,
                        arguments=self._extract_call_arguments(call, code),
                        line_number=call.start_point[0] + 1,
                        file_path="",
                        full_expression=full_expr,
                    ))

        return calls

    def get_string_literals(self, code: str) -> List[Tuple[str, int]]:
        """Extract string literals with line numbers."""
        strings = []
        if not self._tree_sitter_available:
            return self._get_string_literals_regex(code)

        tree = self._parse(code)
        if not tree:
            return strings

        # Find interpreted_string_literal and raw_string_literal
        for node_type in ['interpreted_string_literal', 'raw_string_literal']:
            for node in self._find_nodes_by_type(tree.root_node, node_type):
                text = self._get_node_text(node, code)
                # Remove quotes
                if text.startswith('"') or text.startswith('`'):
                    text = text[1:-1]
                strings.append((text, node.start_point[0] + 1))

        return strings

    # =========================================================================
    # AST-based Analysis
    # =========================================================================

    def _ast_analysis(self, file_path: Path, content: str) -> List[Finding]:
        """Perform AST-based vulnerability analysis."""
        findings = []

        tree = self._parse(content)
        if not tree:
            return findings

        method_calls = self.get_method_calls(content)

        for call in method_calls:
            # SQL Injection
            if call.name in self.DANGEROUS_SINKS['sql_injection']:
                if self._is_potentially_tainted(call, content):
                    findings.append(self._create_finding(
                        rule_id='GO-SQLI-001',
                        title='Potential SQL Injection',
                        description=f'SQL query method `{call.name}` may use unsanitized input',
                        file_path=file_path,
                        line_number=call.line_number,
                        severity=Severity.HIGH,
                        confidence=Confidence.MEDIUM,
                        cwe='CWE-89',
                        owasp='A03',
                        snippet=call.full_expression[:100],
                        remediation='Use parameterized queries with placeholders',
                    ))

            # Command Injection
            if call.name in self.DANGEROUS_SINKS['command_injection']:
                if self._is_potentially_tainted(call, content):
                    findings.append(self._create_finding(
                        rule_id='GO-CMDI-001',
                        title='Potential Command Injection',
                        description=f'Command execution via `{call.name}` may use unsanitized input',
                        file_path=file_path,
                        line_number=call.line_number,
                        severity=Severity.CRITICAL,
                        confidence=Confidence.MEDIUM,
                        cwe='CWE-78',
                        owasp='A03',
                        snippet=call.full_expression[:100],
                        remediation='Avoid shell execution with user input; use argument arrays',
                    ))

            # Path Traversal
            if call.name in self.DANGEROUS_SINKS['path_traversal']:
                if self._is_potentially_tainted(call, content):
                    findings.append(self._create_finding(
                        rule_id='GO-PATH-001',
                        title='Potential Path Traversal',
                        description=f'File operation `{call.name}` may use unsanitized path',
                        file_path=file_path,
                        line_number=call.line_number,
                        severity=Severity.HIGH,
                        confidence=Confidence.MEDIUM,
                        cwe='CWE-22',
                        owasp='A01',
                        snippet=call.full_expression[:100],
                        remediation='Validate and sanitize file paths; use filepath.Clean',
                    ))

            # SSRF
            if call.name in self.DANGEROUS_SINKS['ssrf']:
                if self._is_potentially_tainted(call, content):
                    findings.append(self._create_finding(
                        rule_id='GO-SSRF-001',
                        title='Potential SSRF',
                        description=f'HTTP request via `{call.name}` may use user-controlled URL',
                        file_path=file_path,
                        line_number=call.line_number,
                        severity=Severity.HIGH,
                        confidence=Confidence.MEDIUM,
                        cwe='CWE-918',
                        owasp='A10',
                        snippet=call.full_expression[:100],
                        remediation='Validate URLs against allowlist; block internal IPs',
                    ))

        return findings

    def _is_potentially_tainted(self, call: MethodCall, content: str) -> bool:
        """Check if a method call may involve tainted input."""
        # Check arguments for taint source patterns
        for arg in call.arguments:
            for source in self.TAINT_SOURCES:
                if re.search(source, arg):
                    return True

        # Check if arguments involve string concatenation or fmt.Sprintf
        full_expr = call.full_expression
        if '+' in full_expr or 'fmt.Sprintf' in full_expr:
            return True

        return False

    # =========================================================================
    # Pattern-based Analysis
    # =========================================================================

    def _pattern_analysis(self, file_path: Path, content: str) -> List[Finding]:
        """Perform regex pattern-based vulnerability analysis."""
        findings = []
        lines = content.split('\n')

        for vuln_type, patterns in self.DANGEROUS_PATTERNS.items():
            for pattern in patterns:
                for match in re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE):
                    line_num = content[:match.start()].count('\n') + 1
                    snippet = lines[line_num - 1].strip() if line_num <= len(lines) else ""

                    severity = Severity.HIGH
                    if vuln_type == 'command_injection':
                        severity = Severity.CRITICAL
                    elif vuln_type == 'hardcoded_secret':
                        severity = Severity.HIGH

                    findings.append(self._create_finding(
                        rule_id=f'GO-{vuln_type.upper()[:4]}-002',
                        title=f'Potential {vuln_type.replace("_", " ").title()}',
                        description=f'Detected pattern matching {vuln_type}',
                        file_path=file_path,
                        line_number=line_num,
                        severity=severity,
                        confidence=Confidence.LOW,
                        cwe=self._get_cwe_for_vuln(vuln_type),
                        owasp=self._get_owasp_for_vuln(vuln_type),
                        snippet=snippet[:100],
                    ))

        return findings

    def _check_imports(self, file_path: Path, content: str) -> List[Finding]:
        """Check for imports of weak crypto packages."""
        findings = []

        for pkg, reason in self.WEAK_CRYPTO_PACKAGES.items():
            # Match import statements
            patterns = [
                rf'import\s+"{pkg}"',
                rf'import\s+\(\s*[^)]*"{pkg}"[^)]*\)',
            ]
            for pattern in patterns:
                if re.search(pattern, content, re.MULTILINE):
                    line_num = 1
                    for i, line in enumerate(content.split('\n'), 1):
                        if pkg in line:
                            line_num = i
                            break

                    findings.append(self._create_finding(
                        rule_id='GO-CRYPTO-001',
                        title='Weak Cryptographic Algorithm',
                        description=f'Import of weak crypto package: {pkg}. {reason}',
                        file_path=file_path,
                        line_number=line_num,
                        severity=Severity.MEDIUM,
                        confidence=Confidence.HIGH,
                        cwe='CWE-327',
                        owasp='A02',
                        snippet=f'import "{pkg}"',
                        remediation='Use crypto/sha256 or crypto/sha512 for hashing; crypto/aes for encryption',
                    ))
                    break

        return findings

    # =========================================================================
    # Helper Methods
    # =========================================================================

    def _extract_struct_fields(self, struct_node, code: str) -> List[str]:
        """Extract field names from a struct definition."""
        fields = []
        field_list = struct_node.child_by_field_name('fields') if hasattr(struct_node, 'child_by_field_name') else None
        if field_list:
            for child in field_list.children:
                if child.type == 'field_declaration':
                    name_node = child.child_by_field_name('name')
                    if name_node:
                        fields.append(self._get_node_text(name_node, code))
        return fields

    def _extract_parameters(self, func_node, code: str) -> List[Tuple[str, str]]:
        """Extract parameter names and types from a function."""
        params = []
        param_list = func_node.child_by_field_name('parameters')
        if param_list:
            for child in param_list.children:
                if child.type == 'parameter_declaration':
                    name_node = child.child_by_field_name('name')
                    type_node = child.child_by_field_name('type')
                    if name_node:
                        name = self._get_node_text(name_node, code)
                        type_str = self._get_node_text(type_node, code) if type_node else ""
                        params.append((name, type_str))
        return params

    def _extract_call_arguments(self, call_node, code: str) -> List[str]:
        """Extract arguments from a function call."""
        args = []
        arg_list = call_node.child_by_field_name('arguments')
        if arg_list:
            for child in arg_list.children:
                if child.type not in ['(', ')', ',']:
                    args.append(self._get_node_text(child, code))
        return args

    def _get_cwe_for_vuln(self, vuln_type: str) -> str:
        """Get CWE ID for a vulnerability type."""
        mapping = {
            'sql_injection': 'CWE-89',
            'command_injection': 'CWE-78',
            'path_traversal': 'CWE-22',
            'ssrf': 'CWE-918',
            'hardcoded_secret': 'CWE-798',
        }
        return mapping.get(vuln_type, '')

    def _get_owasp_for_vuln(self, vuln_type: str) -> str:
        """Get OWASP category for a vulnerability type."""
        mapping = {
            'sql_injection': 'A03',
            'command_injection': 'A03',
            'path_traversal': 'A01',
            'ssrf': 'A10',
            'hardcoded_secret': 'A07',
        }
        return mapping.get(vuln_type, '')

    # =========================================================================
    # Regex Fallback Methods
    # =========================================================================

    def _get_classes_regex(self, code: str) -> List[ClassInfo]:
        """Regex-based struct extraction."""
        classes = []
        pattern = r'type\s+(\w+)\s+struct\s*\{'
        for match in re.finditer(pattern, code):
            line_num = code[:match.start()].count('\n') + 1
            classes.append(ClassInfo(
                name=match.group(1),
                file_path="",
                line_number=line_num,
            ))
        return classes

    def _get_functions_regex(self, code: str) -> List[FunctionInfo]:
        """Regex-based function extraction."""
        functions = []
        pattern = r'func\s+(?:\([^)]+\)\s+)?(\w+)\s*\([^)]*\)'
        for match in re.finditer(pattern, code):
            line_num = code[:match.start()].count('\n') + 1
            functions.append(FunctionInfo(
                name=match.group(1),
                file_path="",
                line_number=line_num,
            ))
        return functions

    def _get_method_calls_regex(self, code: str) -> List[MethodCall]:
        """Regex-based method call extraction."""
        calls = []
        pattern = r'(\w+(?:\.\w+)*)\s*\(([^)]*)\)'
        for match in re.finditer(pattern, code):
            line_num = code[:match.start()].count('\n') + 1
            full_expr = match.group(0)
            parts = match.group(1).split('.')
            if len(parts) > 1:
                obj_name = '.'.join(parts[:-1])
                method_name = parts[-1]
            else:
                obj_name = None
                method_name = parts[0]
            calls.append(MethodCall(
                name=method_name,
                object_name=obj_name,
                arguments=[match.group(2)] if match.group(2) else [],
                line_number=line_num,
                file_path="",
                full_expression=full_expr,
            ))
        return calls

    def _get_string_literals_regex(self, code: str) -> List[Tuple[str, int]]:
        """Regex-based string literal extraction."""
        strings = []
        pattern = r'(?:"([^"\\]*(?:\\.[^"\\]*)*)"|`([^`]*)`)'
        for match in re.finditer(pattern, code):
            line_num = code[:match.start()].count('\n') + 1
            text = match.group(1) or match.group(2) or ""
            strings.append((text, line_num))
        return strings
