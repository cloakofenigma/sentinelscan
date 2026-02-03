"""
AST Analyzer - Syntax-aware code analysis using tree-sitter
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import List, Optional, Dict, Any, Tuple, Generator, TYPE_CHECKING
from dataclasses import dataclass, field
import logging

logger = logging.getLogger(__name__)

# Try to import tree-sitter, gracefully handle if not installed
try:
    import tree_sitter_java
    import tree_sitter_python
    import tree_sitter_javascript
    from tree_sitter import Language, Parser, Node
    TREE_SITTER_AVAILABLE = True
except ImportError:
    TREE_SITTER_AVAILABLE = False
    # Define placeholder types for type hints when tree-sitter not installed
    Node = Any  # type: ignore
    Language = Any  # type: ignore
    Parser = Any  # type: ignore
    logger.warning("tree-sitter not installed. AST analysis disabled. "
                   "Install with: pip install tree-sitter tree-sitter-java tree-sitter-python tree-sitter-javascript")


@dataclass
class ASTNode:
    """Represents a node in the AST"""
    type: str
    text: str
    start_line: int
    end_line: int
    start_column: int
    end_column: int
    children: List['ASTNode'] = field(default_factory=list)
    parent_type: Optional[str] = None


@dataclass
class MethodInfo:
    """Information about a method/function"""
    name: str
    class_name: Optional[str]
    start_line: int
    end_line: int
    parameters: List[str]
    return_type: Optional[str]
    annotations: List[str]
    modifiers: List[str]
    body_text: str


@dataclass
class ClassInfo:
    """Information about a class"""
    name: str
    start_line: int
    end_line: int
    extends: Optional[str]
    implements: List[str]
    annotations: List[str]
    methods: List[MethodInfo]
    fields: List[Dict[str, Any]]


@dataclass
class VariableAssignment:
    """Represents a variable assignment for taint tracking"""
    variable_name: str
    value_source: str  # literal, method_call, parameter, field, etc.
    value_text: str
    line_number: int
    is_tainted: bool = False
    taint_source: Optional[str] = None


class ASTAnalyzer:
    """Base AST analyzer"""

    def __init__(self):
        self.parser = None
        self.language = None

    def parse(self, code: str) -> Optional[Any]:
        """Parse code into AST"""
        raise NotImplementedError

    def get_method_calls(self, code: str) -> List[Dict[str, Any]]:
        """Extract all method calls from code"""
        raise NotImplementedError

    def get_string_literals(self, code: str) -> List[Tuple[str, int]]:
        """Extract all string literals with line numbers"""
        raise NotImplementedError

    def get_variable_assignments(self, code: str) -> List[VariableAssignment]:
        """Extract variable assignments for taint tracking"""
        raise NotImplementedError


class JavaASTAnalyzer(ASTAnalyzer):
    """Java-specific AST analyzer using tree-sitter"""

    # Dangerous method calls that could indicate vulnerabilities
    DANGEROUS_SINKS = {
        'sql_injection': [
            'executeQuery', 'executeUpdate', 'execute', 'prepareStatement',
            'createNativeQuery', 'createQuery', 'nativeQuery',
        ],
        'command_injection': [
            'exec', 'getRuntime().exec', 'ProcessBuilder', 'Runtime.exec',
        ],
        'path_traversal': [
            'new File', 'Paths.get', 'FileInputStream', 'FileOutputStream',
            'FileReader', 'FileWriter', 'readFile', 'writeFile',
        ],
        'ssrf': [
            'openConnection', 'URL', 'HttpURLConnection', 'HttpClient',
            'RestTemplate', 'WebClient',
        ],
        'deserialization': [
            'ObjectInputStream', 'readObject', 'readUnshared',
            'XMLDecoder', 'fromXML',
        ],
        'xss': [
            'getWriter().print', 'getWriter().write', 'getOutputStream',
            'sendRedirect', 'forward',
        ],
    }

    # Taint sources - where user input comes from
    TAINT_SOURCES = [
        'getParameter', 'getHeader', 'getCookies', 'getInputStream',
        'getReader', 'getQueryString', 'getPathInfo', 'getRequestURI',
        'getRequestURL', 'getAttribute', 'getSession',
        '@RequestParam', '@PathVariable', '@RequestBody', '@RequestHeader',
    ]

    def __init__(self):
        super().__init__()
        if TREE_SITTER_AVAILABLE:
            self.language = Language(tree_sitter_java.language())
            self.parser = Parser(self.language)

    def parse(self, code: str) -> Optional[Any]:
        """Parse Java code into AST"""
        if not TREE_SITTER_AVAILABLE or not self.parser:
            return None

        try:
            tree = self.parser.parse(bytes(code, 'utf-8'))
            return tree
        except Exception as e:
            logger.debug(f"Failed to parse Java code: {e}")
            return None

    def get_classes(self, code: str) -> List[ClassInfo]:
        """Extract class information from Java code"""
        classes = []
        tree = self.parse(code)
        if not tree:
            return classes

        def find_classes(node: Node, code_bytes: bytes) -> None:
            if node.type == 'class_declaration':
                class_info = self._extract_class_info(node, code_bytes)
                if class_info:
                    classes.append(class_info)

            for child in node.children:
                find_classes(child, code_bytes)

        code_bytes = bytes(code, 'utf-8')
        find_classes(tree.root_node, code_bytes)
        return classes

    def _extract_class_info(self, node: Node, code_bytes: bytes) -> Optional[ClassInfo]:
        """Extract class information from AST node"""
        name = None
        extends = None
        implements = []
        annotations = []
        methods = []
        fields = []

        for child in node.children:
            if child.type == 'identifier':
                name = code_bytes[child.start_byte:child.end_byte].decode('utf-8')
            elif child.type == 'superclass':
                for sc_child in child.children:
                    if sc_child.type == 'type_identifier':
                        extends = code_bytes[sc_child.start_byte:sc_child.end_byte].decode('utf-8')
            elif child.type == 'super_interfaces':
                for iface in child.children:
                    if iface.type == 'type_identifier':
                        implements.append(code_bytes[iface.start_byte:iface.end_byte].decode('utf-8'))
            elif child.type == 'modifiers':
                for mod in child.children:
                    if mod.type == 'marker_annotation' or mod.type == 'annotation':
                        annotations.append(code_bytes[mod.start_byte:mod.end_byte].decode('utf-8'))
            elif child.type == 'class_body':
                methods, fields = self._extract_class_members(child, code_bytes, name)

        if name:
            return ClassInfo(
                name=name,
                start_line=node.start_point[0] + 1,
                end_line=node.end_point[0] + 1,
                extends=extends,
                implements=implements,
                annotations=annotations,
                methods=methods,
                fields=fields,
            )
        return None

    def _extract_class_members(self, body_node: Node, code_bytes: bytes,
                                class_name: str) -> Tuple[List[MethodInfo], List[Dict]]:
        """Extract methods and fields from class body"""
        methods = []
        fields = []

        for child in body_node.children:
            if child.type == 'method_declaration':
                method = self._extract_method_info(child, code_bytes, class_name)
                if method:
                    methods.append(method)
            elif child.type == 'field_declaration':
                field = self._extract_field_info(child, code_bytes)
                if field:
                    fields.append(field)

        return methods, fields

    def _extract_method_info(self, node: Node, code_bytes: bytes,
                              class_name: str) -> Optional[MethodInfo]:
        """Extract method information"""
        name = None
        return_type = None
        parameters = []
        annotations = []
        modifiers = []

        for child in node.children:
            if child.type == 'identifier':
                name = code_bytes[child.start_byte:child.end_byte].decode('utf-8')
            elif child.type in ['type_identifier', 'void_type', 'generic_type']:
                return_type = code_bytes[child.start_byte:child.end_byte].decode('utf-8')
            elif child.type == 'formal_parameters':
                for param in child.children:
                    if param.type == 'formal_parameter':
                        param_text = code_bytes[param.start_byte:param.end_byte].decode('utf-8')
                        parameters.append(param_text)
            elif child.type == 'modifiers':
                for mod in child.children:
                    if mod.type in ['marker_annotation', 'annotation']:
                        annotations.append(code_bytes[mod.start_byte:mod.end_byte].decode('utf-8'))
                    elif mod.type in ['public', 'private', 'protected', 'static', 'final']:
                        modifiers.append(mod.type)

        if name:
            body_text = code_bytes[node.start_byte:node.end_byte].decode('utf-8')
            return MethodInfo(
                name=name,
                class_name=class_name,
                start_line=node.start_point[0] + 1,
                end_line=node.end_point[0] + 1,
                parameters=parameters,
                return_type=return_type,
                annotations=annotations,
                modifiers=modifiers,
                body_text=body_text,
            )
        return None

    def _extract_field_info(self, node: Node, code_bytes: bytes) -> Optional[Dict]:
        """Extract field information"""
        field_text = code_bytes[node.start_byte:node.end_byte].decode('utf-8')
        return {
            'text': field_text,
            'line': node.start_point[0] + 1,
        }

    def get_method_calls(self, code: str) -> List[Dict[str, Any]]:
        """Extract all method calls"""
        calls = []
        tree = self.parse(code)
        if not tree:
            return calls

        code_bytes = bytes(code, 'utf-8')

        def find_calls(node: Node) -> None:
            if node.type == 'method_invocation':
                call_info = {
                    'text': code_bytes[node.start_byte:node.end_byte].decode('utf-8'),
                    'line': node.start_point[0] + 1,
                    'method_name': None,
                    'object': None,
                    'arguments': [],
                }

                for child in node.children:
                    if child.type == 'identifier':
                        call_info['method_name'] = code_bytes[child.start_byte:child.end_byte].decode('utf-8')
                    elif child.type == 'field_access':
                        call_info['object'] = code_bytes[child.start_byte:child.end_byte].decode('utf-8')
                    elif child.type == 'argument_list':
                        for arg in child.children:
                            if arg.type not in ['(', ')', ',']:
                                call_info['arguments'].append(
                                    code_bytes[arg.start_byte:arg.end_byte].decode('utf-8')
                                )

                calls.append(call_info)

            for child in node.children:
                find_calls(child)

        find_calls(tree.root_node)
        return calls

    def get_string_literals(self, code: str) -> List[Tuple[str, int]]:
        """Extract all string literals with line numbers"""
        literals = []
        tree = self.parse(code)
        if not tree:
            return literals

        code_bytes = bytes(code, 'utf-8')

        def find_strings(node: Node) -> None:
            if node.type == 'string_literal':
                text = code_bytes[node.start_byte:node.end_byte].decode('utf-8')
                # Remove quotes
                if text.startswith('"') and text.endswith('"'):
                    text = text[1:-1]
                literals.append((text, node.start_point[0] + 1))

            for child in node.children:
                find_strings(child)

        find_strings(tree.root_node)
        return literals

    def get_variable_assignments(self, code: str) -> List[VariableAssignment]:
        """Extract variable assignments for taint tracking"""
        assignments = []
        tree = self.parse(code)
        if not tree:
            return assignments

        code_bytes = bytes(code, 'utf-8')

        def find_assignments(node: Node) -> None:
            if node.type == 'local_variable_declaration':
                assignment = self._parse_variable_declaration(node, code_bytes)
                if assignment:
                    assignments.append(assignment)
            elif node.type == 'assignment_expression':
                assignment = self._parse_assignment(node, code_bytes)
                if assignment:
                    assignments.append(assignment)

            for child in node.children:
                find_assignments(child)

        find_assignments(tree.root_node)
        return assignments

    def _parse_variable_declaration(self, node: Node, code_bytes: bytes) -> Optional[VariableAssignment]:
        """Parse a variable declaration"""
        var_name = None
        value_text = ""
        value_source = "unknown"

        for child in node.children:
            if child.type == 'variable_declarator':
                for vc in child.children:
                    if vc.type == 'identifier':
                        var_name = code_bytes[vc.start_byte:vc.end_byte].decode('utf-8')
                    elif vc.type not in ['=', 'identifier']:
                        value_text = code_bytes[vc.start_byte:vc.end_byte].decode('utf-8')
                        value_source = self._determine_value_source(vc)

        if var_name:
            is_tainted, taint_source = self._check_taint(value_text)
            return VariableAssignment(
                variable_name=var_name,
                value_source=value_source,
                value_text=value_text,
                line_number=node.start_point[0] + 1,
                is_tainted=is_tainted,
                taint_source=taint_source,
            )
        return None

    def _parse_assignment(self, node: Node, code_bytes: bytes) -> Optional[VariableAssignment]:
        """Parse an assignment expression"""
        var_name = None
        value_text = ""
        value_source = "unknown"

        children = list(node.children)
        if len(children) >= 3:
            var_name = code_bytes[children[0].start_byte:children[0].end_byte].decode('utf-8')
            value_text = code_bytes[children[2].start_byte:children[2].end_byte].decode('utf-8')
            value_source = self._determine_value_source(children[2])

        if var_name:
            is_tainted, taint_source = self._check_taint(value_text)
            return VariableAssignment(
                variable_name=var_name,
                value_source=value_source,
                value_text=value_text,
                line_number=node.start_point[0] + 1,
                is_tainted=is_tainted,
                taint_source=taint_source,
            )
        return None

    def _determine_value_source(self, node: Node) -> str:
        """Determine the source type of a value"""
        if node.type == 'string_literal':
            return 'literal'
        elif node.type == 'method_invocation':
            return 'method_call'
        elif node.type == 'identifier':
            return 'variable'
        elif node.type == 'field_access':
            return 'field'
        elif node.type in ['decimal_integer_literal', 'hex_integer_literal']:
            return 'literal'
        elif node.type == 'object_creation_expression':
            return 'constructor'
        elif node.type == 'binary_expression':
            return 'expression'
        return 'unknown'

    def _check_taint(self, value_text: str) -> Tuple[bool, Optional[str]]:
        """Check if a value comes from a taint source"""
        for source in self.TAINT_SOURCES:
            if source in value_text:
                return True, source
        return False, None

    def find_dangerous_patterns(self, code: str) -> List[Dict[str, Any]]:
        """Find potentially dangerous code patterns"""
        findings = []

        # Get method calls
        calls = self.get_method_calls(code)

        # Get variable assignments to track taint
        assignments = self.get_variable_assignments(code)
        tainted_vars = {a.variable_name for a in assignments if a.is_tainted}

        for call in calls:
            method_name = call.get('method_name', '')
            full_text = call.get('text', '')

            # Check against dangerous sinks
            for vuln_type, sinks in self.DANGEROUS_SINKS.items():
                for sink in sinks:
                    if sink in method_name or sink in full_text:
                        # Check if any argument is tainted
                        is_vulnerable = False
                        for arg in call.get('arguments', []):
                            # Check if argument contains tainted variable
                            for tainted in tainted_vars:
                                if tainted in arg:
                                    is_vulnerable = True
                                    break
                            # Check for string concatenation (potential injection)
                            if '+' in arg and '"' in arg:
                                is_vulnerable = True

                        if is_vulnerable:
                            findings.append({
                                'type': vuln_type,
                                'sink': sink,
                                'line': call['line'],
                                'code': full_text,
                                'confidence': 'high' if any(t in full_text for t in self.TAINT_SOURCES) else 'medium',
                            })

        return findings


class PythonASTAnalyzer(ASTAnalyzer):
    """Python-specific AST analyzer"""

    DANGEROUS_SINKS = {
        'sql_injection': ['execute', 'executemany', 'raw', 'extra'],
        'command_injection': ['system', 'popen', 'subprocess', 'exec', 'eval'],
        'path_traversal': ['open', 'read', 'write', 'Path'],
        'deserialization': ['pickle.loads', 'pickle.load', 'yaml.load', 'marshal.loads'],
        'ssrf': ['requests.get', 'requests.post', 'urllib.request', 'httpx'],
    }

    TAINT_SOURCES = [
        'request.args', 'request.form', 'request.data', 'request.json',
        'request.GET', 'request.POST', 'input(', 'sys.argv',
    ]

    def __init__(self):
        super().__init__()
        if TREE_SITTER_AVAILABLE:
            self.language = Language(tree_sitter_python.language())
            self.parser = Parser(self.language)

    def parse(self, code: str) -> Optional[Any]:
        """Parse Python code into AST"""
        if not TREE_SITTER_AVAILABLE or not self.parser:
            return None

        try:
            tree = self.parser.parse(bytes(code, 'utf-8'))
            return tree
        except Exception as e:
            logger.debug(f"Failed to parse Python code: {e}")
            return None

    def get_function_definitions(self, code: str) -> List[Dict[str, Any]]:
        """Extract function definitions"""
        functions = []
        tree = self.parse(code)
        if not tree:
            return functions

        code_bytes = bytes(code, 'utf-8')

        def find_functions(node: Node) -> None:
            if node.type == 'function_definition':
                func_info = {
                    'name': None,
                    'line': node.start_point[0] + 1,
                    'parameters': [],
                    'decorators': [],
                }

                for child in node.children:
                    if child.type == 'identifier':
                        func_info['name'] = code_bytes[child.start_byte:child.end_byte].decode('utf-8')
                    elif child.type == 'parameters':
                        for param in child.children:
                            if param.type == 'identifier':
                                func_info['parameters'].append(
                                    code_bytes[param.start_byte:param.end_byte].decode('utf-8')
                                )
                    elif child.type == 'decorator':
                        func_info['decorators'].append(
                            code_bytes[child.start_byte:child.end_byte].decode('utf-8')
                        )

                functions.append(func_info)

            for child in node.children:
                find_functions(child)

        find_functions(tree.root_node)
        return functions

    def get_method_calls(self, code: str) -> List[Dict[str, Any]]:
        """Extract method/function calls"""
        calls = []
        tree = self.parse(code)
        if not tree:
            return calls

        code_bytes = bytes(code, 'utf-8')

        def find_calls(node: Node) -> None:
            if node.type == 'call':
                call_info = {
                    'text': code_bytes[node.start_byte:node.end_byte].decode('utf-8'),
                    'line': node.start_point[0] + 1,
                    'function': None,
                    'arguments': [],
                }

                for child in node.children:
                    if child.type in ['identifier', 'attribute']:
                        call_info['function'] = code_bytes[child.start_byte:child.end_byte].decode('utf-8')
                    elif child.type == 'argument_list':
                        for arg in child.children:
                            if arg.type not in ['(', ')', ',']:
                                call_info['arguments'].append(
                                    code_bytes[arg.start_byte:arg.end_byte].decode('utf-8')
                                )

                calls.append(call_info)

            for child in node.children:
                find_calls(child)

        find_calls(tree.root_node)
        return calls


class JavaScriptASTAnalyzer(ASTAnalyzer):
    """JavaScript/TypeScript AST analyzer"""

    DANGEROUS_SINKS = {
        'xss': ['innerHTML', 'outerHTML', 'document.write', 'eval'],
        'sql_injection': ['query', 'execute', 'raw'],
        'command_injection': ['exec', 'spawn', 'execSync'],
        'path_traversal': ['readFile', 'writeFile', 'createReadStream'],
        'ssrf': ['fetch', 'axios', 'request', 'http.get'],
    }

    TAINT_SOURCES = [
        'req.body', 'req.query', 'req.params', 'req.headers',
        'request.body', 'request.query', 'request.params',
        'document.location', 'window.location', 'location.search',
    ]

    def __init__(self):
        super().__init__()
        if TREE_SITTER_AVAILABLE:
            self.language = Language(tree_sitter_javascript.language())
            self.parser = Parser(self.language)

    def parse(self, code: str) -> Optional[Any]:
        """Parse JavaScript code into AST"""
        if not TREE_SITTER_AVAILABLE or not self.parser:
            return None

        try:
            tree = self.parser.parse(bytes(code, 'utf-8'))
            return tree
        except Exception as e:
            logger.debug(f"Failed to parse JavaScript code: {e}")
            return None

    def get_method_calls(self, code: str) -> List[Dict[str, Any]]:
        """Extract function/method calls"""
        calls = []
        tree = self.parse(code)
        if not tree:
            return calls

        code_bytes = bytes(code, 'utf-8')

        def find_calls(node: Node) -> None:
            if node.type == 'call_expression':
                call_info = {
                    'text': code_bytes[node.start_byte:node.end_byte].decode('utf-8'),
                    'line': node.start_point[0] + 1,
                    'function': None,
                    'arguments': [],
                }

                for child in node.children:
                    if child.type in ['identifier', 'member_expression']:
                        call_info['function'] = code_bytes[child.start_byte:child.end_byte].decode('utf-8')
                    elif child.type == 'arguments':
                        for arg in child.children:
                            if arg.type not in ['(', ')', ',']:
                                call_info['arguments'].append(
                                    code_bytes[arg.start_byte:arg.end_byte].decode('utf-8')
                                )

                calls.append(call_info)

            for child in node.children:
                find_calls(child)

        find_calls(tree.root_node)
        return calls


def get_ast_analyzer(language: str) -> Optional[ASTAnalyzer]:
    """Factory function to get appropriate AST analyzer"""
    if not TREE_SITTER_AVAILABLE:
        return None

    analyzers = {
        'java': JavaASTAnalyzer,
        'python': PythonASTAnalyzer,
        'javascript': JavaScriptASTAnalyzer,
        'typescript': JavaScriptASTAnalyzer,
    }

    analyzer_class = analyzers.get(language.lower())
    if analyzer_class:
        return analyzer_class()
    return None
