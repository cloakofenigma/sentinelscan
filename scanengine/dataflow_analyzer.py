"""
Dataflow Analyzer - Inter-procedural taint tracking and dataflow analysis
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import List, Dict, Set, Optional, Tuple, Any
from dataclasses import dataclass, field
from collections import defaultdict
from enum import Enum
import logging

from .call_graph import CallGraph, CallGraphBuilder, MethodSignature, MethodCall, CallGraphNode
from .ast_analyzer import JavaASTAnalyzer, TREE_SITTER_AVAILABLE
from .models import Finding, Severity, Confidence, Location

logger = logging.getLogger(__name__)


class TaintSource(Enum):
    """Types of taint sources"""
    HTTP_PARAMETER = "http_parameter"
    HTTP_HEADER = "http_header"
    HTTP_BODY = "http_body"
    PATH_VARIABLE = "path_variable"
    COOKIE = "cookie"
    DATABASE = "database"
    FILE_INPUT = "file_input"
    USER_INPUT = "user_input"
    ENVIRONMENT = "environment"


class SinkType(Enum):
    """Types of dangerous sinks"""
    SQL_QUERY = "sql_query"
    COMMAND_EXEC = "command_exec"
    FILE_ACCESS = "file_access"
    SSRF = "ssrf"
    XSS = "xss"
    LDAP_QUERY = "ldap_query"
    XPATH_QUERY = "xpath_query"
    DESERIALIZATION = "deserialization"
    LOG_OUTPUT = "log_output"


@dataclass
class TaintedValue:
    """Represents a tainted value"""
    variable_name: str
    source_type: TaintSource
    source_location: str  # file:line
    source_annotation: Optional[str] = None
    propagation_path: List[str] = field(default_factory=list)

    def add_propagation(self, step: str):
        """Add a propagation step"""
        self.propagation_path.append(step)


@dataclass
class TaintState:
    """Taint state for a method"""
    method_id: str
    tainted_params: Dict[str, TaintedValue] = field(default_factory=dict)
    tainted_locals: Dict[str, TaintedValue] = field(default_factory=dict)
    tainted_return: Optional[TaintedValue] = None

    @property
    def all_tainted(self) -> Dict[str, TaintedValue]:
        """Get all tainted variables"""
        return {**self.tainted_params, **self.tainted_locals}


@dataclass
class DataflowVulnerability:
    """Represents a detected dataflow vulnerability"""
    sink_type: SinkType
    source: TaintedValue
    sink_location: str  # file:line
    sink_code: str
    method_chain: List[str]  # Methods the data flowed through
    confidence: Confidence = Confidence.HIGH


class TaintSourceDetector:
    """Detects taint sources in code"""

    # Java/Spring taint source patterns
    JAVA_SOURCES = {
        TaintSource.HTTP_PARAMETER: [
            r'@RequestParam\s+\w+\s+(\w+)',
            r'@QueryParam\s+\w+\s+(\w+)',
            r'request\.getParameter\s*\(\s*["\'](\w+)["\']\s*\)',
            r'getParameter\s*\(\s*["\'](\w+)["\']\s*\)',
        ],
        TaintSource.PATH_VARIABLE: [
            r'@PathVariable\s+(?:\w+\s+)?(\w+)',
            r'@PathParam\s+(?:\w+\s+)?(\w+)',
        ],
        TaintSource.HTTP_BODY: [
            r'@RequestBody\s+\w+\s+(\w+)',
        ],
        TaintSource.HTTP_HEADER: [
            r'@RequestHeader\s+(?:\w+\s+)?(\w+)',
            r'request\.getHeader\s*\(\s*["\'](\w+)["\']\s*\)',
        ],
        TaintSource.COOKIE: [
            r'@CookieValue\s+(?:\w+\s+)?(\w+)',
            r'request\.getCookies\s*\(\s*\)',
        ],
    }

    # Python/Flask/Django taint sources
    PYTHON_SOURCES = {
        TaintSource.HTTP_PARAMETER: [
            r'request\.args\.get\s*\(\s*["\'](\w+)["\']\s*\)',
            r'request\.GET\.get\s*\(\s*["\'](\w+)["\']\s*\)',
            r'request\.form\.get\s*\(\s*["\'](\w+)["\']\s*\)',
            r'request\.POST\.get\s*\(\s*["\'](\w+)["\']\s*\)',
        ],
        TaintSource.HTTP_BODY: [
            r'request\.json',
            r'request\.data',
            r'request\.body',
        ],
        TaintSource.PATH_VARIABLE: [
            r'def\s+\w+\s*\([^)]*(\w+)[^)]*\):',  # Flask route params
        ],
    }

    def __init__(self):
        self._compiled_java = self._compile_patterns(self.JAVA_SOURCES)
        self._compiled_python = self._compile_patterns(self.PYTHON_SOURCES)

    def _compile_patterns(self, sources: Dict) -> Dict[TaintSource, List[re.Pattern]]:
        """Compile regex patterns"""
        compiled = {}
        for source_type, patterns in sources.items():
            compiled[source_type] = [re.compile(p) for p in patterns]
        return compiled

    def detect_sources_java(self, code: str, file_path: str) -> List[TaintedValue]:
        """Detect taint sources in Java code"""
        tainted = []
        lines = code.splitlines()

        for line_num, line in enumerate(lines, 1):
            for source_type, patterns in self._compiled_java.items():
                for pattern in patterns:
                    match = pattern.search(line)
                    if match:
                        var_name = match.group(1) if match.lastindex else "unknown"
                        tainted.append(TaintedValue(
                            variable_name=var_name,
                            source_type=source_type,
                            source_location=f"{file_path}:{line_num}",
                            source_annotation=match.group(0),
                        ))

        return tainted

    def detect_sources_python(self, code: str, file_path: str) -> List[TaintedValue]:
        """Detect taint sources in Python code"""
        tainted = []
        lines = code.splitlines()

        for line_num, line in enumerate(lines, 1):
            for source_type, patterns in self._compiled_python.items():
                for pattern in patterns:
                    match = pattern.search(line)
                    if match:
                        var_name = match.group(1) if match.lastindex else "unknown"
                        tainted.append(TaintedValue(
                            variable_name=var_name,
                            source_type=source_type,
                            source_location=f"{file_path}:{line_num}",
                            source_annotation=match.group(0),
                        ))

        return tainted


class SinkDetector:
    """Detects dangerous sinks in code"""

    JAVA_SINKS = {
        SinkType.SQL_QUERY: [
            r'executeQuery\s*\(',
            r'executeUpdate\s*\(',
            r'createNativeQuery\s*\(',
            r'createQuery\s*\(',
            r'jdbcTemplate\.\w+\s*\(',
            r'\$\{[^}]+\}',  # MyBatis interpolation
        ],
        SinkType.COMMAND_EXEC: [
            r'Runtime\.getRuntime\(\)\.exec\s*\(',
            r'ProcessBuilder\s*\(',
            r'\.exec\s*\(',
        ],
        SinkType.FILE_ACCESS: [
            r'new\s+File\s*\(',
            r'new\s+FileInputStream\s*\(',
            r'new\s+FileOutputStream\s*\(',
            r'Files\.read',
            r'Files\.write',
            r'Paths\.get\s*\(',
        ],
        SinkType.SSRF: [
            r'new\s+URL\s*\(',
            r'openConnection\s*\(',
            r'RestTemplate.*\.\w+\s*\(',
            r'WebClient.*\.uri\s*\(',
            r'HttpClient.*\.send\s*\(',
        ],
        SinkType.XSS: [
            r'response\.getWriter\(\)\.(print|write)\s*\(',
            r'\.innerHTML\s*=',
            r'document\.write\s*\(',
        ],
        SinkType.DESERIALIZATION: [
            r'ObjectInputStream\s*\(',
            r'\.readObject\s*\(',
            r'XMLDecoder\s*\(',
        ],
        SinkType.LOG_OUTPUT: [
            r'logger\.(info|debug|warn|error)\s*\(',
            r'log\.(info|debug|warn|error)\s*\(',
        ],
    }

    def __init__(self):
        self._compiled_java = {}
        for sink_type, patterns in self.JAVA_SINKS.items():
            self._compiled_java[sink_type] = [re.compile(p) for p in patterns]

    def detect_sinks_java(self, code: str, file_path: str) -> List[Tuple[SinkType, int, str]]:
        """Detect dangerous sinks in Java code"""
        sinks = []
        lines = code.splitlines()

        for line_num, line in enumerate(lines, 1):
            for sink_type, patterns in self._compiled_java.items():
                for pattern in patterns:
                    if pattern.search(line):
                        sinks.append((sink_type, line_num, line.strip()))
                        break  # One sink per line per type

        return sinks


class DataflowAnalyzer:
    """
    Performs inter-procedural dataflow analysis to track tainted data
    from sources to sinks across method boundaries.
    """

    def __init__(self, call_graph: CallGraph = None):
        self.call_graph = call_graph or CallGraph()
        self.source_detector = TaintSourceDetector()
        self.sink_detector = SinkDetector()
        self.taint_states: Dict[str, TaintState] = {}
        self.vulnerabilities: List[DataflowVulnerability] = []

    def analyze_files(self, files: List[Path], content_cache: Dict[str, str] = None) -> List[DataflowVulnerability]:
        """Analyze files for dataflow vulnerabilities"""
        content_cache = content_cache or {}

        # Build call graph if not provided
        if not self.call_graph.nodes:
            builder = CallGraphBuilder()
            self.call_graph = builder.build_from_files(files, content_cache)
            logger.info(f"Built call graph: {self.call_graph.stats()}")

        # Phase 1: Detect all taint sources
        self._detect_all_sources(files, content_cache)

        # Phase 2: Propagate taint through call graph
        self._propagate_taint()

        # Phase 3: Check for tainted data reaching sinks
        self._check_sinks(files, content_cache)

        return self.vulnerabilities

    def _detect_all_sources(self, files: List[Path], content_cache: Dict[str, str]):
        """Detect taint sources in all files"""
        for file_path in files:
            content = content_cache.get(str(file_path))
            if not content:
                continue

            file_str = str(file_path)
            suffix = file_path.suffix.lower()

            # Detect sources based on language
            if suffix == '.java':
                sources = self.source_detector.detect_sources_java(content, file_str)
            elif suffix == '.py':
                sources = self.source_detector.detect_sources_python(content, file_str)
            else:
                continue

            # Associate sources with methods
            for source in sources:
                self._associate_source_with_method(source, file_str)

    def _associate_source_with_method(self, source: TaintedValue, file_path: str):
        """Associate a taint source with its containing method"""
        # Find the method containing this source
        methods = self.call_graph.find_methods_in_file(file_path)

        source_line = int(source.source_location.split(':')[-1])

        # Sort methods by line number to find the correct containing method
        sorted_methods = sorted(methods, key=lambda m: m.signature.line_number)

        # Find the method that contains this line (method with highest start line <= source_line)
        containing_method = None
        for method in sorted_methods:
            if method.signature.line_number <= source_line:
                containing_method = method
            else:
                break

        if containing_method:
            method_id = containing_method.signature.unique_id

            if method_id not in self.taint_states:
                self.taint_states[method_id] = TaintState(method_id=method_id)

            # Add as tainted parameter
            self.taint_states[method_id].tainted_params[source.variable_name] = source
            logger.debug(f"Associated taint {source.variable_name} with method {containing_method.signature.method_name}")

    def _propagate_taint(self):
        """Propagate taint through the call graph"""
        # Worklist algorithm for taint propagation
        worklist = list(self.taint_states.keys())
        iterations = 0
        max_iterations = len(self.call_graph.nodes) * 2

        while worklist and iterations < max_iterations:
            iterations += 1
            method_id = worklist.pop(0)

            if method_id not in self.taint_states:
                continue

            state = self.taint_states[method_id]
            node = self.call_graph.get_method(method_id)

            if not node:
                continue

            # Propagate taint to callees
            for callee_id in node.callees:
                changed = self._propagate_to_callee(state, callee_id, node.call_sites)
                if changed and callee_id not in worklist:
                    worklist.append(callee_id)

        logger.debug(f"Taint propagation completed in {iterations} iterations")

    def _propagate_to_callee(self, caller_state: TaintState, callee_id: str,
                             call_sites: List[MethodCall]) -> bool:
        """Propagate taint from caller to callee"""
        callee_node = self.call_graph.get_method(callee_id)
        if not callee_node:
            return False

        if callee_id not in self.taint_states:
            self.taint_states[callee_id] = TaintState(method_id=callee_id)

        callee_state = self.taint_states[callee_id]
        changed = False

        # Find call sites to this callee
        for call in call_sites:
            if call.callee_name == callee_node.signature.method_name:
                # Check if any arguments are tainted
                for i, arg in enumerate(call.arguments):
                    for var_name, taint in caller_state.all_tainted.items():
                        if var_name in arg:
                            # Propagate taint to callee parameter
                            param_name = f"param_{i}"
                            if param_name not in callee_state.tainted_params:
                                new_taint = TaintedValue(
                                    variable_name=param_name,
                                    source_type=taint.source_type,
                                    source_location=taint.source_location,
                                    source_annotation=taint.source_annotation,
                                    propagation_path=taint.propagation_path + [
                                        f"{caller_state.method_id} -> {callee_id}"
                                    ],
                                )
                                callee_state.tainted_params[param_name] = new_taint
                                changed = True

        return changed

    def _check_sinks(self, files: List[Path], content_cache: Dict[str, str]):
        """Check if tainted data reaches dangerous sinks"""
        for file_path in files:
            content = content_cache.get(str(file_path))
            if not content:
                continue

            file_str = str(file_path)
            suffix = file_path.suffix.lower()

            if suffix != '.java':
                continue

            # Detect sinks
            sinks = self.sink_detector.detect_sinks_java(content, file_str)

            # Check each sink against taint states
            for sink_type, line_num, sink_code in sinks:
                self._check_sink_for_taint(sink_type, line_num, sink_code, file_str, content)

    def _check_sink_for_taint(self, sink_type: SinkType, line_num: int,
                              sink_code: str, file_path: str, content: str):
        """Check if a sink uses tainted data"""
        # Find the method containing this sink
        methods = self.call_graph.find_methods_in_file(file_path)

        # Sort and find containing method
        sorted_methods = sorted(methods, key=lambda m: m.signature.line_number)
        containing_method = None
        for method in sorted_methods:
            if method.signature.line_number <= line_num:
                containing_method = method
            else:
                break

        if not containing_method:
            return

        method_id = containing_method.signature.unique_id
        state = self.taint_states.get(method_id)

        if not state:
            return

        # Check if any tainted variable is used in the sink or flows to it
        for var_name, taint in state.all_tainted.items():
            # Direct usage in sink
            if var_name in sink_code:
                self._add_vulnerability(sink_type, taint, file_path, line_num, sink_code, method_id)
                continue

            # Check for indirect flow (variable used in expression that reaches sink)
            if self._variable_flows_to_sink(var_name, sink_code, content, line_num):
                self._add_vulnerability(sink_type, taint, file_path, line_num, sink_code, method_id)

    def _add_vulnerability(self, sink_type: SinkType, taint: TaintedValue,
                          file_path: str, line_num: int, sink_code: str, method_id: str):
        """Add a vulnerability to the list"""
        vuln = DataflowVulnerability(
            sink_type=sink_type,
            source=taint,
            sink_location=f"{file_path}:{line_num}",
            sink_code=sink_code,
            method_chain=taint.propagation_path + [method_id],
            confidence=Confidence.HIGH,
        )
        self.vulnerabilities.append(vuln)
        logger.info(f"Found {sink_type.value} vulnerability: {taint.source_type.value} -> sink at line {line_num}")

    def _variable_flows_to_sink(self, var_name: str, sink_code: str, content: str, sink_line: int) -> bool:
        """Check if a variable flows into a sink (basic check)"""
        # Direct usage
        if var_name in sink_code:
            return True

        # Check for string concatenation with the variable in nearby lines
        lines = content.splitlines()
        start = max(0, sink_line - 5)
        end = min(len(lines), sink_line + 1)
        context = '\n'.join(lines[start:end])

        # Check for common patterns
        patterns = [
            f'{var_name}\\s*\\+',  # var + something
            f'\\+\\s*{var_name}',  # something + var
            f'\\$\\{{{var_name}\\}}',  # ${var}
            f'%s.*{var_name}',  # format string
            f'{var_name}\\)',  # passed as argument
        ]

        for pattern in patterns:
            if re.search(pattern, context):
                return True

        return False

    def get_findings(self) -> List[Finding]:
        """Convert vulnerabilities to Finding objects"""
        findings = []

        sink_to_vuln_type = {
            SinkType.SQL_QUERY: ("SQL Injection", "CWE-89", "A03"),
            SinkType.COMMAND_EXEC: ("Command Injection", "CWE-78", "A03"),
            SinkType.FILE_ACCESS: ("Path Traversal", "CWE-22", "A01"),
            SinkType.SSRF: ("Server-Side Request Forgery", "CWE-918", "A10"),
            SinkType.XSS: ("Cross-Site Scripting", "CWE-79", "A03"),
            SinkType.DESERIALIZATION: ("Insecure Deserialization", "CWE-502", "A08"),
            SinkType.LOG_OUTPUT: ("Sensitive Data Logging", "CWE-532", "A09"),
        }

        for vuln in self.vulnerabilities:
            vuln_info = sink_to_vuln_type.get(vuln.sink_type, ("Unknown", "N/A", "N/A"))

            file_path, line_str = vuln.sink_location.rsplit(':', 1)
            line_num = int(line_str)

            finding = Finding(
                rule_id=f"DATAFLOW-{vuln.sink_type.value.upper()}",
                rule_name=f"{vuln_info[0]} via {vuln.source.source_type.value}",
                description=f"Tainted data from {vuln.source.source_type.value} ({vuln.source.variable_name}) "
                           f"flows to {vuln.sink_type.value} sink. "
                           f"Flow: {' -> '.join(vuln.method_chain) if vuln.method_chain else 'direct'}",
                severity=Severity.HIGH if vuln.sink_type in [SinkType.SQL_QUERY, SinkType.COMMAND_EXEC] else Severity.MEDIUM,
                confidence=vuln.confidence,
                location=Location(
                    file_path=file_path,
                    line_number=line_num,
                    snippet=vuln.sink_code,
                ),
                cwe=vuln_info[1] if vuln_info[1] != "N/A" else None,
                owasp=vuln_info[2] if vuln_info[2] != "N/A" else None,
                tags=['dataflow', vuln.sink_type.value, vuln.source.source_type.value],
                remediation=f"Sanitize or validate the {vuln.source.source_type.value} input before using in {vuln.sink_type.value}",
            )
            findings.append(finding)

        return findings


def analyze_dataflow(files: List[Path], content_cache: Dict[str, str] = None) -> List[Finding]:
    """Convenience function to run dataflow analysis"""
    analyzer = DataflowAnalyzer()
    analyzer.analyze_files(files, content_cache)
    return analyzer.get_findings()
