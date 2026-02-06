"""
Base classes for SentinelScan analyzers.

This module defines abstract base classes that all analyzers must inherit from:
- BaseAnalyzer: Common interface for all analyzers
- LanguageAnalyzer: AST-based language analyzers
- FrameworkAnalyzer: Framework-specific security analyzers
- IaCAnalyzer: Infrastructure-as-Code analyzers

All analyzers include robust error handling for graceful degradation.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Dict, List, Set, Optional, Any, Tuple
from pathlib import Path
from enum import Enum
import logging
import traceback

# Import from existing models
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))
from models import Finding, Severity, Confidence, Location

logger = logging.getLogger(__name__)


# ============================================================================
# Custom Exceptions
# ============================================================================

class AnalyzerError(Exception):
    """Base exception for analyzer errors."""
    def __init__(self, message: str, analyzer_name: str = "", file_path: str = ""):
        self.message = message
        self.analyzer_name = analyzer_name
        self.file_path = file_path
        super().__init__(f"[{analyzer_name}] {message}" if analyzer_name else message)


class ParseError(AnalyzerError):
    """Error during code parsing."""
    pass


class PatternMatchError(AnalyzerError):
    """Error during pattern matching."""
    pass


class ConfigurationError(AnalyzerError):
    """Error in analyzer configuration."""
    pass


# ============================================================================
# Data Classes
# ============================================================================

@dataclass
class AnalyzerCapabilities:
    """Describes what capabilities an analyzer has."""
    supports_ast: bool = False
    supports_dataflow: bool = False
    supports_taint_tracking: bool = False
    supports_semantic_analysis: bool = False
    supports_cross_file: bool = False


@dataclass
class ClassInfo:
    """Information about a class definition."""
    name: str
    file_path: str
    line_number: int
    extends: Optional[str] = None
    implements: List[str] = field(default_factory=list)
    annotations: List[str] = field(default_factory=list)
    methods: List[str] = field(default_factory=list)
    fields: List[str] = field(default_factory=list)


@dataclass
class FunctionInfo:
    """Information about a function/method definition."""
    name: str
    file_path: str
    line_number: int
    end_line: int = 0
    parameters: List[Tuple[str, str]] = field(default_factory=list)  # (name, type)
    return_type: Optional[str] = None
    annotations: List[str] = field(default_factory=list)
    is_async: bool = False
    is_static: bool = False
    visibility: str = "public"  # public, private, protected


@dataclass
class MethodCall:
    """Information about a method/function call."""
    name: str
    object_name: Optional[str]  # The object the method is called on
    arguments: List[str]
    line_number: int
    file_path: str
    full_expression: str = ""


@dataclass
class Endpoint:
    """Information about an API endpoint."""
    path: str
    method: str  # GET, POST, PUT, DELETE, etc.
    handler: str  # Function/method name
    file_path: str
    line_number: int
    parameters: List[Dict[str, Any]] = field(default_factory=list)
    auth_required: bool = False
    auth_annotations: List[str] = field(default_factory=list)


@dataclass
class SecurityConfig:
    """Security configuration setting."""
    name: str
    value: Any
    file_path: str
    line_number: int
    is_secure: bool
    recommendation: str = ""


@dataclass
class IaCResource:
    """Infrastructure as Code resource definition."""
    resource_type: str  # e.g., "aws_s3_bucket", "kubernetes_deployment"
    name: str
    file_path: str
    line_number: int
    properties: Dict[str, Any] = field(default_factory=dict)
    provider: str = ""  # aws, gcp, azure, kubernetes


class VulnerabilityType(Enum):
    """Types of security vulnerabilities."""
    SQL_INJECTION = "sql_injection"
    COMMAND_INJECTION = "command_injection"
    XSS = "xss"
    PATH_TRAVERSAL = "path_traversal"
    SSRF = "ssrf"
    DESERIALIZATION = "deserialization"
    XXE = "xxe"
    LDAP_INJECTION = "ldap_injection"
    TEMPLATE_INJECTION = "template_injection"
    HARDCODED_SECRET = "hardcoded_secret"
    WEAK_CRYPTO = "weak_crypto"
    MISSING_AUTH = "missing_auth"
    CSRF = "csrf"
    OPEN_REDIRECT = "open_redirect"
    INSECURE_CONFIG = "insecure_config"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    UNSAFE_CODE = "unsafe_code"  # For Rust unsafe blocks


# ============================================================================
# Abstract Base Classes
# ============================================================================

class BaseAnalyzer(ABC):
    """
    Abstract base class for all analyzers.

    All analyzers must implement:
    - name: Unique identifier for the analyzer
    - supported_extensions: File extensions this analyzer handles
    - capabilities: What features the analyzer supports
    - analyze_file: Single file analysis
    - analyze_files: Multi-file analysis (for cross-file analysis)
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Unique name for this analyzer."""
        pass

    @property
    @abstractmethod
    def supported_extensions(self) -> Set[str]:
        """File extensions this analyzer can process (e.g., {'.go', '.mod'})."""
        pass

    @property
    @abstractmethod
    def capabilities(self) -> AnalyzerCapabilities:
        """Capabilities of this analyzer."""
        pass

    @abstractmethod
    def analyze_file(self, file_path: Path, content: str) -> List[Finding]:
        """
        Analyze a single file.

        Args:
            file_path: Path to the file
            content: File contents

        Returns:
            List of security findings
        """
        pass

    @abstractmethod
    def analyze_files(self, files: List[Path], content_cache: Dict[str, str]) -> List[Finding]:
        """
        Analyze multiple files (enables cross-file analysis).

        Args:
            files: List of file paths to analyze
            content_cache: Dictionary mapping file paths to their contents

        Returns:
            List of security findings
        """
        pass

    def can_analyze(self, file_path: Path) -> bool:
        """Check if this analyzer can process the given file."""
        try:
            return file_path.suffix.lower() in self.supported_extensions
        except Exception:
            return False

    def safe_analyze_file(self, file_path: Path, content: str) -> List[Finding]:
        """
        Safely analyze a file with error handling.

        This wrapper catches and logs errors without crashing the scan.

        Args:
            file_path: Path to the file
            content: File contents

        Returns:
            List of findings (empty list on error)
        """
        try:
            return self.analyze_file(file_path, content)
        except UnicodeDecodeError as e:
            logger.warning(f"[{self.name}] Unicode error in {file_path}: {e}")
            return []
        except MemoryError as e:
            logger.error(f"[{self.name}] Memory error analyzing {file_path}: {e}")
            return []
        except RecursionError as e:
            logger.error(f"[{self.name}] Recursion limit in {file_path}: {e}")
            return []
        except Exception as e:
            logger.warning(f"[{self.name}] Error analyzing {file_path}: {e}")
            logger.debug(traceback.format_exc())
            return []

    def safe_analyze_files(self, files: List[Path], content_cache: Dict[str, str]) -> List[Finding]:
        """
        Safely analyze multiple files with error handling.

        Args:
            files: List of file paths
            content_cache: File contents cache

        Returns:
            List of findings (continues on error)
        """
        findings = []
        for file_path in files:
            try:
                if self.can_analyze(file_path):
                    content = content_cache.get(str(file_path), "")
                    if content:
                        file_findings = self.safe_analyze_file(file_path, content)
                        findings.extend(file_findings)
            except Exception as e:
                logger.warning(f"[{self.name}] Error processing {file_path}: {e}")
                continue
        return findings

    def _create_finding(
        self,
        rule_id: str,
        title: str,
        description: str,
        file_path: Path,
        line_number: int,
        severity: Severity,
        confidence: Confidence,
        cwe: str = "",
        owasp: str = "",
        snippet: str = "",
        remediation: str = "",
    ) -> Finding:
        """Helper to create a Finding object."""
        return Finding(
            rule_id=rule_id,
            rule_name=title,  # Finding uses rule_name not title
            description=description,
            severity=severity,
            confidence=confidence,
            location=Location(
                file_path=str(file_path),
                line_number=line_number,
                column=0,
                snippet=snippet,
            ),
            cwe=cwe if cwe else None,
            owasp=owasp if owasp else None,
            remediation=remediation if remediation else None,
        )


class LanguageAnalyzer(BaseAnalyzer, ABC):
    """
    Abstract base class for language-specific AST analyzers.

    Language analyzers use tree-sitter for parsing and provide:
    - Dangerous sink patterns
    - Taint source patterns
    - Class/function extraction
    - Method call extraction
    """

    def __init__(self):
        self.parser = None
        self.language = None
        self._tree_sitter_available = False
        self._initialize_parser()

    @property
    @abstractmethod
    def language_name(self) -> str:
        """Programming language name (e.g., 'go', 'rust', 'csharp')."""
        pass

    @property
    @abstractmethod
    def tree_sitter_module(self) -> Optional[str]:
        """
        Tree-sitter module name (e.g., 'tree_sitter_go').
        Return None if tree-sitter is not used.
        """
        pass

    @property
    @abstractmethod
    def dangerous_sinks(self) -> Dict[str, List[str]]:
        """
        Dangerous sink patterns by vulnerability type.

        Returns:
            Dict mapping VulnerabilityType to list of sink patterns
            e.g., {'sql_injection': ['Query', 'Exec', 'QueryRow']}
        """
        pass

    @property
    @abstractmethod
    def taint_sources(self) -> List[str]:
        """
        Patterns that indicate tainted (user-controlled) input.

        Returns:
            List of patterns like ['r.URL.Query', 'c.Query', 'req.body']
        """
        pass

    @abstractmethod
    def get_classes(self, code: str) -> List[ClassInfo]:
        """Extract class/struct definitions from code."""
        pass

    @abstractmethod
    def get_functions(self, code: str) -> List[FunctionInfo]:
        """Extract function/method definitions from code."""
        pass

    @abstractmethod
    def get_method_calls(self, code: str) -> List[MethodCall]:
        """Extract method/function calls from code."""
        pass

    @abstractmethod
    def get_string_literals(self, code: str) -> List[Tuple[str, int]]:
        """Extract string literals with line numbers."""
        pass

    @property
    def dataflow_config(self) -> Optional[Any]:
        """
        Get the dataflow configuration for this language.

        Returns:
            LanguageDataflowConfig if dataflow is supported, None otherwise.
            Override this in subclasses to provide language-specific dataflow config.
        """
        return None

    def _initialize_parser(self):
        """Initialize the tree-sitter parser if available."""
        if self.tree_sitter_module is None:
            return

        try:
            import importlib
            from tree_sitter import Language, Parser

            ts_module = importlib.import_module(self.tree_sitter_module)
            self.language = Language(ts_module.language())
            self.parser = Parser(self.language)
            self._tree_sitter_available = True
            logger.debug(f"Tree-sitter initialized for {self.language_name}")
        except ImportError as e:
            logger.debug(f"Tree-sitter not available for {self.language_name}: {e}")
            self._tree_sitter_available = False
        except Exception as e:
            logger.warning(f"Failed to initialize tree-sitter for {self.language_name}: {e}")
            self._tree_sitter_available = False

    def _parse(self, code: str):
        """Parse code and return the syntax tree."""
        if not self._tree_sitter_available:
            return None
        try:
            return self.parser.parse(bytes(code, 'utf-8'))
        except Exception as e:
            logger.debug(f"Parse error in {self.language_name}: {e}")
            return None

    def _find_nodes_by_type(self, node, node_type: str) -> List:
        """Recursively find all nodes of a specific type."""
        results = []
        if node.type == node_type:
            results.append(node)
        for child in node.children:
            results.extend(self._find_nodes_by_type(child, node_type))
        return results

    def _get_node_text(self, node, code: str) -> str:
        """Get the text content of a node."""
        return code[node.start_byte:node.end_byte]


class FrameworkAnalyzer(BaseAnalyzer, ABC):
    """
    Abstract base class for framework-specific security analyzers.

    Framework analyzers provide:
    - Framework detection (is this project using this framework?)
    - Endpoint discovery
    - Security configuration analysis
    - Framework-specific vulnerability patterns
    """

    @property
    @abstractmethod
    def framework_name(self) -> str:
        """Framework name (e.g., 'React', 'Django', 'Spring')."""
        pass

    @property
    @abstractmethod
    def base_language(self) -> str:
        """
        Underlying language (e.g., 'javascript', 'python', 'java').
        This helps filter which files to analyze.
        """
        pass

    @property
    @abstractmethod
    def detection_patterns(self) -> List[str]:
        """
        Patterns used to detect if a project uses this framework.
        Can be file patterns, import patterns, or content patterns.
        """
        pass

    @property
    @abstractmethod
    def framework_extensions(self) -> Set[str]:
        """File extensions specific to this framework."""
        pass

    @abstractmethod
    def is_framework_project(self, files: List[Path], content_cache: Dict[str, str]) -> bool:
        """
        Detect if the scanned project uses this framework.

        Args:
            files: All files in the project
            content_cache: File contents cache

        Returns:
            True if the project uses this framework
        """
        pass

    @abstractmethod
    def get_endpoints(self, files: List[Path], content_cache: Dict[str, str]) -> List[Endpoint]:
        """
        Discover API endpoints defined in the project.

        Returns:
            List of discovered endpoints
        """
        pass

    @abstractmethod
    def get_security_configs(self, files: List[Path], content_cache: Dict[str, str]) -> List[SecurityConfig]:
        """
        Analyze security-related configurations.

        Returns:
            List of security configurations with their status
        """
        pass

    def get_framework_files(self, files: List[Path]) -> List[Path]:
        """Filter files relevant to this framework."""
        return [f for f in files if f.suffix.lower() in self.framework_extensions]


class IaCAnalyzer(BaseAnalyzer, ABC):
    """
    Abstract base class for Infrastructure-as-Code analyzers.

    IaC analyzers provide:
    - Resource extraction
    - Misconfiguration detection
    - Best practice validation
    """

    @property
    @abstractmethod
    def iac_type(self) -> str:
        """IaC type (e.g., 'terraform', 'kubernetes', 'cloudformation')."""
        pass

    @property
    @abstractmethod
    def providers(self) -> List[str]:
        """Cloud providers supported (e.g., ['aws', 'gcp', 'azure'])."""
        pass

    @abstractmethod
    def get_resources(self, file_path: Path, content: str) -> List[IaCResource]:
        """
        Extract resource definitions from IaC file.

        Returns:
            List of IaC resources
        """
        pass

    @abstractmethod
    def check_misconfigurations(self, resources: List[IaCResource]) -> List[Finding]:
        """
        Check resources for security misconfigurations.

        Args:
            resources: List of IaC resources to check

        Returns:
            List of security findings for misconfigurations
        """
        pass

    def analyze_file(self, file_path: Path, content: str) -> List[Finding]:
        """Analyze a single IaC file with error handling."""
        try:
            resources = self.get_resources(file_path, content)
            return self.check_misconfigurations(resources)
        except Exception as e:
            logger.warning(f"[{self.name}] Error analyzing IaC file {file_path}: {e}")
            return []

    def analyze_files(self, files: List[Path], content_cache: Dict[str, str]) -> List[Finding]:
        """Analyze multiple IaC files with error handling."""
        all_findings = []
        all_resources = []

        for file_path in files:
            try:
                if not self.can_analyze(file_path):
                    continue
                content = content_cache.get(str(file_path), "")
                if content:
                    resources = self.get_resources(file_path, content)
                    all_resources.extend(resources)
            except Exception as e:
                logger.warning(f"[{self.name}] Error parsing IaC file {file_path}: {e}")
                continue

        # Check misconfigurations across all resources
        try:
            all_findings = self.check_misconfigurations(all_resources)
        except Exception as e:
            logger.warning(f"[{self.name}] Error checking misconfigurations: {e}")
            all_findings = []

        return all_findings
