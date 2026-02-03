"""
Spring Framework Analyzer - Specialized security analysis for Spring Boot applications
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import List, Dict, Set, Optional, Tuple, Any
from dataclasses import dataclass, field
from enum import Enum
import logging

from .models import Finding, Severity, Confidence, Location
from .ast_analyzer import JavaASTAnalyzer, TREE_SITTER_AVAILABLE

logger = logging.getLogger(__name__)


class SpringAnnotation(Enum):
    """Common Spring annotations"""
    CONTROLLER = "Controller"
    REST_CONTROLLER = "RestController"
    SERVICE = "Service"
    REPOSITORY = "Repository"
    COMPONENT = "Component"
    CONFIGURATION = "Configuration"
    REQUEST_MAPPING = "RequestMapping"
    GET_MAPPING = "GetMapping"
    POST_MAPPING = "PostMapping"
    PUT_MAPPING = "PutMapping"
    DELETE_MAPPING = "DeleteMapping"
    REQUEST_PARAM = "RequestParam"
    PATH_VARIABLE = "PathVariable"
    REQUEST_BODY = "RequestBody"
    REQUEST_HEADER = "RequestHeader"
    COOKIE_VALUE = "CookieValue"
    PRE_AUTHORIZE = "PreAuthorize"
    SECURED = "Secured"
    VALID = "Valid"
    VALIDATED = "Validated"
    QUERY = "Query"
    MODIFYING = "Modifying"


@dataclass
class SpringEndpoint:
    """Represents a Spring MVC endpoint"""
    class_name: str
    method_name: str
    http_method: str
    path: str
    file_path: str
    line_number: int
    parameters: List[Dict[str, Any]] = field(default_factory=list)
    has_authentication: bool = False
    has_validation: bool = False
    annotations: List[str] = field(default_factory=list)


@dataclass
class SpringSecurityConfig:
    """Represents Spring Security configuration"""
    file_path: str
    csrf_enabled: bool = True
    cors_configured: bool = False
    cors_allow_all: bool = False
    permit_all_paths: List[str] = field(default_factory=list)
    authenticated_paths: List[str] = field(default_factory=list)
    issues: List[str] = field(default_factory=list)


@dataclass
class SpringDataQuery:
    """Represents a Spring Data JPA query"""
    repository_name: str
    method_name: str
    query: str
    file_path: str
    line_number: int
    is_native: bool = False
    has_interpolation: bool = False


class SpringAnalyzer:
    """
    Analyzes Spring Boot applications for security issues.
    Understands Spring annotations, security configurations, and common patterns.
    """

    # Patterns for detecting Spring annotations
    ANNOTATION_PATTERNS = {
        'controller': r'@(Controller|RestController)',
        'request_mapping': r'@(RequestMapping|GetMapping|PostMapping|PutMapping|DeleteMapping|PatchMapping)',
        'input_param': r'@(RequestParam|PathVariable|RequestBody|RequestHeader|CookieValue)',
        'security': r'@(PreAuthorize|Secured|RolesAllowed)',
        'validation': r'@(Valid|Validated)',
        'jpa_query': r'@Query\s*\(',
        'jpa_modifying': r'@Modifying',
    }

    # SQL injection patterns in JPA
    SQL_INJECTION_PATTERNS = [
        r'@Query\s*\([^)]*["\'].*\+\s*',  # String concatenation in @Query
        r'@Query\s*\([^)]*\$\{',  # SpEL expression interpolation
        r'createNativeQuery\s*\([^)]*\+',  # Native query with concatenation
        r'createQuery\s*\([^)]*\+',  # JPQL with concatenation
    ]

    # Insecure configuration patterns
    INSECURE_CONFIG_PATTERNS = {
        'csrf_disabled': [
            r'csrf\s*\(\s*\)\s*\.\s*disable\s*\(',
            r'csrf\s*\(.*AbstractHttpConfigurer::disable',
            r'\.csrf\(\)\s*\.disable\(\)',
        ],
        'cors_allow_all': [
            r'allowedOrigins\s*\(\s*["\']?\*["\']?\s*\)',
            r'allowedOriginPatterns\s*\(\s*["\']?\*["\']?\s*\)',
        ],
        'permit_all': [
            r'anyRequest\s*\(\s*\)\s*\.\s*permitAll\s*\(',
            r'\.permitAll\s*\(\s*\)',
        ],
        'session_fixation': [
            r'sessionFixation\s*\(\s*\)\s*\.\s*none\s*\(',
        ],
        'frame_options_disabled': [
            r'frameOptions\s*\(\s*\)\s*\.\s*disable\s*\(',
        ],
    }

    # Actuator exposure patterns
    ACTUATOR_PATTERNS = [
        r'management\.endpoints\.web\.exposure\.include\s*=\s*\*',
        r'management\.security\.enabled\s*=\s*false',
        r'exposure:\s*\n\s*include:\s*\*',
    ]

    def __init__(self):
        self.java_analyzer = JavaASTAnalyzer() if TREE_SITTER_AVAILABLE else None
        self.endpoints: List[SpringEndpoint] = []
        self.security_configs: List[SpringSecurityConfig] = []
        self.data_queries: List[SpringDataQuery] = []

    def analyze_files(self, files: List[Path], content_cache: Dict[str, str] = None) -> List[Finding]:
        """Analyze Spring Boot application files"""
        content_cache = content_cache or {}
        findings = []

        # Categorize files
        java_files = [f for f in files if f.suffix.lower() == '.java']
        config_files = [f for f in files if f.suffix.lower() in ['.yml', '.yaml', '.properties']]

        # Analyze Java source files
        for file_path in java_files:
            content = content_cache.get(str(file_path))
            if not content:
                try:
                    content = file_path.read_text(encoding='utf-8', errors='ignore')
                    content_cache[str(file_path)] = content
                except Exception as e:
                    logger.debug(f"Failed to read {file_path}: {e}")
                    continue

            # Analyze different aspects
            findings.extend(self._analyze_controllers(file_path, content))
            findings.extend(self._analyze_security_config(file_path, content))
            findings.extend(self._analyze_jpa_queries(file_path, content))
            findings.extend(self._analyze_input_validation(file_path, content))

        # Analyze configuration files
        for file_path in config_files:
            content = content_cache.get(str(file_path))
            if not content:
                try:
                    content = file_path.read_text(encoding='utf-8', errors='ignore')
                except Exception:
                    continue

            findings.extend(self._analyze_config_files(file_path, content))

        # Cross-file analysis
        findings.extend(self._analyze_endpoint_security())

        return findings

    def _analyze_controllers(self, file_path: Path, content: str) -> List[Finding]:
        """Analyze Spring MVC controllers"""
        findings = []
        file_str = str(file_path)

        # Check if this is a controller
        if not re.search(self.ANNOTATION_PATTERNS['controller'], content):
            return findings

        lines = content.splitlines()

        # Extract endpoints
        current_class = None
        class_mapping = ""

        for i, line in enumerate(lines, 1):
            # Track class
            class_match = re.search(r'(?:public\s+)?class\s+(\w+)', line)
            if class_match:
                current_class = class_match.group(1)
                # Check for class-level RequestMapping
                if i > 1:
                    prev_lines = '\n'.join(lines[max(0, i-5):i])
                    mapping_match = re.search(r'@RequestMapping\s*\(\s*["\']([^"\']+)["\']', prev_lines)
                    if mapping_match:
                        class_mapping = mapping_match.group(1)

            # Find endpoint methods
            mapping_match = re.search(r'@(Get|Post|Put|Delete|Patch|Request)Mapping\s*(?:\([^)]*\))?', line)
            if mapping_match and current_class:
                http_method = mapping_match.group(1).upper()
                if http_method == 'REQUEST':
                    http_method = 'GET'  # Default

                # Extract path
                path_match = re.search(r'@\w+Mapping\s*\(\s*(?:value\s*=\s*)?["\']([^"\']*)["\']', line)
                path = class_mapping + (path_match.group(1) if path_match else "")

                # Look ahead for method definition and parameters
                method_content = '\n'.join(lines[i-1:min(i+10, len(lines))])
                method_match = re.search(r'public\s+\w+\s+(\w+)\s*\(([^)]*)\)', method_content)

                if method_match:
                    method_name = method_match.group(1)
                    params_str = method_match.group(2)

                    # Parse parameters
                    parameters = self._parse_parameters(params_str)

                    # Check for security annotations
                    context = '\n'.join(lines[max(0, i-3):i+1])
                    has_auth = bool(re.search(self.ANNOTATION_PATTERNS['security'], context))
                    has_valid = bool(re.search(self.ANNOTATION_PATTERNS['validation'], method_content))

                    endpoint = SpringEndpoint(
                        class_name=current_class,
                        method_name=method_name,
                        http_method=http_method,
                        path=path,
                        file_path=file_str,
                        line_number=i,
                        parameters=parameters,
                        has_authentication=has_auth,
                        has_validation=has_valid,
                    )
                    self.endpoints.append(endpoint)

                    # Check for missing validation on POST/PUT with @RequestBody
                    if http_method in ['POST', 'PUT'] and not has_valid:
                        has_request_body = any(p.get('annotation') == 'RequestBody' for p in parameters)
                        if has_request_body:
                            findings.append(Finding(
                                rule_id="SPRING-VALID-001",
                                rule_name="Missing Input Validation",
                                description=f"Endpoint {method_name} accepts @RequestBody without @Valid annotation",
                                severity=Severity.MEDIUM,
                                confidence=Confidence.HIGH,
                                location=Location(file_path=file_str, line_number=i, snippet=line.strip()),
                                cwe="CWE-20",
                                owasp="A03",
                                tags=['spring', 'validation', 'input'],
                                remediation="Add @Valid annotation before @RequestBody parameter",
                            ))

        return findings

    def _parse_parameters(self, params_str: str) -> List[Dict[str, Any]]:
        """Parse method parameters"""
        parameters = []
        if not params_str.strip():
            return parameters

        # Split by comma, handling generics
        depth = 0
        current = ""
        for char in params_str:
            if char == '<':
                depth += 1
            elif char == '>':
                depth -= 1
            elif char == ',' and depth == 0:
                if current.strip():
                    parameters.append(self._parse_single_param(current.strip()))
                current = ""
                continue
            current += char

        if current.strip():
            parameters.append(self._parse_single_param(current.strip()))

        return parameters

    def _parse_single_param(self, param: str) -> Dict[str, Any]:
        """Parse a single parameter"""
        result = {'raw': param}

        # Check for annotations
        for ann in ['RequestParam', 'PathVariable', 'RequestBody', 'RequestHeader', 'CookieValue']:
            if f'@{ann}' in param:
                result['annotation'] = ann
                result['is_user_input'] = True
                break

        # Extract type and name
        parts = param.split()
        if parts:
            result['name'] = parts[-1]
            # Type is everything before the last part, minus annotations
            type_parts = [p for p in parts[:-1] if not p.startswith('@')]
            result['type'] = ' '.join(type_parts) if type_parts else 'unknown'

        return result

    def _analyze_security_config(self, file_path: Path, content: str) -> List[Finding]:
        """Analyze Spring Security configuration"""
        findings = []
        file_str = str(file_path)

        # Check if this is a security config
        if 'SecurityFilterChain' not in content and 'WebSecurityConfigurerAdapter' not in content:
            return findings

        config = SpringSecurityConfig(file_path=file_str)

        lines = content.splitlines()
        for i, line in enumerate(lines, 1):
            # Check for CSRF disabled
            for pattern in self.INSECURE_CONFIG_PATTERNS['csrf_disabled']:
                if re.search(pattern, line):
                    config.csrf_enabled = False
                    findings.append(Finding(
                        rule_id="SPRING-SEC-001",
                        rule_name="CSRF Protection Disabled",
                        description="CSRF protection is disabled in Spring Security configuration",
                        severity=Severity.HIGH,
                        confidence=Confidence.HIGH,
                        location=Location(file_path=file_str, line_number=i, snippet=line.strip()),
                        cwe="CWE-352",
                        owasp="A01",
                        tags=['spring', 'csrf', 'security-config'],
                        remediation="Enable CSRF protection for state-changing operations",
                    ))
                    break

            # Check for CORS allow all
            for pattern in self.INSECURE_CONFIG_PATTERNS['cors_allow_all']:
                if re.search(pattern, line):
                    config.cors_allow_all = True
                    findings.append(Finding(
                        rule_id="SPRING-SEC-002",
                        rule_name="Insecure CORS Configuration",
                        description="CORS is configured to allow all origins",
                        severity=Severity.MEDIUM,
                        confidence=Confidence.HIGH,
                        location=Location(file_path=file_str, line_number=i, snippet=line.strip()),
                        cwe="CWE-942",
                        owasp="A01",
                        tags=['spring', 'cors', 'security-config'],
                        remediation="Configure specific allowed origins instead of wildcard",
                    ))
                    break

            # Check for permit all on anyRequest
            if re.search(r'anyRequest\s*\(\s*\)\s*\.\s*permitAll', line):
                findings.append(Finding(
                    rule_id="SPRING-SEC-003",
                    rule_name="Permissive Security Configuration",
                    description="All requests are permitted without authentication",
                    severity=Severity.CRITICAL,
                    confidence=Confidence.HIGH,
                    location=Location(file_path=file_str, line_number=i, snippet=line.strip()),
                    cwe="CWE-862",
                    owasp="A01",
                    tags=['spring', 'authentication', 'security-config'],
                    remediation="Use anyRequest().authenticated() and explicitly permit only public endpoints",
                ))

            # Check for session fixation disabled
            for pattern in self.INSECURE_CONFIG_PATTERNS['session_fixation']:
                if re.search(pattern, line):
                    findings.append(Finding(
                        rule_id="SPRING-SEC-004",
                        rule_name="Session Fixation Protection Disabled",
                        description="Session fixation protection is disabled",
                        severity=Severity.MEDIUM,
                        confidence=Confidence.HIGH,
                        location=Location(file_path=file_str, line_number=i, snippet=line.strip()),
                        cwe="CWE-384",
                        owasp="A07",
                        tags=['spring', 'session', 'security-config'],
                        remediation="Enable session fixation protection (newSession or changeSessionId)",
                    ))
                    break

        self.security_configs.append(config)
        return findings

    def _analyze_jpa_queries(self, file_path: Path, content: str) -> List[Finding]:
        """Analyze Spring Data JPA queries for SQL injection"""
        findings = []
        file_str = str(file_path)

        # Check if this is a repository
        if '@Repository' not in content and 'JpaRepository' not in content and 'CrudRepository' not in content:
            return findings

        lines = content.splitlines()

        for i, line in enumerate(lines, 1):
            # Check for @Query annotation
            if '@Query' in line:
                # Get the query content (may span multiple lines)
                query_content = line
                j = i
                while j < len(lines) and ')' not in query_content:
                    j += 1
                    query_content += ' ' + lines[j-1]

                # Check for SQL injection patterns
                for pattern in self.SQL_INJECTION_PATTERNS:
                    if re.search(pattern, query_content):
                        findings.append(Finding(
                            rule_id="SPRING-JPA-001",
                            rule_name="SQL Injection in JPA Query",
                            description="JPA query uses string concatenation or interpolation with potential user input",
                            severity=Severity.CRITICAL,
                            confidence=Confidence.HIGH,
                            location=Location(file_path=file_str, line_number=i, snippet=line.strip()),
                            cwe="CWE-89",
                            owasp="A03",
                            tags=['spring', 'jpa', 'sql-injection'],
                            remediation="Use named parameters (:paramName) instead of string concatenation",
                        ))
                        break

                # Check for nativeQuery=true (higher risk)
                if 'nativeQuery' in query_content and 'true' in query_content.lower():
                    if '${' in query_content or '+' in query_content:
                        findings.append(Finding(
                            rule_id="SPRING-JPA-002",
                            rule_name="SQL Injection in Native Query",
                            description="Native SQL query uses string interpolation or concatenation",
                            severity=Severity.CRITICAL,
                            confidence=Confidence.HIGH,
                            location=Location(file_path=file_str, line_number=i, snippet=line.strip()),
                            cwe="CWE-89",
                            owasp="A03",
                            tags=['spring', 'jpa', 'sql-injection', 'native-query'],
                            remediation="Use parameterized queries with positional or named parameters",
                        ))

        return findings

    def _analyze_input_validation(self, file_path: Path, content: str) -> List[Finding]:
        """Analyze input validation practices"""
        findings = []
        file_str = str(file_path)

        # Skip if not a controller
        if not re.search(self.ANNOTATION_PATTERNS['controller'], content):
            return findings

        lines = content.splitlines()

        for i, line in enumerate(lines, 1):
            # Check for @RequestBody without @Valid in context
            if '@RequestBody' in line and '@Valid' not in line:
                # Check previous line for @Valid
                if i > 1 and '@Valid' not in lines[i-2]:
                    # Get method context
                    context = '\n'.join(lines[max(0, i-5):min(i+3, len(lines))])
                    if '@Valid' not in context and '@Validated' not in context:
                        findings.append(Finding(
                            rule_id="SPRING-INPUT-001",
                            rule_name="Missing Request Body Validation",
                            description="@RequestBody parameter without @Valid annotation",
                            severity=Severity.LOW,
                            confidence=Confidence.MEDIUM,
                            location=Location(file_path=file_str, line_number=i, snippet=line.strip()),
                            cwe="CWE-20",
                            owasp="A03",
                            tags=['spring', 'validation', 'input'],
                            remediation="Add @Valid annotation before @RequestBody",
                        ))

        return findings

    def _analyze_config_files(self, file_path: Path, content: str) -> List[Finding]:
        """Analyze Spring configuration files (YAML/properties)"""
        findings = []
        file_str = str(file_path)

        lines = content.splitlines()

        for i, line in enumerate(lines, 1):
            # Check for actuator exposure
            for pattern in self.ACTUATOR_PATTERNS:
                if re.search(pattern, line):
                    findings.append(Finding(
                        rule_id="SPRING-CFG-001",
                        rule_name="Actuator Endpoints Exposed",
                        description="Spring Actuator endpoints are exposed without restriction",
                        severity=Severity.HIGH,
                        confidence=Confidence.HIGH,
                        location=Location(file_path=file_str, line_number=i, snippet=line.strip()),
                        cwe="CWE-200",
                        owasp="A01",
                        tags=['spring', 'actuator', 'config'],
                        remediation="Restrict actuator endpoints or require authentication",
                    ))
                    break

            # Check for debug mode
            if re.search(r'debug\s*[=:]\s*true', line, re.IGNORECASE):
                findings.append(Finding(
                    rule_id="SPRING-CFG-002",
                    rule_name="Debug Mode Enabled",
                    description="Debug mode is enabled in configuration",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.MEDIUM,
                    location=Location(file_path=file_str, line_number=i, snippet=line.strip()),
                    cwe="CWE-489",
                    owasp="A05",
                    tags=['spring', 'debug', 'config'],
                    remediation="Disable debug mode in production",
                ))

            # Check for insecure session config
            if re.search(r'http-only\s*[=:]\s*false', line, re.IGNORECASE):
                findings.append(Finding(
                    rule_id="SPRING-CFG-003",
                    rule_name="Insecure Session Cookie",
                    description="Session cookie HttpOnly flag is disabled",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.HIGH,
                    location=Location(file_path=file_str, line_number=i, snippet=line.strip()),
                    cwe="CWE-614",
                    owasp="A07",
                    tags=['spring', 'session', 'cookie', 'config'],
                    remediation="Enable HttpOnly flag for session cookies",
                ))

        return findings

    def _analyze_endpoint_security(self) -> List[Finding]:
        """Cross-file analysis of endpoint security"""
        findings = []

        # Check for unprotected state-changing endpoints
        for endpoint in self.endpoints:
            if endpoint.http_method in ['POST', 'PUT', 'DELETE', 'PATCH']:
                if not endpoint.has_authentication:
                    # Check if CSRF is disabled globally
                    csrf_disabled = any(not c.csrf_enabled for c in self.security_configs)

                    if csrf_disabled:
                        findings.append(Finding(
                            rule_id="SPRING-XFILE-001",
                            rule_name="Unprotected State-Changing Endpoint",
                            description=f"Endpoint {endpoint.method_name} ({endpoint.http_method}) "
                                       f"has no method-level security and CSRF is disabled",
                            severity=Severity.HIGH,
                            confidence=Confidence.MEDIUM,
                            location=Location(
                                file_path=endpoint.file_path,
                                line_number=endpoint.line_number,
                                snippet=f"@{endpoint.http_method.capitalize()}Mapping"
                            ),
                            cwe="CWE-352",
                            owasp="A01",
                            tags=['spring', 'csrf', 'endpoint-security'],
                            remediation="Add @PreAuthorize annotation or enable CSRF protection",
                        ))

        return findings

    def get_endpoints(self) -> List[SpringEndpoint]:
        """Get all discovered endpoints"""
        return self.endpoints

    def get_security_configs(self) -> List[SpringSecurityConfig]:
        """Get all discovered security configurations"""
        return self.security_configs


def analyze_spring_application(files: List[Path], content_cache: Dict[str, str] = None) -> List[Finding]:
    """Convenience function to analyze a Spring Boot application"""
    analyzer = SpringAnalyzer()
    return analyzer.analyze_files(files, content_cache)
