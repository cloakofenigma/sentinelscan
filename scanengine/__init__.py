"""
SentinelScan - Multi-Engine Static Application Security Testing (SAST) Tool.

A comprehensive security scanner supporting 15+ languages and 20+ frameworks
with 7 chained analysis engines for maximum vulnerability detection.

Analysis Engines:
    1. Pattern Matching - Regex-based vulnerability detection
    2. AST Analysis - Syntax tree parsing with tree-sitter
    3. Call Graph - Inter-procedural call tracking
    4. Dataflow Analysis - Taint tracking with SSA transformation
    5. Spring Analyzer - Spring Security-specific checks
    6. MyBatis Analyzer - SQL injection in XML mappers
    7. Context Engine - False positive reduction
    8. LLM Analysis - AI-powered semantic analysis (optional)

Supported Languages:
    Java, Kotlin, Python, JavaScript/TypeScript, Go, Rust, C#,
    Ruby, PHP, Swift, Scala

Supported Frameworks:
    Spring Boot, Django, Flask, React, Vue, Angular, Express,
    Rails, ASP.NET, Gin, Laravel, GraphQL, gRPC, Android, iOS

Infrastructure as Code:
    Terraform, Kubernetes, CloudFormation, Dockerfile

Quick Start:
    >>> from scanengine import create_scanner
    >>> scanner = create_scanner()
    >>> result = scanner.scan("/path/to/project")
    >>> print(f"Found {len(result.findings)} vulnerabilities")

Output Formats:
    SARIF (GitHub/GitLab), HTML (human review), Excel (reporting)

See Also:
    - USAGE.md for detailed documentation
    - https://github.com/sentinelscan for project home
"""

__version__ = "0.7.0"
__author__ = "SentinelScan"

from .scanner import SecurityScanner, create_scanner
from .models import Finding, Rule, ScanResult, Severity, Confidence, Location
from .call_graph import CallGraph, CallGraphBuilder
from .dataflow_analyzer import DataflowAnalyzer, analyze_dataflow
from .spring_analyzer import SpringAnalyzer, analyze_spring_application
from .mybatis_analyzer import MybatisAnalyzer, analyze_mybatis_mappers

# Phase 4: LLM integration
from .llm import (
    LLMClient, LLMConfig, create_llm_client,
    LLMSecurityAnalyzer, create_llm_analyzer,
    ContextAssembler, create_context_assembler,
    SecurityPrompts,
)

# Phase 5: Reporters and Hooks
from .reporters import SARIFReporter, HTMLReporter, ExcelReporter, generate_sarif, generate_html_report, generate_excel_report
from .hooks import install_hooks, uninstall_hooks, run_pre_commit_scan, run_pre_push_scan

# Phase 7: Profiling utilities
from .profiling import (
    PerformanceMetrics,
    ScanProfiler,
    profile,
    timed,
    get_global_metrics,
)

__all__ = [
    # Core
    'SecurityScanner',
    'create_scanner',
    'Finding',
    'Rule',
    'ScanResult',
    'Severity',
    'Confidence',
    'Location',
    # Phase 3
    'CallGraph',
    'CallGraphBuilder',
    'DataflowAnalyzer',
    'analyze_dataflow',
    'SpringAnalyzer',
    'analyze_spring_application',
    'MybatisAnalyzer',
    'analyze_mybatis_mappers',
    # Phase 4
    'LLMClient',
    'LLMConfig',
    'create_llm_client',
    'LLMSecurityAnalyzer',
    'create_llm_analyzer',
    'ContextAssembler',
    'create_context_assembler',
    'SecurityPrompts',
    # Phase 5
    'SARIFReporter',
    'HTMLReporter',
    'generate_sarif',
    'generate_html_report',
    'install_hooks',
    'uninstall_hooks',
    'run_pre_commit_scan',
    'run_pre_push_scan',
    # Profiling
    'PerformanceMetrics',
    'ScanProfiler',
    'profile',
    'timed',
    'get_global_metrics',
]
