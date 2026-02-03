"""
SentinelScan - Source Code Security Analysis Tool
Phase 1: Java/Spring focused with pattern-based detection
Phase 2: Context-aware analysis with AST parsing
Phase 3: Inter-procedural dataflow analysis
Phase 4: LLM-based vulnerability analysis
Phase 5: CI/CD Integration and Reporting
"""

__version__ = "0.5.0"
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
]
