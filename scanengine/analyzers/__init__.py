"""
SentinelScan Analyzers Package

This package provides a modular, extensible system for security analysis
across multiple programming languages, frameworks, and infrastructure-as-code.

Components:
- base: Abstract base classes for all analyzer types
- registry: Centralized analyzer registration and discovery
- languages: Language-specific AST analyzers (Go, Rust, C#, etc.)
- frameworks: Framework-specific security analyzers (React, Django, etc.)
- iac: Infrastructure-as-Code analyzers (Terraform, Kubernetes, etc.)
"""

from .base import (
    AnalyzerCapabilities,
    BaseAnalyzer,
    LanguageAnalyzer,
    FrameworkAnalyzer,
    IaCAnalyzer,
    ClassInfo,
    FunctionInfo,
    Endpoint,
    IaCResource,
)
from .registry import AnalyzerRegistry

__all__ = [
    # Base classes
    'AnalyzerCapabilities',
    'BaseAnalyzer',
    'LanguageAnalyzer',
    'FrameworkAnalyzer',
    'IaCAnalyzer',
    # Data classes
    'ClassInfo',
    'FunctionInfo',
    'Endpoint',
    'IaCResource',
    # Registry
    'AnalyzerRegistry',
]
