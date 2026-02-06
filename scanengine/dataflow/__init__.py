"""
Deep Dataflow Analysis Engine for SentinelScan

This package provides advanced inter-procedural taint tracking with:
- SSA (Static Single Assignment) transformation
- Formal taint lattice with join/meet operations
- Transfer functions for all statement types
- Sanitizer detection and tracking
- Type resolution with inheritance support
- Fixed-point worklist algorithm
"""

from .taint_lattice import (
    TaintLevel,
    TaintLabel,
    TaintValue,
    TaintAbstractState,
    TaintLattice,
)

from .ssa import (
    SSAVariable,
    SSAStatement,
    SSAAssignment,
    SSAMethodCall,
    SSAFieldAccess,
    SSAPhiFunction,
    SSABasicBlock,
    SSAMethod,
    SSATransformer,
)

from .sanitizers import (
    Sanitizer,
    SanitizerRegistry,
)

from .type_resolver import (
    TypeInfo,
    TypeResolver,
)

from .engine import (
    MethodSummary,
    InterproceduralEngine,
)

from .deep_analyzer import (
    DeepDataflowAnalyzer,
)

from .multilang import (
    LanguageDataflowConfig,
    get_language_config,
    get_all_taint_sources,
    get_all_sinks,
    get_all_sanitizers,
    is_taint_source,
    is_sink,
    is_sanitizer,
    get_source_annotation,
    LANGUAGE_CONFIGS,
    GO_CONFIG,
    CSHARP_CONFIG,
    KOTLIN_CONFIG,
    PHP_CONFIG,
    RUBY_CONFIG,
    RUST_CONFIG,
    SWIFT_CONFIG,
)

__all__ = [
    # Taint Lattice
    'TaintLevel',
    'TaintLabel',
    'TaintValue',
    'TaintAbstractState',
    'TaintLattice',
    # SSA
    'SSAVariable',
    'SSAStatement',
    'SSAAssignment',
    'SSAMethodCall',
    'SSAFieldAccess',
    'SSAPhiFunction',
    'SSABasicBlock',
    'SSAMethod',
    'SSATransformer',
    # Sanitizers
    'Sanitizer',
    'SanitizerRegistry',
    # Type Resolution
    'TypeInfo',
    'TypeResolver',
    # Engine
    'MethodSummary',
    'InterproceduralEngine',
    # Main Analyzer
    'DeepDataflowAnalyzer',
    # Multi-Language Support
    'LanguageDataflowConfig',
    'get_language_config',
    'get_all_taint_sources',
    'get_all_sinks',
    'get_all_sanitizers',
    'is_taint_source',
    'is_sink',
    'is_sanitizer',
    'get_source_annotation',
    'LANGUAGE_CONFIGS',
    'GO_CONFIG',
    'CSHARP_CONFIG',
    'KOTLIN_CONFIG',
    'PHP_CONFIG',
    'RUBY_CONFIG',
    'RUST_CONFIG',
    'SWIFT_CONFIG',
]
