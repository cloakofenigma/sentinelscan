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
]
