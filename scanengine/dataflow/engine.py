"""
Inter-procedural Engine - Main analysis engine for deep dataflow

Performs inter-procedural taint analysis using method summaries
and worklist-based fixed-point iteration.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Set, Optional, Tuple, Any
from pathlib import Path
from collections import defaultdict
import logging

from .ssa import (
    SSAMethod, SSATransformer, SSAStatement, SSAMethodCall,
    SSAReturn, SSAVariable
)
from .taint_lattice import (
    TaintLevel, TaintLabel, TaintValue, TaintAbstractState, TaintLattice
)
from .transfer_functions import (
    TransferFunctionRegistry, TransferResult,
    check_parameter_source, TAINT_SOURCE_ANNOTATIONS
)
from .sanitizers import SanitizerRegistry
from .type_resolver import TypeResolver

import sys
sys.path.insert(0, str(__file__).rsplit('/', 2)[0])
from ..dataflow_analyzer import TaintSource, SinkType, DataflowVulnerability
from ..models import Confidence

logger = logging.getLogger(__name__)


@dataclass
class MethodSummary:
    """
    Summary of a method's taint behavior.

    Captures how taint flows through the method without storing
    all internal states.
    """
    method_id: str

    # Which parameters can flow to return value
    # Maps param_index -> True if param flows to return
    param_to_return: Dict[int, bool] = field(default_factory=dict)

    # Which parameters can flow to fields
    # Maps param_index -> [field_names]
    param_to_fields: Dict[int, List[str]] = field(default_factory=dict)

    # If method is a source, which source type
    return_sources: Set[TaintSource] = field(default_factory=set)

    # Is this method a sink? Which params are sink arguments?
    sink_params: Dict[int, SinkType] = field(default_factory=dict)

    # Can receiver taint escape to return?
    receiver_to_return: bool = False

    # Analyzed - have we completed analysis?
    analyzed: bool = False


@dataclass
class DetectedVulnerability:
    """Vulnerability detected during analysis"""
    sink_type: SinkType
    source_label: TaintLabel
    source_location: str
    sink_location: str
    sink_method: str
    propagation_path: Tuple[str, ...]
    confidence: Confidence


class InterproceduralEngine:
    """
    Performs inter-procedural taint analysis.

    Algorithm:
    1. Transform methods to SSA form
    2. Initialize taint at sources (annotated parameters)
    3. Build initial method summaries
    4. Fixed-point iteration:
       - Analyze methods with transfer functions
       - At calls: apply callee summary
       - Update summaries when analysis changes
       - Add callers to worklist when summary changes
    5. Check all sinks for tainted data
    """

    def __init__(self, sanitizer_registry: Optional[SanitizerRegistry] = None,
                type_resolver: Optional[TypeResolver] = None,
                max_iterations: int = 100,
                max_call_depth: int = 10):
        """
        Initialize the engine.

        Args:
            sanitizer_registry: Registry of sanitizers
            type_resolver: Type resolver for polymorphism
            max_iterations: Maximum fixed-point iterations
            max_call_depth: Maximum call chain depth to analyze
        """
        self.sanitizer_registry = sanitizer_registry or SanitizerRegistry()
        self.type_resolver = type_resolver or TypeResolver()
        self.max_iterations = max_iterations
        self.max_call_depth = max_call_depth

        # SSA transformer
        self.ssa_transformer = SSATransformer()

        # Transfer function registry
        self.transfer = TransferFunctionRegistry(
            self.sanitizer_registry,
            self.type_resolver
        )

        # Analysis state
        self.ssa_methods: Dict[str, SSAMethod] = {}
        self.summaries: Dict[str, MethodSummary] = {}
        self.method_states: Dict[str, TaintAbstractState] = {}
        self.worklist: List[str] = []

        # Call graph information
        self.callers: Dict[str, Set[str]] = defaultdict(set)  # method_id -> callers
        self.callees: Dict[str, Set[str]] = defaultdict(set)  # method_id -> callees

        # Detected vulnerabilities
        self.vulnerabilities: List[DetectedVulnerability] = []

        # Content cache reference
        self._content_cache: Dict[str, str] = {}

    def analyze(self, files: List[Path],
               content_cache: Dict[str, str]) -> List[DetectedVulnerability]:
        """
        Main analysis entry point.

        Args:
            files: List of source files to analyze
            content_cache: File content cache

        Returns:
            List of detected vulnerabilities
        """
        self._content_cache = content_cache
        self.vulnerabilities = []

        logger.info(f"Starting inter-procedural analysis on {len(files)} files")

        # Phase 1: Build type graph
        logger.debug("Phase 1: Building type graph")
        self.type_resolver.build_type_graph(files, content_cache)

        # Phase 2: Transform methods to SSA
        logger.debug("Phase 2: Transforming methods to SSA")
        self._build_ssa_methods(files)

        if not self.ssa_methods:
            logger.warning("No methods to analyze")
            return []

        # Phase 3: Build call graph
        logger.debug("Phase 3: Building call graph")
        self._build_call_relationships()

        # Phase 4: Initialize sources
        logger.debug("Phase 4: Initializing taint sources")
        self._initialize_sources()

        # Phase 5: Fixed-point iteration
        logger.debug("Phase 5: Running fixed-point analysis")
        self._run_fixed_point()

        # Phase 6: Collect vulnerabilities
        logger.debug("Phase 6: Collecting vulnerabilities")
        self._collect_vulnerabilities()

        logger.info(f"Analysis complete: {len(self.vulnerabilities)} vulnerabilities found")
        return self.vulnerabilities

    def _build_ssa_methods(self, files: List[Path]) -> None:
        """Build SSA form for all methods in files"""
        try:
            from ..ast_analyzer import JavaASTAnalyzer, TREE_SITTER_AVAILABLE
            if not TREE_SITTER_AVAILABLE:
                logger.warning("Tree-sitter not available, SSA transformation limited")
                return

            ast_analyzer = JavaASTAnalyzer()
        except ImportError:
            logger.warning("Could not import AST analyzer")
            return

        for file_path in files:
            if file_path.suffix.lower() not in ['.java']:
                continue

            content = self._content_cache.get(str(file_path), '')
            if not content:
                continue

            try:
                classes = ast_analyzer.get_classes(content)
                for cls in classes:
                    for method in cls.methods:
                        ssa_method = self.ssa_transformer.transform_method(
                            method, content, str(file_path)
                        )
                        self.ssa_methods[ssa_method.unique_id] = ssa_method

            except Exception as e:
                logger.debug(f"Failed to process {file_path}: {e}")

        logger.debug(f"Transformed {len(self.ssa_methods)} methods to SSA")

    def _build_call_relationships(self) -> None:
        """Build caller/callee relationships from SSA methods"""
        for method_id, ssa_method in self.ssa_methods.items():
            for stmt in ssa_method.get_all_statements():
                if isinstance(stmt, SSAMethodCall):
                    # Try to resolve callee
                    callee_ids = self._resolve_call_target(stmt, ssa_method)
                    for callee_id in callee_ids:
                        self.callees[method_id].add(callee_id)
                        self.callers[callee_id].add(method_id)

    def _resolve_call_target(self, call: SSAMethodCall,
                            caller: SSAMethod) -> List[str]:
        """Resolve possible target methods for a call"""
        targets = []

        # Try type-based resolution
        receiver_type = None
        if call.receiver:
            receiver_type = self.type_resolver.get_variable_type(
                call.receiver.original_name
            )

        if receiver_type:
            sigs = self.type_resolver.resolve_method_target(
                call.method_name,
                receiver_type,
                len(call.arguments)
            )
            for sig in sigs:
                targets.append(sig.unique_id)

        # Fallback: search by name
        if not targets:
            for method_id, ssa_method in self.ssa_methods.items():
                if ssa_method.name == call.method_name:
                    if len(ssa_method.parameters) >= len(call.arguments):
                        targets.append(method_id)

        return targets[:5]  # Limit to prevent explosion

    def _initialize_sources(self) -> None:
        """Initialize taint at all source locations"""
        for method_id, ssa_method in self.ssa_methods.items():
            state = TaintAbstractState()

            # Check parameters for source annotations
            for i, param in enumerate(ssa_method.parameters):
                source = self._check_param_source(param, ssa_method.annotations)
                if source:
                    label = TaintLabel(
                        source,
                        f"{ssa_method.file_path}:{ssa_method.start_line}",
                        self._get_annotation_for_param(param),
                        param.original_name
                    )
                    taint = TaintValue.tainted(label, (f"param:{param.original_name}",))
                    state = state.set(param.ssa_name, taint)

                    logger.debug(f"Initialized taint source: {param.original_name} ({source.value}) in {ssa_method.name}")

                    # Add to worklist if we found tainted parameters
                    if method_id not in self.worklist:
                        self.worklist.append(method_id)

            self.method_states[method_id] = state

            # Initialize empty summary
            self.summaries[method_id] = MethodSummary(method_id=method_id)

    def _check_param_source(self, param: SSAVariable,
                           method_annotations: List[str]) -> Optional[TaintSource]:
        """Check if a parameter is a taint source"""
        # Check parameter annotations (e.g., @RequestParam, @PathVariable)
        for param_ann in param.annotations:
            for ann_pattern, source in TAINT_SOURCE_ANNOTATIONS.items():
                if ann_pattern.replace('@', '') in param_ann:
                    return source

        # Check if this is a controller method (any endpoint annotation)
        # Controllers receive HTTP input, so parameters are tainted
        for method_ann in method_annotations:
            if any(mapping in method_ann for mapping in
                   ['Mapping', 'GetMapping', 'PostMapping', 'PutMapping',
                    'DeleteMapping', 'PatchMapping', 'Path']):
                # Controller method - check if param has web annotations
                for param_ann in param.annotations:
                    if any(web_ann in param_ann for web_ann in
                           ['RequestParam', 'PathVariable', 'RequestBody',
                            'RequestHeader', 'CookieValue', 'QueryParam',
                            'PathParam', 'HeaderParam', 'FormParam']):
                        for ann_pattern, source in TAINT_SOURCE_ANNOTATIONS.items():
                            if ann_pattern.replace('@', '') in param_ann:
                                return source

        return None

    def _get_annotation_for_param(self, param: SSAVariable) -> Optional[str]:
        """Get the annotation string for a parameter"""
        for ann in param.annotations:
            for ann_pattern in TAINT_SOURCE_ANNOTATIONS.keys():
                if ann_pattern.replace('@', '') in ann:
                    return ann_pattern
        return None

    def _get_annotation_for_source(self, source: TaintSource,
                                   annotations: List[str]) -> Optional[str]:
        """Get the annotation string for a source"""
        for ann in annotations:
            for ann_pattern, src in TAINT_SOURCE_ANNOTATIONS.items():
                if src == source and ann_pattern.replace('@', '') in ann:
                    return ann_pattern
        return None

    def _run_fixed_point(self) -> None:
        """Worklist-based fixed-point iteration"""
        iterations = 0

        while self.worklist and iterations < self.max_iterations:
            iterations += 1
            method_id = self.worklist.pop(0)

            if method_id not in self.ssa_methods:
                continue

            ssa_method = self.ssa_methods[method_id]
            old_state = self.method_states.get(method_id, TaintAbstractState())

            # Analyze method
            new_state = self._analyze_method(ssa_method)

            # Check if state changed
            if old_state != new_state:
                self.method_states[method_id] = new_state

                # Update summary
                old_summary = self.summaries.get(method_id)
                self._update_summary(method_id, new_state)
                new_summary = self.summaries[method_id]

                # If summary changed, add callers to worklist
                if self._summary_changed(old_summary, new_summary):
                    for caller_id in self.callers.get(method_id, []):
                        if caller_id not in self.worklist:
                            self.worklist.append(caller_id)

        logger.debug(f"Fixed-point reached after {iterations} iterations")

    def _analyze_method(self, ssa_method: SSAMethod) -> TaintAbstractState:
        """Analyze a single method, returning the final state"""
        self.transfer.set_context(ssa_method.annotations, ssa_method.file_path)
        self.type_resolver.clear_variable_cache()

        # Start with current method state
        state = self.method_states.get(ssa_method.unique_id, TaintAbstractState())

        # Process all statements
        for stmt in ssa_method.get_all_statements():
            result = self.transfer.transfer(stmt, state)
            state = result.new_state

            # Handle method calls specially for inter-procedural
            if isinstance(stmt, SSAMethodCall):
                state = self._handle_interprocedural_call(stmt, state, ssa_method)

            # Record vulnerabilities found during transfer
            if result.is_sink_reached and result.sink_type and result.sink_argument_taint:
                self._record_vulnerability(
                    result.sink_type,
                    result.sink_argument_taint,
                    stmt,
                    ssa_method
                )

        return state

    def _handle_interprocedural_call(self, call: SSAMethodCall,
                                    state: TaintAbstractState,
                                    caller: SSAMethod) -> TaintAbstractState:
        """Handle inter-procedural aspects of a method call"""
        # Resolve call targets
        target_ids = self._resolve_call_target(call, caller)

        if not target_ids:
            return state

        # Apply summaries from all possible targets
        result_taints = []

        for target_id in target_ids:
            summary = self.summaries.get(target_id)
            if summary and summary.analyzed:
                taint = self._apply_summary(summary, call, state)
                result_taints.append(taint)

        # Join all possible results
        if result_taints and call.defines:
            joined = result_taints[0]
            for t in result_taints[1:]:
                joined = TaintLattice.join(joined, t)
            state = state.set(call.defines.ssa_name, joined)

        return state

    def _apply_summary(self, summary: MethodSummary,
                      call: SSAMethodCall,
                      state: TaintAbstractState) -> TaintValue:
        """Apply a method summary to compute return taint"""
        result = TaintValue.untainted()

        # Check param-to-return flow
        for param_idx, flows_to_return in summary.param_to_return.items():
            if flows_to_return and param_idx < len(call.arguments):
                arg_taint = self.transfer._evaluate_expression_taint(
                    call.arguments[param_idx], state
                )
                if arg_taint.is_tainted:
                    result = TaintLattice.join(result, arg_taint)

        # Check receiver-to-return flow
        if summary.receiver_to_return and call.receiver:
            recv_taint = state.get(call.receiver.ssa_name)
            result = TaintLattice.join(result, recv_taint)

        # Check if method is a source
        for source in summary.return_sources:
            label = TaintLabel(source, f"summary:{summary.method_id}",
                              None, call.method_name)
            result = TaintLattice.join(result, TaintValue.tainted(label))

        return result

    def _update_summary(self, method_id: str,
                       state: TaintAbstractState) -> None:
        """Update method summary from analyzed state"""
        ssa_method = self.ssa_methods.get(method_id)
        if not ssa_method:
            return

        summary = self.summaries.get(method_id, MethodSummary(method_id=method_id))

        # Check which parameters flow to return
        if state.return_taint and state.return_taint.is_tainted:
            for label in state.return_taint.labels:
                for i, param in enumerate(ssa_method.parameters):
                    if param.original_name == label.original_variable:
                        summary.param_to_return[i] = True

        # Check receiver flow (simplified)
        # In full implementation, we'd track 'this' references

        summary.analyzed = True
        self.summaries[method_id] = summary

    def _summary_changed(self, old: Optional[MethodSummary],
                        new: MethodSummary) -> bool:
        """Check if summary changed (affects callers)"""
        if old is None:
            return True
        if not old.analyzed and new.analyzed:
            return True
        if old.param_to_return != new.param_to_return:
            return True
        if old.return_sources != new.return_sources:
            return True
        if old.receiver_to_return != new.receiver_to_return:
            return True
        return False

    def _record_vulnerability(self, sink_type: SinkType,
                             taint: TaintValue,
                             sink_stmt: SSAStatement,
                             method: SSAMethod) -> None:
        """Record a detected vulnerability"""
        for label in taint.labels:
            vuln = DetectedVulnerability(
                sink_type=sink_type,
                source_label=label,
                source_location=label.source_location,
                sink_location=f"{method.file_path}:{sink_stmt.line_number}",
                sink_method=method.name,
                propagation_path=taint.propagation_path,
                confidence=Confidence.HIGH
            )
            self.vulnerabilities.append(vuln)

    def _collect_vulnerabilities(self) -> None:
        """Final pass to collect all vulnerabilities"""
        # Already collected during analysis
        # This method can do additional checks if needed

        # Deduplicate
        seen = set()
        unique = []
        for vuln in self.vulnerabilities:
            key = (vuln.sink_type, vuln.source_location, vuln.sink_location)
            if key not in seen:
                seen.add(key)
                unique.append(vuln)
        self.vulnerabilities = unique

    def get_dataflow_vulnerabilities(self) -> List[DataflowVulnerability]:
        """Convert to DataflowVulnerability format for compatibility"""
        from ..dataflow_analyzer import TaintedValue as LegacyTaintedValue

        results = []
        for vuln in self.vulnerabilities:
            legacy_source = LegacyTaintedValue(
                variable_name=vuln.source_label.original_variable,
                source_type=vuln.source_label.source_type,
                source_location=vuln.source_label.source_location,
                source_annotation=vuln.source_label.source_annotation,
                propagation_path=list(vuln.propagation_path)
            )

            results.append(DataflowVulnerability(
                sink_type=vuln.sink_type,
                source=legacy_source,
                sink_location=vuln.sink_location,
                sink_code=vuln.sink_method,
                method_chain=list(vuln.propagation_path),
                confidence=vuln.confidence
            ))

        return results
