"""
Transfer Functions - Define how taint propagates through statements

Provides transfer functions for each type of SSA statement,
defining how taint values are transformed.
"""

from __future__ import annotations

from typing import Dict, List, Set, Optional, Callable, Any, Tuple
from dataclasses import dataclass
import logging

from .ssa import (
    SSAStatement, SSAAssignment, SSAMethodCall, SSAFieldAccess,
    SSAFieldWrite, SSAReturn, SSAPhiFunction, SSAVariable, SSAExpression,
    ExpressionKind
)
from .taint_lattice import (
    TaintLevel, TaintLabel, TaintValue, TaintAbstractState, TaintLattice
)
from .sanitizers import SanitizerRegistry, Sanitizer, is_taint_preserving
from .type_resolver import TypeResolver, TypeInfo

import sys
sys.path.insert(0, str(__file__).rsplit('/', 2)[0])
from ..dataflow_analyzer import TaintSource, SinkType

logger = logging.getLogger(__name__)


# ============================================================
# TAINT SOURCE DETECTION
# ============================================================

# Methods that return tainted data
TAINT_SOURCE_METHODS = {
    # HTTP Request methods (Java/Spring)
    'getParameter': TaintSource.HTTP_PARAMETER,
    'getQueryString': TaintSource.HTTP_PARAMETER,
    'getParameterValues': TaintSource.HTTP_PARAMETER,
    'getParameterMap': TaintSource.HTTP_PARAMETER,
    'getHeader': TaintSource.HTTP_HEADER,
    'getHeaders': TaintSource.HTTP_HEADER,
    'getCookies': TaintSource.COOKIE,
    'getCookie': TaintSource.COOKIE,
    'getInputStream': TaintSource.HTTP_BODY,
    'getReader': TaintSource.HTTP_BODY,
    'getRequestBody': TaintSource.HTTP_BODY,
    'getBody': TaintSource.HTTP_BODY,
    'getPathInfo': TaintSource.PATH_VARIABLE,
    'getRequestURI': TaintSource.PATH_VARIABLE,
    'getRequestURL': TaintSource.PATH_VARIABLE,
    'getServletPath': TaintSource.PATH_VARIABLE,

    # File/IO sources
    'readLine': TaintSource.FILE_INPUT,
    'readAllLines': TaintSource.FILE_INPUT,
    'readAllBytes': TaintSource.FILE_INPUT,
    'read': TaintSource.FILE_INPUT,

    # Environment
    'getenv': TaintSource.ENVIRONMENT,
    'getProperty': TaintSource.ENVIRONMENT,

    # Database (when reading user data)
    'getString': TaintSource.DATABASE,
    'getObject': TaintSource.DATABASE,
    'next': TaintSource.DATABASE,  # ResultSet.next() context

    # Generic user input
    'nextLine': TaintSource.USER_INPUT,
    'next': TaintSource.USER_INPUT,
}

# Annotations that indicate tainted parameters
TAINT_SOURCE_ANNOTATIONS = {
    '@RequestParam': TaintSource.HTTP_PARAMETER,
    '@QueryParam': TaintSource.HTTP_PARAMETER,
    '@PathVariable': TaintSource.PATH_VARIABLE,
    '@PathParam': TaintSource.PATH_VARIABLE,
    '@RequestBody': TaintSource.HTTP_BODY,
    '@RequestHeader': TaintSource.HTTP_HEADER,
    '@HeaderParam': TaintSource.HTTP_HEADER,
    '@CookieValue': TaintSource.COOKIE,
    '@CookieParam': TaintSource.COOKIE,
    '@FormParam': TaintSource.HTTP_PARAMETER,
    '@MatrixParam': TaintSource.HTTP_PARAMETER,
}


# ============================================================
# SINK DETECTION
# ============================================================

# Methods that are dangerous sinks
SINK_METHODS = {
    # SQL Injection
    'executeQuery': SinkType.SQL_QUERY,
    'executeUpdate': SinkType.SQL_QUERY,
    'execute': SinkType.SQL_QUERY,
    'createQuery': SinkType.SQL_QUERY,
    'createNativeQuery': SinkType.SQL_QUERY,
    'createSQLQuery': SinkType.SQL_QUERY,
    'rawQuery': SinkType.SQL_QUERY,

    # Command Injection
    'exec': SinkType.COMMAND_EXEC,
    'start': SinkType.COMMAND_EXEC,  # ProcessBuilder.start()
    'command': SinkType.COMMAND_EXEC,  # ProcessBuilder.command()

    # File Access / Path Traversal
    'FileInputStream': SinkType.FILE_ACCESS,
    'FileOutputStream': SinkType.FILE_ACCESS,
    'FileReader': SinkType.FILE_ACCESS,
    'FileWriter': SinkType.FILE_ACCESS,
    'newInputStream': SinkType.FILE_ACCESS,
    'newOutputStream': SinkType.FILE_ACCESS,
    'readAllBytes': SinkType.FILE_ACCESS,
    'readAllLines': SinkType.FILE_ACCESS,
    'write': SinkType.FILE_ACCESS,
    'delete': SinkType.FILE_ACCESS,
    'exists': SinkType.FILE_ACCESS,

    # SSRF
    'openConnection': SinkType.SSRF,
    'openStream': SinkType.SSRF,
    'getForObject': SinkType.SSRF,
    'getForEntity': SinkType.SSRF,
    'postForObject': SinkType.SSRF,
    'postForEntity': SinkType.SSRF,
    'exchange': SinkType.SSRF,
    'retrieve': SinkType.SSRF,
    'newCall': SinkType.SSRF,

    # XSS
    'write': SinkType.XSS,  # Response writer
    'print': SinkType.XSS,
    'println': SinkType.XSS,
    'append': SinkType.XSS,
    'setAttribute': SinkType.XSS,

    # Deserialization
    'readObject': SinkType.DESERIALIZATION,
    'readUnshared': SinkType.DESERIALIZATION,
    'fromJson': SinkType.DESERIALIZATION,
    'readValue': SinkType.DESERIALIZATION,
    'unmarshal': SinkType.DESERIALIZATION,

    # LDAP
    'search': SinkType.LDAP_QUERY,
    'lookup': SinkType.LDAP_QUERY,

    # XPath
    'evaluate': SinkType.XPATH_QUERY,
    'selectNodes': SinkType.XPATH_QUERY,
    'selectSingleNode': SinkType.XPATH_QUERY,

    # Logging (sensitive data)
    'info': SinkType.LOG_OUTPUT,
    'debug': SinkType.LOG_OUTPUT,
    'warn': SinkType.LOG_OUTPUT,
    'error': SinkType.LOG_OUTPUT,
    'trace': SinkType.LOG_OUTPUT,
    'log': SinkType.LOG_OUTPUT,
}


@dataclass
class TransferResult:
    """Result of applying a transfer function"""
    new_state: TaintAbstractState
    is_sink_reached: bool = False
    sink_type: Optional[SinkType] = None
    sink_argument_taint: Optional[TaintValue] = None


class TransferFunctionRegistry:
    """
    Registry of transfer functions for different statement types.

    Transfer functions define how taint propagates through each statement.
    """

    def __init__(self, sanitizer_registry: SanitizerRegistry,
                type_resolver: TypeResolver):
        self.sanitizer_registry = sanitizer_registry
        self.type_resolver = type_resolver

        # Current method context for source detection
        self.current_method_annotations: List[str] = []
        self.current_file_path: str = ""
        self.current_line: int = 0

    def set_context(self, annotations: List[str], file_path: str):
        """Set context for current method being analyzed"""
        self.current_method_annotations = annotations
        self.current_file_path = file_path

    def transfer(self, stmt: SSAStatement,
                state: TaintAbstractState) -> TransferResult:
        """
        Apply transfer function for a statement.

        Args:
            stmt: SSA statement to process
            state: Current abstract state

        Returns:
            TransferResult with new state and sink detection info
        """
        self.current_line = stmt.line_number

        if isinstance(stmt, SSAAssignment):
            return self._transfer_assignment(stmt, state)
        elif isinstance(stmt, SSAMethodCall):
            return self._transfer_method_call(stmt, state)
        elif isinstance(stmt, SSAFieldAccess):
            return self._transfer_field_access(stmt, state)
        elif isinstance(stmt, SSAFieldWrite):
            return self._transfer_field_write(stmt, state)
        elif isinstance(stmt, SSAReturn):
            return self._transfer_return(stmt, state)
        elif isinstance(stmt, SSAPhiFunction):
            return self._transfer_phi(stmt, state)
        else:
            return TransferResult(state)

    def _transfer_assignment(self, stmt: SSAAssignment,
                            state: TaintAbstractState) -> TransferResult:
        """
        Transfer for assignment: x = expr

        Taint of x becomes taint of expr.
        """
        if not stmt.defines or not stmt.rhs:
            return TransferResult(state)

        rhs_taint = self._evaluate_expression_taint(stmt.rhs, state)
        new_state = state.set(stmt.defines.ssa_name, rhs_taint)

        return TransferResult(new_state)

    def _transfer_method_call(self, stmt: SSAMethodCall,
                             state: TaintAbstractState) -> TransferResult:
        """
        Transfer for method call: result = obj.method(args)

        Handles:
        - Sanitizer calls (clear/reduce taint)
        - Source calls (introduce taint)
        - Sink calls (detect vulnerabilities)
        - Normal calls (propagate taint)
        """
        # Check if this is a sanitizer call
        sanitizer = self._check_sanitizer(stmt)
        if sanitizer:
            return self._handle_sanitizer_call(stmt, state, sanitizer)

        # Check if this is a taint source
        source_type = self._check_source(stmt)
        if source_type:
            return self._handle_source_call(stmt, state, source_type)

        # Check if this is a sink
        sink_type = self._check_sink(stmt)
        sink_reached = False
        sink_taint = None

        if sink_type:
            # Check if any tainted argument reaches the sink
            for arg in stmt.arguments:
                arg_taint = self._evaluate_expression_taint(arg, state)
                if arg_taint.is_tainted_for(sink_type):
                    sink_reached = True
                    sink_taint = arg_taint
                    break

        # Normal call - propagate taint through
        result_taint = self._compute_call_result_taint(stmt, state)

        new_state = state
        if stmt.defines:
            new_state = state.set(stmt.defines.ssa_name, result_taint)

        # Handle collection mutations
        new_state = self._handle_collection_mutation(stmt, new_state)

        return TransferResult(
            new_state,
            is_sink_reached=sink_reached,
            sink_type=sink_type if sink_reached else None,
            sink_argument_taint=sink_taint
        )

    def _transfer_field_access(self, stmt: SSAFieldAccess,
                              state: TaintAbstractState) -> TransferResult:
        """
        Transfer for field access: x = obj.field

        Result taint is join of object taint and field-specific taint.
        """
        if not stmt.defines:
            return TransferResult(state)

        # Get object taint
        obj_taint = TaintValue.untainted()
        if stmt.receiver:
            obj_taint = state.get(stmt.receiver.ssa_name)

        # Get field-specific taint
        field_taint = TaintValue.untainted()
        if stmt.receiver:
            field_taint = state.get_field(stmt.receiver.ssa_name, stmt.field_name)

        # Result is join of both
        result_taint = TaintLattice.join(obj_taint, field_taint)

        new_state = state.set(stmt.defines.ssa_name, result_taint)
        return TransferResult(new_state)

    def _transfer_field_write(self, stmt: SSAFieldWrite,
                             state: TaintAbstractState) -> TransferResult:
        """
        Transfer for field write: obj.field = value

        Propagates taint from value to the field.
        """
        if not stmt.value or not stmt.receiver:
            return TransferResult(state)

        value_taint = self._evaluate_expression_taint(stmt.value, state)
        new_state = state.set_field(
            stmt.receiver.ssa_name,
            stmt.field_name,
            value_taint
        )

        return TransferResult(new_state)

    def _transfer_return(self, stmt: SSAReturn,
                        state: TaintAbstractState) -> TransferResult:
        """
        Transfer for return statement.

        Sets the method's return taint.
        """
        if not stmt.value:
            return TransferResult(state)

        return_taint = self._evaluate_expression_taint(stmt.value, state)
        new_state = state.set_return(return_taint)

        return TransferResult(new_state)

    def _transfer_phi(self, stmt: SSAPhiFunction,
                     state: TaintAbstractState) -> TransferResult:
        """
        Transfer for phi function: x_3 = phi(x_1, x_2)

        Result is join of all incoming values.
        """
        if not stmt.defines:
            return TransferResult(state)

        joined = TaintValue.bottom()
        for var, block_id in stmt.arguments:
            var_taint = state.get(var.ssa_name)
            joined = TaintLattice.join(joined, var_taint)

        new_state = state.set(stmt.defines.ssa_name, joined)
        return TransferResult(new_state)

    # ============================================================
    # EXPRESSION EVALUATION
    # ============================================================

    def _evaluate_expression_taint(self, expr: SSAExpression,
                                   state: TaintAbstractState) -> TaintValue:
        """Recursively evaluate taint of an expression"""
        if expr.kind == ExpressionKind.LITERAL:
            return TaintValue.untainted()

        elif expr.kind == ExpressionKind.VARIABLE:
            if expr.variable:
                return state.get(expr.variable.ssa_name)
            return TaintValue.untainted()

        elif expr.kind == ExpressionKind.BINARY_OP:
            # String concatenation and arithmetic preserve taint
            left = self._evaluate_expression_taint(expr.children[0], state) if expr.children else TaintValue.untainted()
            right = self._evaluate_expression_taint(expr.children[1], state) if len(expr.children) > 1 else TaintValue.untainted()
            return TaintLattice.join(left, right)

        elif expr.kind == ExpressionKind.METHOD_CALL:
            return self._evaluate_method_call_taint(expr, state)

        elif expr.kind == ExpressionKind.FIELD_ACCESS:
            receiver_taint = self._evaluate_expression_taint(expr.receiver, state) if expr.receiver else TaintValue.untainted()
            return receiver_taint  # Field access preserves receiver taint

        elif expr.kind == ExpressionKind.ARRAY_ACCESS:
            # Array access returns collection taint
            if expr.receiver and expr.receiver.variable:
                return state.get_collection(expr.receiver.variable.ssa_name)
            return TaintValue.untainted()

        elif expr.kind == ExpressionKind.CONSTRUCTOR:
            # Constructor: new Class(args) - taint from args
            result = TaintValue.untainted()
            for arg in expr.arguments:
                arg_taint = self._evaluate_expression_taint(arg, state)
                result = TaintLattice.join(result, arg_taint)
            return result

        return TaintValue.untainted()

    def _evaluate_method_call_taint(self, expr: SSAExpression,
                                   state: TaintAbstractState) -> TaintValue:
        """Evaluate taint for a method call expression"""
        method_name = expr.method_name or ""

        # Check if source method
        if method_name in TAINT_SOURCE_METHODS:
            source = TAINT_SOURCE_METHODS[method_name]
            label = TaintLabel(source, f"{self.current_file_path}:{self.current_line}",
                              method_name, method_name)
            return TaintValue.tainted(label)

        # Check if sanitizer
        sanitizer = self.sanitizer_registry.get_sanitization(method_name)
        if sanitizer and sanitizer.returns_sanitized and expr.arguments:
            arg_taint = self._evaluate_expression_taint(expr.arguments[0], state)
            return arg_taint.with_sanitization(sanitizer.sanitizes_for)

        # Check if taint-preserving (like trim, toLowerCase)
        if is_taint_preserving(method_name):
            if expr.receiver:
                return self._evaluate_expression_taint(expr.receiver, state)

        # Default: propagate taint from arguments and receiver
        result = TaintValue.untainted()

        if expr.receiver:
            receiver_taint = self._evaluate_expression_taint(expr.receiver, state)
            result = TaintLattice.join(result, receiver_taint)

        for arg in expr.arguments:
            arg_taint = self._evaluate_expression_taint(arg, state)
            result = TaintLattice.join(result, arg_taint)

        return result

    # ============================================================
    # HELPER METHODS
    # ============================================================

    def _check_sanitizer(self, stmt: SSAMethodCall) -> Optional[Sanitizer]:
        """Check if method call is a sanitizer"""
        receiver_type = None
        if stmt.receiver:
            receiver_type = self.type_resolver.get_variable_type(stmt.receiver.original_name)

        return self.sanitizer_registry.get_sanitization(
            stmt.method_name,
            receiver_type.class_name if receiver_type else stmt.class_name
        )

    def _handle_sanitizer_call(self, stmt: SSAMethodCall,
                              state: TaintAbstractState,
                              sanitizer: Sanitizer) -> TransferResult:
        """Handle a sanitizer method call"""
        if not stmt.defines:
            return TransferResult(state)

        # Get argument taint (the value being sanitized)
        arg_idx = sanitizer.argument_index
        if arg_idx == -1:  # Receiver is being sanitized
            if stmt.receiver:
                arg_taint = state.get(stmt.receiver.ssa_name)
            else:
                arg_taint = TaintValue.untainted()
        elif arg_idx < len(stmt.arguments):
            arg_taint = self._evaluate_expression_taint(stmt.arguments[arg_idx], state)
        else:
            arg_taint = TaintValue.untainted()

        # Apply sanitization
        if sanitizer.returns_sanitized:
            sanitized_taint = arg_taint.with_sanitization(sanitizer.sanitizes_for)
            new_state = state.set(stmt.defines.ssa_name, sanitized_taint)
        else:
            new_state = state.set(stmt.defines.ssa_name, arg_taint)

        return TransferResult(new_state)

    def _check_source(self, stmt: SSAMethodCall) -> Optional[TaintSource]:
        """Check if method call is a taint source"""
        # Check method name
        if stmt.method_name in TAINT_SOURCE_METHODS:
            return TAINT_SOURCE_METHODS[stmt.method_name]

        return None

    def _handle_source_call(self, stmt: SSAMethodCall,
                           state: TaintAbstractState,
                           source: TaintSource) -> TransferResult:
        """Handle a taint source method call"""
        if not stmt.defines:
            return TransferResult(state)

        label = TaintLabel(
            source,
            f"{self.current_file_path}:{stmt.line_number}",
            stmt.method_name,
            stmt.defines.original_name
        )
        taint = TaintValue.tainted(label, (f"{stmt.method_name}@{stmt.line_number}",))

        new_state = state.set(stmt.defines.ssa_name, taint)
        return TransferResult(new_state)

    def _check_sink(self, stmt: SSAMethodCall) -> Optional[SinkType]:
        """Check if method call is a dangerous sink"""
        if stmt.method_name in SINK_METHODS:
            return SINK_METHODS[stmt.method_name]
        return None

    def _compute_call_result_taint(self, stmt: SSAMethodCall,
                                  state: TaintAbstractState) -> TaintValue:
        """Compute taint for result of a method call"""
        result = TaintValue.untainted()

        # Propagate from receiver
        if stmt.receiver:
            recv_taint = state.get(stmt.receiver.ssa_name)
            result = TaintLattice.join(result, recv_taint)

        # Propagate from arguments (for methods that return transformed input)
        if is_taint_preserving(stmt.method_name):
            for arg in stmt.arguments:
                arg_taint = self._evaluate_expression_taint(arg, state)
                result = TaintLattice.join(result, arg_taint)

        return result

    def _handle_collection_mutation(self, stmt: SSAMethodCall,
                                   state: TaintAbstractState) -> TaintAbstractState:
        """Handle collection add/put operations"""
        COLLECTION_ADD_METHODS = {'add', 'addAll', 'put', 'putAll', 'set',
                                  'push', 'offer', 'addFirst', 'addLast'}

        if stmt.method_name not in COLLECTION_ADD_METHODS:
            return state

        if not stmt.receiver or not stmt.arguments:
            return state

        # Get taint of value being added
        value_taint = self._evaluate_expression_taint(stmt.arguments[-1], state)

        if value_taint.is_tainted:
            # Mark collection as containing tainted data
            return state.set_collection(stmt.receiver.ssa_name, value_taint)

        return state


def check_parameter_source(annotations: List[str]) -> Optional[TaintSource]:
    """Check if parameter annotations indicate a taint source"""
    for annotation in annotations:
        for ann_pattern, source in TAINT_SOURCE_ANNOTATIONS.items():
            if ann_pattern in annotation:
                return source
    return None
