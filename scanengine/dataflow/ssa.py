"""
SSA (Static Single Assignment) Transformation

Converts AST to SSA form where each variable is assigned exactly once.
This enables precise tracking of data flow through the program.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any, Set, Tuple
from enum import Enum
import re
import logging

logger = logging.getLogger(__name__)


class ExpressionKind(Enum):
    """Types of expressions in SSA form"""
    LITERAL = "literal"
    VARIABLE = "variable"
    BINARY_OP = "binary_op"
    UNARY_OP = "unary_op"
    METHOD_CALL = "method_call"
    FIELD_ACCESS = "field_access"
    ARRAY_ACCESS = "array_access"
    CONSTRUCTOR = "constructor"
    CAST = "cast"
    TERNARY = "ternary"
    UNKNOWN = "unknown"


@dataclass
class SSAVariable:
    """A variable in SSA form with version number"""
    original_name: str      # Original variable name (e.g., "x")
    version: int           # SSA version number (e.g., 1, 2, 3)
    type_hint: Optional[str] = None  # Type if known
    is_parameter: bool = False
    parameter_index: int = -1
    annotations: List[str] = field(default_factory=list)  # Parameter annotations like @RequestParam

    @property
    def ssa_name(self) -> str:
        """Get the SSA-versioned name"""
        return f"{self.original_name}_{self.version}"

    def __hash__(self):
        return hash((self.original_name, self.version))

    def __eq__(self, other):
        if not isinstance(other, SSAVariable):
            return False
        return self.original_name == other.original_name and self.version == other.version

    def __str__(self):
        return self.ssa_name


@dataclass
class SSAExpression:
    """Expression in SSA form"""
    kind: ExpressionKind
    text: str  # Original source text
    children: List['SSAExpression'] = field(default_factory=list)
    value: Any = None  # For literals
    variable: Optional[SSAVariable] = None  # For variable references
    method_name: Optional[str] = None  # For method calls
    field_name: Optional[str] = None  # For field access
    receiver: Optional['SSAExpression'] = None  # For method calls and field access
    arguments: List['SSAExpression'] = field(default_factory=list)  # For method calls

    @classmethod
    def literal(cls, value: Any, text: str) -> 'SSAExpression':
        return cls(ExpressionKind.LITERAL, text, value=value)

    @classmethod
    def variable_ref(cls, var: SSAVariable) -> 'SSAExpression':
        return cls(ExpressionKind.VARIABLE, var.ssa_name, variable=var)

    @classmethod
    def method_call(cls, receiver: Optional['SSAExpression'],
                   method_name: str, arguments: List['SSAExpression'],
                   text: str) -> 'SSAExpression':
        return cls(ExpressionKind.METHOD_CALL, text,
                  method_name=method_name, receiver=receiver, arguments=arguments)

    @classmethod
    def field_access(cls, receiver: 'SSAExpression',
                    field_name: str, text: str) -> 'SSAExpression':
        return cls(ExpressionKind.FIELD_ACCESS, text,
                  field_name=field_name, receiver=receiver)

    @classmethod
    def binary_op(cls, left: 'SSAExpression', right: 'SSAExpression',
                 op: str, text: str) -> 'SSAExpression':
        expr = cls(ExpressionKind.BINARY_OP, text, children=[left, right])
        expr.value = op  # Store operator
        return expr


@dataclass
class SSAStatement:
    """Base class for SSA statements"""
    line_number: int
    column: int = 0
    defines: Optional[SSAVariable] = None  # Variable defined by this statement
    uses: List[SSAVariable] = field(default_factory=list)  # Variables used


@dataclass
class SSAAssignment(SSAStatement):
    """Assignment statement: x_1 = expr"""
    rhs: Optional[SSAExpression] = None


@dataclass
class SSAMethodCall(SSAStatement):
    """Method call statement: result_1 = obj.method(arg1, arg2)"""
    receiver: Optional[SSAVariable] = None  # Object the method is called on
    receiver_expr: Optional[SSAExpression] = None  # Full receiver expression
    method_name: str = ""
    arguments: List[SSAExpression] = field(default_factory=list)
    is_static: bool = False
    class_name: Optional[str] = None  # For static calls or known types


@dataclass
class SSAFieldAccess(SSAStatement):
    """Field access statement: x_1 = obj.field"""
    receiver: Optional[SSAVariable] = None
    receiver_expr: Optional[SSAExpression] = None
    field_name: str = ""
    is_write: bool = False  # True for obj.field = value


@dataclass
class SSAFieldWrite(SSAStatement):
    """Field write statement: obj.field = value"""
    receiver: Optional[SSAVariable] = None
    field_name: str = ""
    value: Optional[SSAExpression] = None


@dataclass
class SSAReturn(SSAStatement):
    """Return statement"""
    value: Optional[SSAExpression] = None


@dataclass
class SSAPhiFunction(SSAStatement):
    """Phi function: x_3 = phi(x_1, x_2) - merges control flow"""
    arguments: List[Tuple[SSAVariable, int]] = field(default_factory=list)  # (var, block_id)


@dataclass
class SSABasicBlock:
    """A basic block in the control flow graph"""
    id: int
    statements: List[SSAStatement] = field(default_factory=list)
    predecessors: List[int] = field(default_factory=list)  # Block IDs
    successors: List[int] = field(default_factory=list)  # Block IDs
    phi_functions: List[SSAPhiFunction] = field(default_factory=list)

    def add_statement(self, stmt: SSAStatement):
        self.statements.append(stmt)

    def add_phi(self, phi: SSAPhiFunction):
        self.phi_functions.append(phi)


@dataclass
class SSAMethod:
    """SSA form of a method"""
    name: str
    class_name: Optional[str]
    file_path: str
    start_line: int
    end_line: int
    parameters: List[SSAVariable] = field(default_factory=list)
    return_type: Optional[str] = None
    annotations: List[str] = field(default_factory=list)

    # CFG structure
    entry_block_id: int = 0
    blocks: Dict[int, SSABasicBlock] = field(default_factory=dict)

    # Variable tracking
    local_variables: Dict[str, List[SSAVariable]] = field(default_factory=dict)

    @property
    def unique_id(self) -> str:
        """Unique identifier for this method"""
        return f"{self.file_path}:{self.class_name or ''}:{self.name}:{self.start_line}"

    def get_all_statements(self) -> List[SSAStatement]:
        """Get all statements in order"""
        stmts = []
        for block in self.blocks.values():
            stmts.extend(block.phi_functions)
            stmts.extend(block.statements)
        return stmts

    def get_return_statements(self) -> List[SSAReturn]:
        """Get all return statements"""
        returns = []
        for stmt in self.get_all_statements():
            if isinstance(stmt, SSAReturn):
                returns.append(stmt)
        return returns


class SSATransformer:
    """
    Transforms method AST to SSA form.

    Uses a simplified approach suitable for taint analysis:
    1. Parse method body to extract assignments and calls
    2. Build a linear sequence of basic blocks (simplified CFG)
    3. Assign SSA versions to variables
    4. Insert phi functions at control flow merge points
    """

    def __init__(self):
        self.version_counters: Dict[str, int] = {}
        self.current_definitions: Dict[str, SSAVariable] = {}
        self.block_counter = 0

    def reset(self):
        """Reset state for new method"""
        self.version_counters = {}
        self.current_definitions = {}
        self.block_counter = 0

    def _new_version(self, var_name: str, type_hint: Optional[str] = None) -> SSAVariable:
        """Create a new SSA version for a variable"""
        if var_name not in self.version_counters:
            self.version_counters[var_name] = 0
        self.version_counters[var_name] += 1
        version = self.version_counters[var_name]

        var = SSAVariable(var_name, version, type_hint)
        self.current_definitions[var_name] = var
        return var

    def _get_current(self, var_name: str) -> Optional[SSAVariable]:
        """Get the current SSA version of a variable"""
        return self.current_definitions.get(var_name)

    def _new_block(self) -> SSABasicBlock:
        """Create a new basic block"""
        block = SSABasicBlock(self.block_counter)
        self.block_counter += 1
        return block

    def transform_method(self, method_info: Any, code: str,
                        file_path: str) -> SSAMethod:
        """
        Transform a method to SSA form.

        Args:
            method_info: MethodInfo from ast_analyzer
            code: Full source code
            file_path: Path to source file
        """
        self.reset()

        # Create SSA method structure
        ssa_method = SSAMethod(
            name=method_info.name,
            class_name=method_info.class_name,
            file_path=file_path,
            start_line=method_info.start_line,
            end_line=method_info.end_line,
            return_type=method_info.return_type,
            annotations=method_info.annotations,
        )

        # Process parameters - each parameter gets version 1
        for i, param_str in enumerate(method_info.parameters):
            param_name, param_type, param_annotations = self._parse_parameter(param_str)
            if param_name:
                var = self._new_version(param_name, param_type)
                var.is_parameter = True
                var.parameter_index = i
                var.annotations = param_annotations
                ssa_method.parameters.append(var)
                if param_name not in ssa_method.local_variables:
                    ssa_method.local_variables[param_name] = []
                ssa_method.local_variables[param_name].append(var)

        # Create entry block
        entry_block = self._new_block()
        ssa_method.entry_block_id = entry_block.id
        ssa_method.blocks[entry_block.id] = entry_block

        # Parse method body
        body = method_info.body_text
        self._transform_body(body, entry_block, ssa_method)

        return ssa_method

    def _parse_parameter(self, param_str: str) -> Tuple[Optional[str], Optional[str], List[str]]:
        """Parse a parameter string like 'String name' or '@RequestParam String id'"""
        # Extract annotations first
        annotations = re.findall(r'@\w+(?:\s*\([^)]*\))?', param_str)

        # Remove annotations for name/type parsing
        clean_str = re.sub(r'@\w+\s*(\([^)]*\))?\s*', '', param_str).strip()

        # Handle varargs
        clean_str = clean_str.replace('...', '')

        # Split by whitespace
        parts = clean_str.split()
        if len(parts) >= 2:
            param_type = parts[-2]
            param_name = parts[-1]
            return param_name, param_type, annotations
        elif len(parts) == 1:
            return parts[0], None, annotations
        return None, None, annotations

    def _transform_body(self, body: str, block: SSABasicBlock,
                       ssa_method: SSAMethod):
        """Transform method body to SSA statements"""
        lines = body.split('\n')

        for line_offset, line in enumerate(lines):
            line = line.strip()
            if not line or line.startswith('//') or line.startswith('/*'):
                continue

            # Try to parse different statement types
            stmt = self._parse_statement(line, ssa_method.start_line + line_offset)
            if stmt:
                block.add_statement(stmt)

                # Track variable definitions
                if stmt.defines:
                    var = stmt.defines
                    if var.original_name not in ssa_method.local_variables:
                        ssa_method.local_variables[var.original_name] = []
                    ssa_method.local_variables[var.original_name].append(var)

    def _parse_statement(self, line: str, line_number: int) -> Optional[SSAStatement]:
        """Parse a single line into an SSA statement"""
        line = line.rstrip(';').strip()

        # Return statement
        if line.startswith('return '):
            return self._parse_return(line, line_number)

        # Assignment with declaration: Type var = expr
        decl_match = re.match(
            r'(?:final\s+)?(\w+(?:<[^>]+>)?)\s+(\w+)\s*=\s*(.+)',
            line
        )
        if decl_match:
            var_type, var_name, expr_text = decl_match.groups()
            return self._parse_assignment(var_name, expr_text, line_number, var_type)

        # Simple assignment: var = expr
        assign_match = re.match(r'(\w+)\s*=\s*(.+)', line)
        if assign_match:
            var_name, expr_text = assign_match.groups()
            return self._parse_assignment(var_name, expr_text, line_number)

        # Field assignment: obj.field = expr
        field_assign_match = re.match(r'(\w+)\.(\w+)\s*=\s*(.+)', line)
        if field_assign_match:
            obj_name, field_name, expr_text = field_assign_match.groups()
            return self._parse_field_write(obj_name, field_name, expr_text, line_number)

        # Method call without assignment
        if '(' in line and not line.startswith('if') and not line.startswith('for'):
            return self._parse_method_call_stmt(line, line_number)

        return None

    def _parse_assignment(self, var_name: str, expr_text: str,
                         line_number: int, var_type: Optional[str] = None) -> SSAAssignment:
        """Parse an assignment statement"""
        # Create new SSA version for the variable
        new_var = self._new_version(var_name, var_type)

        # Parse the right-hand side expression
        rhs = self._parse_expression(expr_text)

        # Collect used variables
        uses = self._collect_used_variables(rhs)

        return SSAAssignment(
            line_number=line_number,
            defines=new_var,
            uses=uses,
            rhs=rhs
        )

    def _parse_return(self, line: str, line_number: int) -> SSAReturn:
        """Parse a return statement"""
        expr_text = line[7:].strip()  # Remove 'return '

        if not expr_text:
            return SSAReturn(line_number=line_number)

        value = self._parse_expression(expr_text)
        uses = self._collect_used_variables(value)

        return SSAReturn(
            line_number=line_number,
            uses=uses,
            value=value
        )

    def _parse_field_write(self, obj_name: str, field_name: str,
                          expr_text: str, line_number: int) -> SSAFieldWrite:
        """Parse a field write: obj.field = value"""
        receiver = self._get_current(obj_name)
        value = self._parse_expression(expr_text)
        uses = self._collect_used_variables(value)
        if receiver:
            uses.append(receiver)

        return SSAFieldWrite(
            line_number=line_number,
            receiver=receiver,
            field_name=field_name,
            value=value,
            uses=uses
        )

    def _parse_method_call_stmt(self, line: str,
                                line_number: int) -> Optional[SSAMethodCall]:
        """Parse a standalone method call"""
        # Pattern: obj.method(args) or method(args) or Class.method(args)
        match = re.match(r'(?:(\w+(?:\.\w+)*)\.)?(\w+)\s*\(([^)]*)\)', line)
        if not match:
            return None

        receiver_text, method_name, args_text = match.groups()

        receiver = None
        receiver_expr = None
        is_static = False
        class_name = None

        if receiver_text:
            # Check if it's a class name (static call) or variable
            if receiver_text[0].isupper():
                is_static = True
                class_name = receiver_text
            else:
                receiver = self._get_current(receiver_text)
                if receiver:
                    receiver_expr = SSAExpression.variable_ref(receiver)

        arguments = self._parse_arguments(args_text)
        uses = []
        if receiver:
            uses.append(receiver)
        for arg in arguments:
            uses.extend(self._collect_used_variables(arg))

        return SSAMethodCall(
            line_number=line_number,
            receiver=receiver,
            receiver_expr=receiver_expr,
            method_name=method_name,
            arguments=arguments,
            is_static=is_static,
            class_name=class_name,
            uses=uses
        )

    def _parse_expression(self, text: str) -> SSAExpression:
        """Parse an expression into SSA form"""
        text = text.strip()

        # Null/boolean literals
        if text in ('null', 'true', 'false'):
            return SSAExpression.literal(text, text)

        # Numeric literal
        if re.match(r'^-?\d+(\.\d+)?[LlFfDd]?$', text):
            return SSAExpression.literal(text, text)

        # String literal
        if text.startswith('"') and text.endswith('"'):
            return SSAExpression.literal(text[1:-1], text)

        # Constructor: new Class(args)
        new_match = re.match(r'new\s+(\w+(?:<[^>]+>)?)\s*\(([^)]*)\)', text)
        if new_match:
            class_name, args_text = new_match.groups()
            arguments = self._parse_arguments(args_text)
            expr = SSAExpression(ExpressionKind.CONSTRUCTOR, text)
            expr.value = class_name
            expr.arguments = arguments
            return expr

        # Method call chain: obj.method1().method2()
        if '(' in text:
            return self._parse_method_chain(text)

        # Field access: obj.field
        if '.' in text and '(' not in text:
            parts = text.rsplit('.', 1)
            receiver = self._parse_expression(parts[0])
            return SSAExpression.field_access(receiver, parts[1], text)

        # Binary operation: a + b, a && b, etc.
        for op in [' + ', ' - ', ' * ', ' / ', ' && ', ' || ', ' == ', ' != ', ' < ', ' > ']:
            if op in text:
                idx = text.find(op)
                left = self._parse_expression(text[:idx])
                right = self._parse_expression(text[idx + len(op):])
                return SSAExpression.binary_op(left, right, op.strip(), text)

        # Simple variable reference
        var = self._get_current(text)
        if var:
            return SSAExpression.variable_ref(var)

        # Unknown - treat as literal
        return SSAExpression(ExpressionKind.UNKNOWN, text, value=text)

    def _parse_method_chain(self, text: str) -> SSAExpression:
        """Parse a method call chain like obj.method1().method2()"""
        # Find the outermost method call
        depth = 0
        last_dot = -1

        for i, c in enumerate(text):
            if c == '(':
                depth += 1
            elif c == ')':
                depth -= 1
            elif c == '.' and depth == 0:
                last_dot = i

        if last_dot > 0:
            # Split at last dot
            receiver_text = text[:last_dot]
            call_text = text[last_dot + 1:]

            # Parse the call part: method(args)
            match = re.match(r'(\w+)\s*\(([^)]*)\)', call_text)
            if match:
                method_name, args_text = match.groups()
                receiver = self._parse_expression(receiver_text)
                arguments = self._parse_arguments(args_text)
                return SSAExpression.method_call(receiver, method_name, arguments, text)

        # Simple method call: method(args)
        match = re.match(r'(\w+)\s*\(([^)]*)\)', text)
        if match:
            method_name, args_text = match.groups()
            arguments = self._parse_arguments(args_text)
            return SSAExpression.method_call(None, method_name, arguments, text)

        return SSAExpression(ExpressionKind.UNKNOWN, text)

    def _parse_arguments(self, args_text: str) -> List[SSAExpression]:
        """Parse method arguments"""
        if not args_text.strip():
            return []

        arguments = []
        depth = 0
        current = ""

        for c in args_text:
            if c == ',' and depth == 0:
                if current.strip():
                    arguments.append(self._parse_expression(current.strip()))
                current = ""
            else:
                if c in '([{':
                    depth += 1
                elif c in ')]}':
                    depth -= 1
                current += c

        if current.strip():
            arguments.append(self._parse_expression(current.strip()))

        return arguments

    def _collect_used_variables(self, expr: Optional[SSAExpression]) -> List[SSAVariable]:
        """Collect all SSA variables used in an expression"""
        if not expr:
            return []

        used = []

        if expr.variable:
            used.append(expr.variable)

        if expr.receiver:
            used.extend(self._collect_used_variables(expr.receiver))

        for arg in expr.arguments:
            used.extend(self._collect_used_variables(arg))

        for child in expr.children:
            used.extend(self._collect_used_variables(child))

        return used
