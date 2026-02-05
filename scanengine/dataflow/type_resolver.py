"""
Type Resolver - Type hierarchy and polymorphism resolution

Provides type resolution for variables and tracks inheritance hierarchy
for resolving polymorphic method calls.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Set, Optional, Any, Tuple
from collections import defaultdict
from pathlib import Path
import re
import logging

logger = logging.getLogger(__name__)


@dataclass
class TypeInfo:
    """Information about a resolved type"""
    class_name: str
    package: Optional[str] = None
    is_interface: bool = False
    is_abstract: bool = False
    is_generic: bool = False
    type_parameters: List['TypeInfo'] = field(default_factory=list)
    file_path: Optional[str] = None

    @property
    def qualified_name(self) -> str:
        """Get fully qualified name"""
        if self.package:
            return f"{self.package}.{self.class_name}"
        return self.class_name

    @property
    def simple_name(self) -> str:
        """Get simple class name"""
        return self.class_name

    def __hash__(self):
        return hash((self.class_name, self.package))

    def __eq__(self, other):
        if not isinstance(other, TypeInfo):
            return False
        return self.class_name == other.class_name and self.package == other.package

    def __str__(self):
        return self.qualified_name


@dataclass
class MethodSignature:
    """Signature information for method resolution"""
    method_name: str
    class_name: str
    parameters: List[str]  # Parameter types
    return_type: Optional[str]
    file_path: str
    line_number: int
    is_static: bool = False
    is_abstract: bool = False
    visibility: str = "public"  # public, protected, private, package

    @property
    def unique_id(self) -> str:
        """Unique identifier for this method"""
        param_sig = ",".join(self.parameters) if self.parameters else ""
        return f"{self.file_path}:{self.class_name}:{self.method_name}({param_sig}):{self.line_number}"

    def matches_call(self, method_name: str, arg_count: int) -> bool:
        """Check if this signature matches a method call"""
        if self.method_name != method_name:
            return False
        # Allow varargs and optional parameters
        return len(self.parameters) >= arg_count or len(self.parameters) <= arg_count + 2


class TypeResolver:
    """
    Resolves types and tracks inheritance hierarchy.

    Provides:
    - Type inference for variables
    - Inheritance chain resolution
    - Polymorphic method call resolution
    """

    def __init__(self):
        # Maps: class_name -> ClassInfo
        self.class_registry: Dict[str, Any] = {}

        # Maps: class_name -> parent_class_name
        self.inheritance: Dict[str, str] = {}

        # Maps: interface_name -> [implementing_classes]
        self.interface_impls: Dict[str, List[str]] = defaultdict(list)

        # Maps: class_name -> [interface_names]
        self.class_interfaces: Dict[str, List[str]] = defaultdict(list)

        # Maps: class_name -> [MethodSignature]
        self.class_methods: Dict[str, List[MethodSignature]] = defaultdict(list)

        # Maps: method_name -> [(class_name, MethodSignature)]
        self.method_index: Dict[str, List[Tuple[str, MethodSignature]]] = defaultdict(list)

        # Variable type cache for current analysis
        self._var_types: Dict[str, TypeInfo] = {}

    def build_type_graph(self, files: List[Path], content_cache: Dict[str, str],
                        ast_analyzer: Any = None) -> None:
        """
        Build type hierarchy from all source files.

        Args:
            files: List of source files
            content_cache: File content cache
            ast_analyzer: JavaASTAnalyzer instance (optional)
        """
        if ast_analyzer is None:
            try:
                from ..ast_analyzer import JavaASTAnalyzer, TREE_SITTER_AVAILABLE
                if TREE_SITTER_AVAILABLE:
                    ast_analyzer = JavaASTAnalyzer()
                else:
                    logger.warning("Tree-sitter not available, type resolution limited")
                    return
            except ImportError:
                logger.warning("Could not import AST analyzer")
                return

        for file_path in files:
            if file_path.suffix.lower() not in ['.java']:
                continue

            content = content_cache.get(str(file_path), '')
            if not content:
                continue

            try:
                # Extract classes using AST analyzer
                classes = ast_analyzer.get_classes(content)
                for cls in classes:
                    self._register_class(cls, str(file_path))
            except Exception as e:
                logger.debug(f"Failed to parse {file_path} for types: {e}")

        logger.debug(f"TypeResolver built graph with {len(self.class_registry)} classes")

    def _register_class(self, cls: Any, file_path: str) -> None:
        """Register a class in the type registry"""
        class_name = cls.name
        self.class_registry[class_name] = cls

        # Track inheritance
        if cls.extends:
            self.inheritance[class_name] = cls.extends

        # Track interface implementations
        for interface in cls.implements:
            self.interface_impls[interface].append(class_name)
            self.class_interfaces[class_name].append(interface)

        # Register methods
        for method in cls.methods:
            sig = MethodSignature(
                method_name=method.name,
                class_name=class_name,
                parameters=self._parse_param_types(method.parameters),
                return_type=method.return_type,
                file_path=file_path,
                line_number=method.start_line,
                is_static='static' in method.modifiers,
                is_abstract='abstract' in method.modifiers,
            )
            self.class_methods[class_name].append(sig)
            self.method_index[method.name].append((class_name, sig))

    def _parse_param_types(self, parameters: List[str]) -> List[str]:
        """Extract type names from parameter declarations"""
        types = []
        for param in parameters:
            # Remove annotations
            param = re.sub(r'@\w+\s*(\([^)]*\))?\s*', '', param).strip()
            # Handle varargs
            param = param.replace('...', '')
            # Split by whitespace, type is second-to-last
            parts = param.split()
            if len(parts) >= 2:
                types.append(parts[-2])
            elif len(parts) == 1:
                types.append('Object')
        return types

    def resolve_variable_type(self, var_name: str,
                             method_params: List[str] = None,
                             local_declarations: Dict[str, str] = None) -> Optional[TypeInfo]:
        """
        Resolve the type of a variable from context.

        Args:
            var_name: Variable name
            method_params: Method parameter declarations
            local_declarations: Local variable declarations (name -> type)

        Returns:
            TypeInfo if type can be resolved
        """
        # Check cache
        if var_name in self._var_types:
            return self._var_types[var_name]

        # Check local declarations
        if local_declarations and var_name in local_declarations:
            type_name = local_declarations[var_name]
            type_info = self._create_type_info(type_name)
            self._var_types[var_name] = type_info
            return type_info

        # Check method parameters
        if method_params:
            for param in method_params:
                param = re.sub(r'@\w+\s*(\([^)]*\))?\s*', '', param).strip()
                parts = param.split()
                if len(parts) >= 2 and parts[-1] == var_name:
                    type_name = parts[-2]
                    type_info = self._create_type_info(type_name)
                    self._var_types[var_name] = type_info
                    return type_info

        return None

    def _create_type_info(self, type_name: str) -> TypeInfo:
        """Create TypeInfo from a type name string"""
        # Handle generics: List<String> -> List with type parameter String
        generic_match = re.match(r'(\w+)<(.+)>', type_name)
        if generic_match:
            base_type = generic_match.group(1)
            param_str = generic_match.group(2)
            # Simple split for single type parameter
            type_params = [self._create_type_info(p.strip()) for p in param_str.split(',')]
            return TypeInfo(
                class_name=base_type,
                is_generic=True,
                type_parameters=type_params
            )

        # Check if it's a known class
        if type_name in self.class_registry:
            cls = self.class_registry[type_name]
            return TypeInfo(
                class_name=type_name,
                is_interface=getattr(cls, 'is_interface', False),
            )

        # Check if it's a known interface
        if type_name in self.interface_impls:
            return TypeInfo(
                class_name=type_name,
                is_interface=True
            )

        return TypeInfo(class_name=type_name)

    def get_superclass_chain(self, class_name: str) -> List[str]:
        """
        Get inheritance chain from class to Object.

        Args:
            class_name: Starting class name

        Returns:
            List of class names from the given class up to Object
        """
        chain = [class_name]
        current = class_name

        # Follow inheritance chain
        while current in self.inheritance:
            parent = self.inheritance[current]
            if parent in chain:  # Prevent cycles
                break
            chain.append(parent)
            current = parent

        # Add Object if not already there
        if chain[-1] != 'Object':
            chain.append('Object')

        return chain

    def get_all_implementations(self, interface_name: str) -> List[str]:
        """Get all classes implementing an interface"""
        return self.interface_impls.get(interface_name, [])

    def get_interfaces(self, class_name: str) -> List[str]:
        """Get all interfaces implemented by a class (including inherited)"""
        interfaces = set(self.class_interfaces.get(class_name, []))

        # Also get interfaces from parent classes
        for parent in self.get_superclass_chain(class_name)[1:]:
            interfaces.update(self.class_interfaces.get(parent, []))

        return list(interfaces)

    def is_subtype_of(self, subtype: str, supertype: str) -> bool:
        """Check if subtype is a subclass/implementation of supertype"""
        if subtype == supertype:
            return True

        # Check class hierarchy
        if supertype in self.get_superclass_chain(subtype):
            return True

        # Check interface implementations
        if supertype in self.get_interfaces(subtype):
            return True

        return False

    def resolve_method_target(self, method_name: str,
                             receiver_type: Optional[TypeInfo] = None,
                             arg_count: int = 0) -> List[MethodSignature]:
        """
        Resolve possible targets for a method call (handles polymorphism).

        Args:
            method_name: Name of method being called
            receiver_type: Type of receiver object if known
            arg_count: Number of arguments in call

        Returns:
            List of possible method signatures that could be called
        """
        targets = []

        # If we have a receiver type, search its hierarchy
        if receiver_type:
            # Check the class itself
            self._find_method_in_class(method_name, receiver_type.class_name,
                                      arg_count, targets)

            # Check superclass chain
            for parent in self.get_superclass_chain(receiver_type.class_name)[1:]:
                self._find_method_in_class(method_name, parent, arg_count, targets)

            # If receiver is an interface, check all implementations
            if receiver_type.is_interface:
                for impl in self.get_all_implementations(receiver_type.class_name):
                    self._find_method_in_class(method_name, impl, arg_count, targets)

        # If no receiver type, search all methods with this name
        else:
            for class_name, sig in self.method_index.get(method_name, []):
                if sig.matches_call(method_name, arg_count):
                    targets.append(sig)

        return targets

    def _find_method_in_class(self, method_name: str, class_name: str,
                             arg_count: int, targets: List[MethodSignature]) -> None:
        """Find methods matching name and args in a class"""
        for sig in self.class_methods.get(class_name, []):
            if sig.matches_call(method_name, arg_count):
                if sig not in targets:
                    targets.append(sig)

    def infer_type_from_expression(self, expr_text: str) -> Optional[TypeInfo]:
        """
        Infer type from an expression string.

        Args:
            expr_text: Expression text (e.g., "new ArrayList<>()", "obj.getName()")

        Returns:
            Inferred type if determinable
        """
        expr_text = expr_text.strip()

        # Constructor: new ClassName(...)
        new_match = re.match(r'new\s+(\w+)(?:<[^>]*>)?\s*\(', expr_text)
        if new_match:
            return self._create_type_info(new_match.group(1))

        # String literal
        if expr_text.startswith('"') and expr_text.endswith('"'):
            return TypeInfo(class_name='String', package='java.lang')

        # Numeric literals
        if re.match(r'^-?\d+L?$', expr_text):
            return TypeInfo(class_name='long' if expr_text.endswith('L') else 'int')
        if re.match(r'^-?\d+\.\d+[fF]?$', expr_text):
            return TypeInfo(class_name='float' if expr_text.endswith(('f', 'F')) else 'double')

        # Boolean literal
        if expr_text in ('true', 'false'):
            return TypeInfo(class_name='boolean')

        # Method call - try to infer from known methods
        method_match = re.match(r'(\w+)\.(\w+)\(', expr_text)
        if method_match:
            obj_name, method_name = method_match.groups()
            obj_type = self._var_types.get(obj_name)
            if obj_type:
                targets = self.resolve_method_target(method_name, obj_type)
                if targets and targets[0].return_type:
                    return self._create_type_info(targets[0].return_type)

        return None

    def guess_type_from_name(self, var_name: str) -> Optional[TypeInfo]:
        """
        Guess type from variable naming conventions.

        E.g., userService -> UserService, requestBody -> RequestBody
        """
        # Common suffixes
        suffixes = ['Service', 'Repository', 'Controller', 'Manager',
                   'Helper', 'Util', 'Factory', 'Builder', 'Handler']

        for suffix in suffixes:
            if var_name.endswith(suffix.lower()):
                # Convert camelCase to PascalCase
                guessed = var_name[0].upper() + var_name[1:]
                if guessed in self.class_registry:
                    return self._create_type_info(guessed)

        # Try direct PascalCase conversion
        pascal_name = var_name[0].upper() + var_name[1:]
        if pascal_name in self.class_registry:
            return self._create_type_info(pascal_name)

        return None

    def clear_variable_cache(self):
        """Clear the variable type cache (call when starting new method analysis)"""
        self._var_types.clear()

    def set_variable_type(self, var_name: str, type_info: TypeInfo):
        """Set type for a variable"""
        self._var_types[var_name] = type_info

    def get_variable_type(self, var_name: str) -> Optional[TypeInfo]:
        """Get cached type for a variable"""
        return self._var_types.get(var_name)
