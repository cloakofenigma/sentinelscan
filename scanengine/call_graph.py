"""
Call Graph Constructor - Builds method call relationships for inter-procedural analysis
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import List, Dict, Set, Optional, Tuple, Any
from dataclasses import dataclass, field
from collections import defaultdict
import logging

from .ast_analyzer import (
    JavaASTAnalyzer, PythonASTAnalyzer, JavaScriptASTAnalyzer,
    get_ast_analyzer, TREE_SITTER_AVAILABLE, MethodInfo, ClassInfo
)

logger = logging.getLogger(__name__)


@dataclass
class MethodSignature:
    """Represents a unique method signature"""
    class_name: Optional[str]
    method_name: str
    file_path: str
    line_number: int
    parameters: List[str] = field(default_factory=list)
    return_type: Optional[str] = None
    annotations: List[str] = field(default_factory=list)

    @property
    def qualified_name(self) -> str:
        """Get fully qualified method name"""
        if self.class_name:
            return f"{self.class_name}.{self.method_name}"
        return self.method_name

    @property
    def unique_id(self) -> str:
        """Get unique identifier for this method"""
        return f"{self.file_path}:{self.class_name or ''}:{self.method_name}:{self.line_number}"

    def __hash__(self):
        return hash(self.unique_id)

    def __eq__(self, other):
        if isinstance(other, MethodSignature):
            return self.unique_id == other.unique_id
        return False


@dataclass
class MethodCall:
    """Represents a method call"""
    caller: MethodSignature
    callee_name: str
    callee_object: Optional[str]  # The object the method is called on
    arguments: List[str]
    line_number: int
    file_path: str

    @property
    def callee_qualified_hint(self) -> str:
        """Get a hint for the callee's qualified name"""
        if self.callee_object:
            return f"{self.callee_object}.{self.callee_name}"
        return self.callee_name


@dataclass
class CallGraphNode:
    """Node in the call graph representing a method"""
    signature: MethodSignature
    callers: Set[str] = field(default_factory=set)  # unique_ids of callers
    callees: Set[str] = field(default_factory=set)  # unique_ids of callees
    call_sites: List[MethodCall] = field(default_factory=list)


class CallGraph:
    """
    Represents the call graph of a codebase.
    Maps methods to their callers and callees.
    """

    def __init__(self):
        self.nodes: Dict[str, CallGraphNode] = {}  # unique_id -> node
        self.method_index: Dict[str, List[str]] = defaultdict(list)  # method_name -> [unique_ids]
        self.class_index: Dict[str, List[str]] = defaultdict(list)  # class_name -> [unique_ids]
        self.file_index: Dict[str, List[str]] = defaultdict(list)  # file_path -> [unique_ids]

    def add_method(self, signature: MethodSignature) -> CallGraphNode:
        """Add a method to the call graph"""
        uid = signature.unique_id
        if uid not in self.nodes:
            self.nodes[uid] = CallGraphNode(signature=signature)
            self.method_index[signature.method_name].append(uid)
            if signature.class_name:
                self.class_index[signature.class_name].append(uid)
            self.file_index[signature.file_path].append(uid)
        return self.nodes[uid]

    def add_call(self, call: MethodCall, callee_signature: Optional[MethodSignature] = None):
        """Add a method call edge to the graph"""
        caller_uid = call.caller.unique_id

        # Ensure caller exists
        if caller_uid not in self.nodes:
            self.add_method(call.caller)

        # Add call site
        self.nodes[caller_uid].call_sites.append(call)

        # If we resolved the callee, add the edge
        if callee_signature:
            callee_uid = callee_signature.unique_id
            if callee_uid not in self.nodes:
                self.add_method(callee_signature)

            self.nodes[caller_uid].callees.add(callee_uid)
            self.nodes[callee_uid].callers.add(caller_uid)

    def get_method(self, unique_id: str) -> Optional[CallGraphNode]:
        """Get a method node by unique ID"""
        return self.nodes.get(unique_id)

    def find_methods_by_name(self, method_name: str) -> List[CallGraphNode]:
        """Find all methods with the given name"""
        uids = self.method_index.get(method_name, [])
        return [self.nodes[uid] for uid in uids if uid in self.nodes]

    def find_methods_in_class(self, class_name: str) -> List[CallGraphNode]:
        """Find all methods in a class"""
        uids = self.class_index.get(class_name, [])
        return [self.nodes[uid] for uid in uids if uid in self.nodes]

    def find_methods_in_file(self, file_path: str) -> List[CallGraphNode]:
        """Find all methods in a file"""
        uids = self.file_index.get(file_path, [])
        return [self.nodes[uid] for uid in uids if uid in self.nodes]

    def get_callers(self, unique_id: str) -> List[CallGraphNode]:
        """Get all methods that call this method"""
        node = self.nodes.get(unique_id)
        if not node:
            return []
        return [self.nodes[uid] for uid in node.callers if uid in self.nodes]

    def get_callees(self, unique_id: str) -> List[CallGraphNode]:
        """Get all methods called by this method"""
        node = self.nodes.get(unique_id)
        if not node:
            return []
        return [self.nodes[uid] for uid in node.callees if uid in self.nodes]

    def get_call_chain(self, start_uid: str, max_depth: int = 10) -> List[List[str]]:
        """Get all call chains starting from a method (BFS)"""
        chains = []
        visited = set()
        queue = [([start_uid], 0)]

        while queue:
            path, depth = queue.pop(0)
            current = path[-1]

            if depth >= max_depth:
                chains.append(path)
                continue

            node = self.nodes.get(current)
            if not node or not node.callees:
                chains.append(path)
                continue

            for callee_uid in node.callees:
                if callee_uid not in visited:
                    visited.add(callee_uid)
                    queue.append((path + [callee_uid], depth + 1))

        return chains

    def get_reverse_call_chain(self, end_uid: str, max_depth: int = 10) -> List[List[str]]:
        """Get all call chains ending at a method (reverse BFS)"""
        chains = []
        visited = set()
        queue = [([end_uid], 0)]

        while queue:
            path, depth = queue.pop(0)
            current = path[0]

            if depth >= max_depth:
                chains.append(path)
                continue

            node = self.nodes.get(current)
            if not node or not node.callers:
                chains.append(path)
                continue

            for caller_uid in node.callers:
                if caller_uid not in visited:
                    visited.add(caller_uid)
                    queue.append(([caller_uid] + path, depth + 1))

        return chains

    def stats(self) -> Dict[str, int]:
        """Get call graph statistics"""
        total_edges = sum(len(n.callees) for n in self.nodes.values())
        return {
            'total_methods': len(self.nodes),
            'total_edges': total_edges,
            'total_classes': len(self.class_index),
            'total_files': len(self.file_index),
        }


class CallGraphBuilder:
    """Builds a call graph from source code"""

    def __init__(self):
        self.call_graph = CallGraph()
        self.java_analyzer = JavaASTAnalyzer() if TREE_SITTER_AVAILABLE else None
        self.python_analyzer = PythonASTAnalyzer() if TREE_SITTER_AVAILABLE else None
        self.js_analyzer = JavaScriptASTAnalyzer() if TREE_SITTER_AVAILABLE else None

    def build_from_files(self, files: List[Path], content_cache: Dict[str, str] = None) -> CallGraph:
        """Build call graph from a list of files"""
        content_cache = content_cache or {}

        # First pass: collect all method definitions
        for file_path in files:
            content = content_cache.get(str(file_path))
            if not content:
                try:
                    content = file_path.read_text(encoding='utf-8', errors='ignore')
                    content_cache[str(file_path)] = content
                except Exception as e:
                    logger.debug(f"Failed to read {file_path}: {e}")
                    continue

            self._extract_methods(file_path, content)

        # Second pass: extract method calls and build edges
        for file_path in files:
            content = content_cache.get(str(file_path))
            if content:
                self._extract_calls(file_path, content)

        # Third pass: resolve call targets
        self._resolve_calls()

        return self.call_graph

    def _get_analyzer(self, file_path: Path):
        """Get appropriate analyzer for file type"""
        suffix = file_path.suffix.lower()
        if suffix == '.java':
            return self.java_analyzer
        elif suffix == '.py':
            return self.python_analyzer
        elif suffix in ['.js', '.ts', '.jsx', '.tsx']:
            return self.js_analyzer
        return None

    def _extract_methods(self, file_path: Path, content: str):
        """Extract method definitions from a file"""
        analyzer = self._get_analyzer(file_path)
        if not analyzer:
            return

        file_str = str(file_path)

        if isinstance(analyzer, JavaASTAnalyzer):
            classes = analyzer.get_classes(content)
            for cls in classes:
                for method in cls.methods:
                    sig = MethodSignature(
                        class_name=cls.name,
                        method_name=method.name,
                        file_path=file_str,
                        line_number=method.start_line,
                        parameters=method.parameters,
                        return_type=method.return_type,
                        annotations=method.annotations,
                    )
                    self.call_graph.add_method(sig)

        elif isinstance(analyzer, PythonASTAnalyzer):
            functions = analyzer.get_function_definitions(content)
            for func in functions:
                sig = MethodSignature(
                    class_name=None,  # TODO: Extract class context
                    method_name=func['name'],
                    file_path=file_str,
                    line_number=func['line'],
                    parameters=func.get('parameters', []),
                    annotations=func.get('decorators', []),
                )
                self.call_graph.add_method(sig)

    def _extract_calls(self, file_path: Path, content: str):
        """Extract method calls from a file"""
        analyzer = self._get_analyzer(file_path)
        if not analyzer:
            return

        file_str = str(file_path)

        # Get all methods in this file to determine caller context
        file_methods = self.call_graph.find_methods_in_file(file_str)

        # Get all calls in the file
        calls = analyzer.get_method_calls(content)

        for call_info in calls:
            line = call_info.get('line', 0)

            # Find which method contains this call
            caller = self._find_containing_method(file_methods, line)
            if not caller:
                continue

            method_call = MethodCall(
                caller=caller.signature,
                callee_name=call_info.get('method_name') or call_info.get('function', ''),
                callee_object=call_info.get('object'),
                arguments=call_info.get('arguments', []),
                line_number=line,
                file_path=file_str,
            )

            self.call_graph.add_call(method_call)

    def _find_containing_method(self, methods: List[CallGraphNode], line: int) -> Optional[CallGraphNode]:
        """Find the method that contains a given line number"""
        # Find method whose range contains the line
        # For now, find the method with start_line closest to but before the target line
        best = None
        best_dist = float('inf')

        for method in methods:
            start = method.signature.line_number
            if start <= line:
                dist = line - start
                if dist < best_dist:
                    best_dist = dist
                    best = method

        return best

    def _resolve_calls(self):
        """Resolve call targets to actual method signatures"""
        for node in self.call_graph.nodes.values():
            for call in node.call_sites:
                # Try to resolve the callee
                callee = self._resolve_callee(call)
                if callee:
                    # Add the edge
                    callee_uid = callee.unique_id
                    if callee_uid in self.call_graph.nodes:
                        node.callees.add(callee_uid)
                        self.call_graph.nodes[callee_uid].callers.add(node.signature.unique_id)

    def _resolve_callee(self, call: MethodCall) -> Optional[MethodSignature]:
        """Try to resolve a method call to its target"""
        callee_name = call.callee_name
        if not callee_name:
            return None

        # Find methods with matching name
        candidates = self.call_graph.find_methods_by_name(callee_name)

        if not candidates:
            return None

        if len(candidates) == 1:
            return candidates[0].signature

        # Multiple candidates - try to disambiguate
        # Prefer methods in the same file
        same_file = [c for c in candidates if c.signature.file_path == call.file_path]
        if len(same_file) == 1:
            return same_file[0].signature

        # If callee_object hints at a class, filter by class
        if call.callee_object:
            # Extract potential class name from object
            # e.g., "userService" might map to "UserService"
            potential_class = self._guess_class_from_object(call.callee_object)
            if potential_class:
                class_methods = [c for c in candidates
                                if c.signature.class_name and
                                potential_class.lower() in c.signature.class_name.lower()]
                if len(class_methods) == 1:
                    return class_methods[0].signature

        # Return first candidate as fallback
        return candidates[0].signature

    def _guess_class_from_object(self, obj_name: str) -> Optional[str]:
        """Guess class name from object/variable name"""
        if not obj_name:
            return None

        # Common patterns: userService -> UserService, user_service -> UserService
        # Remove common prefixes/suffixes
        name = obj_name
        for prefix in ['this.', 'self.', '_']:
            if name.startswith(prefix):
                name = name[len(prefix):]

        # Convert to PascalCase
        if '_' in name:
            # snake_case to PascalCase
            return ''.join(word.capitalize() for word in name.split('_'))
        else:
            # camelCase to PascalCase
            return name[0].upper() + name[1:] if name else None


def build_call_graph(files: List[Path], content_cache: Dict[str, str] = None) -> CallGraph:
    """Convenience function to build a call graph"""
    builder = CallGraphBuilder()
    return builder.build_from_files(files, content_cache)
