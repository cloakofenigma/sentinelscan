"""
Taint Lattice - Formal data structures for taint analysis

Provides a proper lattice structure for taint values with join/meet operations
for fixed-point computation in dataflow analysis.
"""

from __future__ import annotations

from enum import IntEnum
from dataclasses import dataclass, field
from typing import Dict, FrozenSet, Set, Optional, Tuple, Any
import sys

# Import from parent package
sys.path.insert(0, str(__file__).rsplit('/', 2)[0])
from ..dataflow_analyzer import TaintSource, SinkType


class TaintLevel(IntEnum):
    """Taint levels in the lattice (ordered for comparison)"""
    BOTTOM = 0       # No information (unreachable code)
    UNTAINTED = 1    # Definitely clean
    MAYBE_TAINTED = 2  # May be tainted (partial sanitization or uncertain)
    TAINTED = 3      # Definitely tainted
    TOP = 4          # Unknown/conflict (conservative assumption)


@dataclass(frozen=True)
class TaintLabel:
    """
    A single taint label tracking one source.
    Immutable for use in sets.
    """
    source_type: TaintSource
    source_location: str  # file:line
    source_annotation: Optional[str]  # e.g., "@RequestParam"
    original_variable: str  # Original variable name at source

    def __hash__(self):
        return hash((self.source_type, self.source_location,
                    self.source_annotation, self.original_variable))

    def __str__(self):
        return f"{self.source_type.value}@{self.source_location}"


@dataclass(frozen=True)
class TaintValue:
    """
    Taint value for a single variable/expression.
    Tracks taint level, source labels, propagation path, and sanitization status.
    Immutable for safe use in fixed-point iteration.
    """
    level: TaintLevel
    labels: FrozenSet[TaintLabel]  # Track multiple potential sources
    propagation_path: Tuple[str, ...]  # Immutable path for hashing
    sanitized_for: FrozenSet[SinkType] = frozenset()  # Sanitized against these sinks

    @classmethod
    def bottom(cls) -> 'TaintValue':
        """Create bottom element (unreachable)"""
        return cls(TaintLevel.BOTTOM, frozenset(), ())

    @classmethod
    def untainted(cls) -> 'TaintValue':
        """Create untainted value"""
        return cls(TaintLevel.UNTAINTED, frozenset(), ())

    @classmethod
    def tainted(cls, label: TaintLabel, path: Tuple[str, ...] = ()) -> 'TaintValue':
        """Create tainted value from a source"""
        return cls(TaintLevel.TAINTED, frozenset([label]), path)

    @classmethod
    def tainted_from_labels(cls, labels: FrozenSet[TaintLabel],
                           path: Tuple[str, ...] = ()) -> 'TaintValue':
        """Create tainted value from multiple labels"""
        if not labels:
            return cls.untainted()
        return cls(TaintLevel.TAINTED, labels, path)

    @classmethod
    def top(cls) -> 'TaintValue':
        """Create top element (unknown/conservative)"""
        return cls(TaintLevel.TOP, frozenset(), ())

    @property
    def is_tainted(self) -> bool:
        """Check if this value is tainted (MAYBE or definitely)"""
        return self.level >= TaintLevel.MAYBE_TAINTED

    @property
    def is_definitely_tainted(self) -> bool:
        """Check if this value is definitely tainted"""
        return self.level == TaintLevel.TAINTED

    @property
    def is_untainted(self) -> bool:
        """Check if this value is definitely untainted"""
        return self.level == TaintLevel.UNTAINTED

    def is_tainted_for(self, sink_type: SinkType) -> bool:
        """Check if tainted for a specific sink type (not sanitized)"""
        return self.level >= TaintLevel.MAYBE_TAINTED and sink_type not in self.sanitized_for

    def with_sanitization(self, sink_types: Set[SinkType]) -> 'TaintValue':
        """Return new TaintValue with sanitization applied"""
        new_sanitized = self.sanitized_for | frozenset(sink_types)

        # If sanitized for ALL sink types, downgrade to MAYBE_TAINTED
        # (still tracking the taint but it's neutralized)
        all_sinks = set(SinkType)
        if new_sanitized >= all_sinks:
            new_level = TaintLevel.MAYBE_TAINTED
        else:
            new_level = self.level

        return TaintValue(new_level, self.labels, self.propagation_path, new_sanitized)

    def with_propagation(self, step: str) -> 'TaintValue':
        """Return new TaintValue with propagation step added"""
        new_path = self.propagation_path + (step,)
        return TaintValue(self.level, self.labels, new_path, self.sanitized_for)

    def __str__(self):
        if self.level == TaintLevel.UNTAINTED:
            return "CLEAN"
        elif self.level == TaintLevel.BOTTOM:
            return "BOTTOM"
        elif self.level == TaintLevel.TOP:
            return "TOP"
        else:
            sources = ", ".join(str(l) for l in self.labels)
            sanitized = ", ".join(s.value for s in self.sanitized_for)
            if sanitized:
                return f"TAINTED({sources})[sanitized:{sanitized}]"
            return f"TAINTED({sources})"


class TaintLattice:
    r"""
    Lattice operations for taint analysis.

    Lattice structure:
           TOP
          / | \
    TAINTED (with various label combinations)
          \ | /
      MAYBE_TAINTED
            |
        UNTAINTED
            |
         BOTTOM
    """

    @staticmethod
    def join(a: TaintValue, b: TaintValue) -> TaintValue:
        """
        Least upper bound - combine taint from two branches.
        Used at control flow merge points.

        Properties:
        - If either is tainted, result is tainted
        - Labels are unioned
        - Sanitizations are intersected (conservative)
        """
        # Handle bottom (unreachable)
        if a.level == TaintLevel.BOTTOM:
            return b
        if b.level == TaintLevel.BOTTOM:
            return a

        # Take maximum taint level
        level = TaintLevel(max(a.level.value, b.level.value))

        # Union of labels (track all possible sources)
        labels = a.labels | b.labels

        # Intersection of sanitizations (conservative - only count as sanitized
        # if sanitized on ALL paths)
        sanitized = a.sanitized_for & b.sanitized_for

        # Keep longer propagation path for debugging
        path = a.propagation_path if len(a.propagation_path) >= len(b.propagation_path) else b.propagation_path

        return TaintValue(level, labels, path, sanitized)

    @staticmethod
    def meet(a: TaintValue, b: TaintValue) -> TaintValue:
        """
        Greatest lower bound - intersection.
        Used for narrowing (e.g., after sanitization checks).

        Properties:
        - If both are tainted, result is tainted
        - Labels are intersected
        - Sanitizations are unioned
        """
        # Handle top
        if a.level == TaintLevel.TOP:
            return b
        if b.level == TaintLevel.TOP:
            return a

        # Take minimum taint level
        level = TaintLevel(min(a.level.value, b.level.value))

        # Intersection of labels
        labels = a.labels & b.labels

        # Union of sanitizations
        sanitized = a.sanitized_for | b.sanitized_for

        # Keep shorter path
        path = a.propagation_path if len(a.propagation_path) <= len(b.propagation_path) else b.propagation_path

        return TaintValue(level, labels, path, sanitized)

    @staticmethod
    def is_less_than_or_equal(a: TaintValue, b: TaintValue) -> bool:
        """Check if a <= b in the lattice (a is more precise)"""
        return a.level <= b.level and a.labels <= b.labels


@dataclass
class TaintAbstractState:
    """
    Abstract state mapping SSA variables to taint values.
    Represents the taint information at a program point.
    """
    # Maps SSA variable name (e.g., "x_1") to its taint value
    variable_taints: Dict[str, TaintValue] = field(default_factory=dict)

    # Maps (object_ssa_name, field_name) to field taint
    # Tracks taint at object.field granularity
    field_taints: Dict[Tuple[str, str], TaintValue] = field(default_factory=dict)

    # Maps collection variable name to element taint
    # Conservative: all elements share same taint
    collection_taints: Dict[str, TaintValue] = field(default_factory=dict)

    # Return value taint (for method analysis)
    return_taint: Optional[TaintValue] = None

    def get(self, var_name: str) -> TaintValue:
        """Get taint for a variable, defaulting to untainted"""
        return self.variable_taints.get(var_name, TaintValue.untainted())

    def get_field(self, obj_name: str, field_name: str) -> TaintValue:
        """Get taint for an object field"""
        return self.field_taints.get((obj_name, field_name), TaintValue.untainted())

    def get_collection(self, collection_name: str) -> TaintValue:
        """Get taint for collection elements"""
        return self.collection_taints.get(collection_name, TaintValue.untainted())

    def set(self, var_name: str, value: TaintValue) -> 'TaintAbstractState':
        """Return new state with updated variable taint (immutable)"""
        new_var_taints = dict(self.variable_taints)
        new_var_taints[var_name] = value
        return TaintAbstractState(
            new_var_taints,
            dict(self.field_taints),
            dict(self.collection_taints),
            self.return_taint
        )

    def set_field(self, obj_name: str, field_name: str,
                  value: TaintValue) -> 'TaintAbstractState':
        """Return new state with updated field taint"""
        new_field_taints = dict(self.field_taints)
        new_field_taints[(obj_name, field_name)] = value
        return TaintAbstractState(
            dict(self.variable_taints),
            new_field_taints,
            dict(self.collection_taints),
            self.return_taint
        )

    def set_collection(self, collection_name: str,
                       value: TaintValue) -> 'TaintAbstractState':
        """Return new state with updated collection taint"""
        new_collection_taints = dict(self.collection_taints)
        # Join with existing to be conservative
        existing = new_collection_taints.get(collection_name, TaintValue.untainted())
        new_collection_taints[collection_name] = TaintLattice.join(existing, value)
        return TaintAbstractState(
            dict(self.variable_taints),
            dict(self.field_taints),
            new_collection_taints,
            self.return_taint
        )

    def set_return(self, value: TaintValue) -> 'TaintAbstractState':
        """Return new state with updated return taint"""
        return TaintAbstractState(
            dict(self.variable_taints),
            dict(self.field_taints),
            dict(self.collection_taints),
            value
        )

    def join(self, other: 'TaintAbstractState') -> 'TaintAbstractState':
        """Join two abstract states (for control flow merge)"""
        # Join variable taints
        all_vars = set(self.variable_taints.keys()) | set(other.variable_taints.keys())
        merged_vars = {}
        for var in all_vars:
            a = self.variable_taints.get(var, TaintValue.bottom())
            b = other.variable_taints.get(var, TaintValue.bottom())
            merged_vars[var] = TaintLattice.join(a, b)

        # Join field taints
        all_fields = set(self.field_taints.keys()) | set(other.field_taints.keys())
        merged_fields = {}
        for field_key in all_fields:
            a = self.field_taints.get(field_key, TaintValue.bottom())
            b = other.field_taints.get(field_key, TaintValue.bottom())
            merged_fields[field_key] = TaintLattice.join(a, b)

        # Join collection taints
        all_colls = set(self.collection_taints.keys()) | set(other.collection_taints.keys())
        merged_colls = {}
        for coll in all_colls:
            a = self.collection_taints.get(coll, TaintValue.bottom())
            b = other.collection_taints.get(coll, TaintValue.bottom())
            merged_colls[coll] = TaintLattice.join(a, b)

        # Join return taints
        merged_return = None
        if self.return_taint or other.return_taint:
            a = self.return_taint or TaintValue.bottom()
            b = other.return_taint or TaintValue.bottom()
            merged_return = TaintLattice.join(a, b)

        return TaintAbstractState(merged_vars, merged_fields, merged_colls, merged_return)

    def __eq__(self, other: object) -> bool:
        """Check state equality for fixed-point detection"""
        if not isinstance(other, TaintAbstractState):
            return False
        return (self.variable_taints == other.variable_taints and
                self.field_taints == other.field_taints and
                self.collection_taints == other.collection_taints and
                self.return_taint == other.return_taint)

    def __hash__(self):
        """Hash for caching"""
        return hash((
            frozenset(self.variable_taints.items()),
            frozenset(self.field_taints.items()),
            frozenset(self.collection_taints.items()),
            self.return_taint
        ))

    def copy(self) -> 'TaintAbstractState':
        """Create a copy of this state"""
        return TaintAbstractState(
            dict(self.variable_taints),
            dict(self.field_taints),
            dict(self.collection_taints),
            self.return_taint
        )

    def get_all_tainted_vars(self) -> Dict[str, TaintValue]:
        """Get all variables that are tainted"""
        return {k: v for k, v in self.variable_taints.items() if v.is_tainted}

    def __str__(self):
        tainted = self.get_all_tainted_vars()
        if not tainted:
            return "State(clean)"
        entries = [f"{k}={v}" for k, v in tainted.items()]
        return f"State({', '.join(entries)})"
