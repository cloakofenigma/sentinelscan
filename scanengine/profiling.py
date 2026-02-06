"""
Performance profiling utilities for SentinelScan.

Provides timing decorators, memory tracking, and performance metrics
for identifying bottlenecks and optimizing scan performance.

Usage:
    from scanengine.profiling import profile, timed, PerformanceMetrics

    @timed
    def slow_function():
        ...

    with profile("my_operation"):
        ...

    metrics = PerformanceMetrics()
    metrics.start("analysis")
    ...
    metrics.stop("analysis")
    print(metrics.summary())
"""

from __future__ import annotations

import time
import functools
import logging
import threading
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Callable, Any, TypeVar, cast
from collections import defaultdict

logger = logging.getLogger(__name__)

# Type variable for generic decorator
F = TypeVar('F', bound=Callable[..., Any])


@dataclass
class TimingResult:
    """Result of a single timing measurement."""
    name: str
    duration_seconds: float
    start_time: float
    end_time: float
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def duration_ms(self) -> float:
        """Duration in milliseconds."""
        return self.duration_seconds * 1000

    def __str__(self) -> str:
        return f"{self.name}: {self.duration_ms:.2f}ms"


@dataclass
class AggregatedMetric:
    """Aggregated statistics for a named metric."""
    name: str
    count: int = 0
    total_seconds: float = 0.0
    min_seconds: float = float('inf')
    max_seconds: float = 0.0

    @property
    def avg_seconds(self) -> float:
        """Average duration in seconds."""
        return self.total_seconds / self.count if self.count > 0 else 0.0

    @property
    def avg_ms(self) -> float:
        """Average duration in milliseconds."""
        return self.avg_seconds * 1000

    @property
    def total_ms(self) -> float:
        """Total duration in milliseconds."""
        return self.total_seconds * 1000

    def add(self, duration: float) -> None:
        """Add a timing measurement."""
        self.count += 1
        self.total_seconds += duration
        self.min_seconds = min(self.min_seconds, duration)
        self.max_seconds = max(self.max_seconds, duration)

    def __str__(self) -> str:
        if self.count == 0:
            return f"{self.name}: no measurements"
        return (
            f"{self.name}: {self.count} calls, "
            f"total={self.total_ms:.2f}ms, "
            f"avg={self.avg_ms:.2f}ms, "
            f"min={self.min_seconds*1000:.2f}ms, "
            f"max={self.max_seconds*1000:.2f}ms"
        )


class PerformanceMetrics:
    """
    Collect and aggregate performance metrics.

    Thread-safe metrics collection for profiling scan operations.

    Example:
        metrics = PerformanceMetrics()

        # Manual timing
        metrics.start("file_scan")
        scan_file(path)
        metrics.stop("file_scan")

        # Context manager
        with metrics.measure("pattern_match"):
            match_patterns(content)

        # Get results
        print(metrics.summary())
    """

    def __init__(self) -> None:
        self._metrics: Dict[str, AggregatedMetric] = defaultdict(
            lambda: AggregatedMetric(name="")
        )
        self._active: Dict[str, float] = {}
        self._lock = threading.Lock()
        self._enabled = True

    def enable(self) -> None:
        """Enable metrics collection."""
        self._enabled = True

    def disable(self) -> None:
        """Disable metrics collection (for production)."""
        self._enabled = False

    def start(self, name: str) -> None:
        """Start timing a named operation."""
        if not self._enabled:
            return
        with self._lock:
            self._active[name] = time.perf_counter()

    def stop(self, name: str) -> Optional[float]:
        """Stop timing and record the measurement."""
        if not self._enabled:
            return None
        with self._lock:
            if name not in self._active:
                logger.warning(f"No active timer for '{name}'")
                return None
            start_time = self._active.pop(name)
            duration = time.perf_counter() - start_time
            if name not in self._metrics:
                self._metrics[name] = AggregatedMetric(name=name)
            self._metrics[name].add(duration)
            return duration

    def record(self, name: str, duration: float) -> None:
        """Record a pre-measured duration."""
        if not self._enabled:
            return
        with self._lock:
            if name not in self._metrics:
                self._metrics[name] = AggregatedMetric(name=name)
            self._metrics[name].add(duration)

    @contextmanager
    def measure(self, name: str):
        """Context manager for timing a block of code."""
        if not self._enabled:
            yield
            return
        start = time.perf_counter()
        try:
            yield
        finally:
            duration = time.perf_counter() - start
            self.record(name, duration)

    def get(self, name: str) -> Optional[AggregatedMetric]:
        """Get metrics for a specific operation."""
        return self._metrics.get(name)

    def reset(self) -> None:
        """Reset all metrics."""
        with self._lock:
            self._metrics.clear()
            self._active.clear()

    def summary(self) -> str:
        """Generate a summary of all metrics."""
        if not self._metrics:
            return "No metrics collected"

        lines = ["Performance Metrics:", "-" * 60]
        sorted_metrics = sorted(
            self._metrics.values(),
            key=lambda m: m.total_seconds,
            reverse=True
        )
        for metric in sorted_metrics:
            lines.append(str(metric))

        total_time = sum(m.total_seconds for m in self._metrics.values())
        lines.append("-" * 60)
        lines.append(f"Total tracked time: {total_time*1000:.2f}ms")
        return "\n".join(lines)

    def to_dict(self) -> Dict[str, Dict[str, Any]]:
        """Export metrics as dictionary."""
        return {
            name: {
                "count": m.count,
                "total_ms": m.total_ms,
                "avg_ms": m.avg_ms,
                "min_ms": m.min_seconds * 1000 if m.count > 0 else 0,
                "max_ms": m.max_seconds * 1000 if m.count > 0 else 0,
            }
            for name, m in self._metrics.items()
        }


# Global metrics instance
_global_metrics = PerformanceMetrics()


def get_global_metrics() -> PerformanceMetrics:
    """Get the global metrics instance."""
    return _global_metrics


def reset_global_metrics() -> None:
    """Reset global metrics."""
    _global_metrics.reset()


@contextmanager
def profile(name: str, metrics: Optional[PerformanceMetrics] = None):
    """
    Context manager for profiling a code block.

    Args:
        name: Name for this measurement
        metrics: PerformanceMetrics instance (uses global if None)

    Example:
        with profile("expensive_operation"):
            do_expensive_work()
    """
    m = metrics or _global_metrics
    with m.measure(name):
        yield


def timed(func: F) -> F:
    """
    Decorator to time function execution.

    Records timing to global metrics using the function name.

    Example:
        @timed
        def slow_function():
            time.sleep(1)
    """
    @functools.wraps(func)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        name = f"{func.__module__}.{func.__qualname__}"
        with profile(name):
            return func(*args, **kwargs)
    return cast(F, wrapper)


def timed_method(func: F) -> F:
    """
    Decorator for timing instance methods.

    Includes class name in the metric name.
    """
    @functools.wraps(func)
    def wrapper(self: Any, *args: Any, **kwargs: Any) -> Any:
        name = f"{self.__class__.__name__}.{func.__name__}"
        with profile(name):
            return func(self, *args, **kwargs)
    return cast(F, wrapper)


class ScanProfiler:
    """
    High-level profiler for scan operations.

    Tracks file processing, rule matching, and analysis phases.

    Example:
        profiler = ScanProfiler()
        profiler.start_scan(target_path)

        for file in files:
            with profiler.file_context(file):
                analyze(file)

        print(profiler.report())
    """

    def __init__(self) -> None:
        self.metrics = PerformanceMetrics()
        self._scan_start: Optional[float] = None
        self._files_processed: int = 0
        self._rules_matched: int = 0
        self._findings_count: int = 0

    def start_scan(self, target: str) -> None:
        """Mark the start of a scan."""
        self._scan_start = time.perf_counter()
        self._files_processed = 0
        self._rules_matched = 0
        self._findings_count = 0
        self.metrics.reset()
        logger.debug(f"Scan started: {target}")

    def end_scan(self) -> float:
        """Mark the end of a scan, return total duration."""
        if self._scan_start is None:
            return 0.0
        duration = time.perf_counter() - self._scan_start
        self._scan_start = None
        return duration

    @contextmanager
    def file_context(self, file_path: str):
        """Context manager for timing file processing."""
        with self.metrics.measure("file_processing"):
            yield
        self._files_processed += 1

    @contextmanager
    def phase_context(self, phase_name: str):
        """Context manager for timing scan phases."""
        with self.metrics.measure(f"phase_{phase_name}"):
            yield

    def record_finding(self) -> None:
        """Record that a finding was generated."""
        self._findings_count += 1

    def record_rule_match(self) -> None:
        """Record that a rule was matched."""
        self._rules_matched += 1

    def report(self) -> str:
        """Generate a profiling report."""
        lines = [
            "=" * 60,
            "SCAN PROFILING REPORT",
            "=" * 60,
            f"Files processed: {self._files_processed}",
            f"Rules matched: {self._rules_matched}",
            f"Findings generated: {self._findings_count}",
            "",
            self.metrics.summary(),
        ]

        # Calculate rates
        file_metric = self.metrics.get("file_processing")
        if file_metric and file_metric.count > 0:
            rate = file_metric.count / file_metric.total_seconds if file_metric.total_seconds > 0 else 0
            lines.append(f"\nProcessing rate: {rate:.1f} files/second")

        return "\n".join(lines)


# Memory profiling (optional, requires tracemalloc)
class MemoryProfiler:
    """
    Memory usage profiler using tracemalloc.

    Example:
        mem = MemoryProfiler()
        mem.start()
        # ... do work ...
        snapshot = mem.snapshot()
        print(mem.top_allocations(10))
    """

    def __init__(self) -> None:
        self._started = False
        self._snapshots: List[Any] = []

    def start(self) -> bool:
        """Start memory tracking."""
        try:
            import tracemalloc
            tracemalloc.start()
            self._started = True
            return True
        except Exception as e:
            logger.warning(f"Could not start memory profiling: {e}")
            return False

    def stop(self) -> None:
        """Stop memory tracking."""
        if self._started:
            try:
                import tracemalloc
                tracemalloc.stop()
            except Exception:
                pass
            self._started = False

    def snapshot(self) -> Optional[Any]:
        """Take a memory snapshot."""
        if not self._started:
            return None
        try:
            import tracemalloc
            snap = tracemalloc.take_snapshot()
            self._snapshots.append(snap)
            return snap
        except Exception:
            return None

    def current_memory(self) -> Optional[tuple]:
        """Get current memory usage (current, peak) in bytes."""
        if not self._started:
            return None
        try:
            import tracemalloc
            return tracemalloc.get_traced_memory()
        except Exception:
            return None

    def top_allocations(self, limit: int = 10) -> str:
        """Get top memory allocations."""
        if not self._snapshots:
            return "No snapshots available"

        try:
            snapshot = self._snapshots[-1]
            stats = snapshot.statistics('lineno')

            lines = [f"Top {limit} memory allocations:"]
            for stat in stats[:limit]:
                lines.append(f"  {stat}")
            return "\n".join(lines)
        except Exception as e:
            return f"Error getting allocations: {e}"
