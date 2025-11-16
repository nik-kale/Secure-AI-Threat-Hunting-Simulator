"""
Performance profiling utilities.

Provides detailed timing and memory profiling for analysis components.
"""
from functools import wraps
from typing import Callable, Any, Dict, Optional, List
from dataclasses import dataclass, field
from datetime import datetime
import time
import logging
import tracemalloc
import json
from pathlib import Path

logger = logging.getLogger(__name__)


@dataclass
class TimingEntry:
    """Single timing measurement."""
    name: str
    start_time: float
    end_time: Optional[float] = None
    duration: Optional[float] = None
    parent: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def finish(self):
        """Mark the timing entry as finished."""
        if self.end_time is None:
            self.end_time = time.time()
            self.duration = self.end_time - self.start_time

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "name": self.name,
            "duration_seconds": self.duration,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "parent": self.parent,
            "metadata": self.metadata
        }


@dataclass
class MemorySnapshot:
    """Memory usage snapshot."""
    timestamp: float
    current_bytes: int
    peak_bytes: int
    label: str
    traceback: Optional[List[str]] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "timestamp": self.timestamp,
            "current_mb": self.current_bytes / 1024 / 1024,
            "peak_mb": self.peak_bytes / 1024 / 1024,
            "label": self.label,
            "traceback": self.traceback
        }


@dataclass
class ProfileReport:
    """Complete profiling report."""
    name: str
    start_time: datetime
    end_time: Optional[datetime] = None
    total_duration: Optional[float] = None
    timings: List[TimingEntry] = field(default_factory=list)
    memory_snapshots: List[MemorySnapshot] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def finish(self):
        """Mark the report as finished."""
        if self.end_time is None:
            self.end_time = datetime.now()
            if self.start_time:
                self.total_duration = (self.end_time - self.start_time).total_seconds()

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "name": self.name,
            "start_time": self.start_time.isoformat() if self.start_time else None,
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "total_duration_seconds": self.total_duration,
            "timings": [t.to_dict() for t in self.timings if t.duration is not None],
            "memory_snapshots": [m.to_dict() for m in self.memory_snapshots],
            "metadata": self.metadata,
            "summary": self._generate_summary()
        }

    def _generate_summary(self) -> Dict[str, Any]:
        """Generate summary statistics."""
        completed_timings = [t for t in self.timings if t.duration is not None]

        if not completed_timings:
            return {}

        durations = [t.duration for t in completed_timings]

        summary = {
            "total_operations": len(completed_timings),
            "total_time_seconds": sum(durations),
            "average_time_seconds": sum(durations) / len(durations),
            "min_time_seconds": min(durations),
            "max_time_seconds": max(durations),
        }

        # Slowest operations
        slowest = sorted(completed_timings, key=lambda t: t.duration, reverse=True)[:5]
        summary["slowest_operations"] = [
            {"name": t.name, "duration_seconds": t.duration}
            for t in slowest
        ]

        # Memory summary
        if self.memory_snapshots:
            summary["memory"] = {
                "peak_mb": max(m.peak_bytes for m in self.memory_snapshots) / 1024 / 1024,
                "final_mb": self.memory_snapshots[-1].current_bytes / 1024 / 1024 if self.memory_snapshots else 0,
                "snapshots": len(self.memory_snapshots)
            }

        return summary


class Profiler:
    """
    Performance profiler for tracking timing and memory usage.

    Can be used as a context manager or decorator.
    """

    def __init__(self, name: str, track_memory: bool = True):
        """
        Initialize profiler.

        Args:
            name: Name of the profiling session
            track_memory: Whether to track memory usage
        """
        self.name = name
        self.track_memory = track_memory
        self.report = ProfileReport(name=name, start_time=datetime.now())
        self._timing_stack: List[str] = []
        self._memory_started = False

    def __enter__(self):
        """Enter context manager."""
        self.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Exit context manager."""
        self.stop()
        return False

    def start(self):
        """Start profiling."""
        self.report.start_time = datetime.now()

        if self.track_memory:
            try:
                tracemalloc.start()
                self._memory_started = True
                self.snapshot_memory("profiling_start")
            except Exception as e:
                logger.warning(f"Could not start memory tracking: {e}")
                self.track_memory = False

    def stop(self):
        """Stop profiling and generate report."""
        # Finish any open timings
        for timing in self.report.timings:
            if timing.end_time is None:
                timing.finish()

        if self.track_memory and self._memory_started:
            try:
                self.snapshot_memory("profiling_end")
                tracemalloc.stop()
            except Exception as e:
                logger.warning(f"Error stopping memory tracking: {e}")

        self.report.finish()

    def time(self, name: str, **metadata) -> 'TimingContext':
        """
        Create a timing context.

        Args:
            name: Name of the operation being timed
            **metadata: Additional metadata to attach

        Returns:
            TimingContext that can be used as a context manager

        Example:
            with profiler.time("load_data"):
                data = load_large_dataset()
        """
        return TimingContext(self, name, metadata)

    def record_timing(self, name: str, duration: float, **metadata):
        """
        Manually record a timing.

        Args:
            name: Name of the operation
            duration: Duration in seconds
            **metadata: Additional metadata
        """
        entry = TimingEntry(
            name=name,
            start_time=time.time() - duration,
            end_time=time.time(),
            duration=duration,
            parent=self._timing_stack[-1] if self._timing_stack else None,
            metadata=metadata
        )
        self.report.timings.append(entry)

    def snapshot_memory(self, label: str):
        """
        Take a memory snapshot.

        Args:
            label: Label for this snapshot
        """
        if not self.track_memory or not self._memory_started:
            return

        try:
            current, peak = tracemalloc.get_traced_memory()

            # Get top memory allocations
            snapshot = tracemalloc.take_snapshot()
            top_stats = snapshot.statistics('lineno')[:3]

            traceback_lines = None
            if top_stats:
                traceback_lines = [str(stat) for stat in top_stats]

            memory_snapshot = MemorySnapshot(
                timestamp=time.time(),
                current_bytes=current,
                peak_bytes=peak,
                label=label,
                traceback=traceback_lines
            )
            self.report.memory_snapshots.append(memory_snapshot)

        except Exception as e:
            logger.warning(f"Error taking memory snapshot: {e}")

    def add_metadata(self, key: str, value: Any):
        """
        Add metadata to the report.

        Args:
            key: Metadata key
            value: Metadata value
        """
        self.report.metadata[key] = value

    def get_report(self) -> ProfileReport:
        """
        Get the current profiling report.

        Returns:
            ProfileReport instance
        """
        return self.report

    def save_report(self, output_path: Path):
        """
        Save the profiling report to a file.

        Args:
            output_path: Path to save the report
        """
        output_path.parent.mkdir(parents=True, exist_ok=True)

        with open(output_path, 'w') as f:
            json.dump(self.report.to_dict(), f, indent=2)

        logger.info(f"Profiling report saved to {output_path}")

    def print_summary(self):
        """Print a summary of the profiling results."""
        report_dict = self.report.to_dict()
        summary = report_dict.get("summary", {})

        print(f"\n{'='*60}")
        print(f"Profiling Report: {self.name}")
        print(f"{'='*60}")
        print(f"Total Duration: {self.report.total_duration:.2f}s")
        print(f"Total Operations: {summary.get('total_operations', 0)}")
        print(f"Average Operation Time: {summary.get('average_time_seconds', 0):.4f}s")

        if "slowest_operations" in summary:
            print(f"\nSlowest Operations:")
            for op in summary["slowest_operations"]:
                print(f"  - {op['name']}: {op['duration_seconds']:.4f}s")

        if "memory" in summary:
            mem = summary["memory"]
            print(f"\nMemory Usage:")
            print(f"  Peak: {mem['peak_mb']:.2f} MB")
            print(f"  Final: {mem['final_mb']:.2f} MB")

        print(f"{'='*60}\n")


class TimingContext:
    """Context manager for timing operations."""

    def __init__(self, profiler: Profiler, name: str, metadata: Dict[str, Any]):
        """
        Initialize timing context.

        Args:
            profiler: Parent profiler instance
            name: Name of the operation
            metadata: Metadata to attach
        """
        self.profiler = profiler
        self.name = name
        self.metadata = metadata
        self.entry: Optional[TimingEntry] = None

    def __enter__(self):
        """Enter timing context."""
        parent = self.profiler._timing_stack[-1] if self.profiler._timing_stack else None

        self.entry = TimingEntry(
            name=self.name,
            start_time=time.time(),
            parent=parent,
            metadata=self.metadata
        )

        self.profiler._timing_stack.append(self.name)
        self.profiler.report.timings.append(self.entry)

        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Exit timing context."""
        if self.entry:
            self.entry.finish()

            # Record exception if any
            if exc_type is not None:
                self.entry.metadata["exception"] = str(exc_val)
                self.entry.metadata["exception_type"] = exc_type.__name__

        if self.profiler._timing_stack:
            self.profiler._timing_stack.pop()

        return False


# ============================================================================
# Decorator
# ============================================================================

def profile(
    name: Optional[str] = None,
    track_memory: bool = True,
    save_report: bool = False,
    report_dir: Optional[Path] = None
):
    """
    Decorator to profile a function.

    Args:
        name: Name for the profiling session (defaults to function name)
        track_memory: Whether to track memory usage
        save_report: Whether to save the report to a file
        report_dir: Directory to save reports (defaults to ./profiling_reports)

    Example:
        @profile(name="data_processing", save_report=True)
        def process_large_dataset(data):
            # Processing logic
            pass
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs) -> Any:
            profiler_name = name or func.__name__

            with Profiler(profiler_name, track_memory=track_memory) as profiler:
                # Add function metadata
                profiler.add_metadata("function", func.__name__)
                profiler.add_metadata("module", func.__module__)

                # Execute function
                with profiler.time("function_execution"):
                    result = func(*args, **kwargs)

                # Save report if requested
                if save_report:
                    output_dir = report_dir or Path("profiling_reports")
                    output_dir.mkdir(parents=True, exist_ok=True)

                    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                    report_path = output_dir / f"{profiler_name}_{timestamp}.json"
                    profiler.save_report(report_path)

                # Print summary to console
                profiler.print_summary()

                return result

        return wrapper
    return decorator


# ============================================================================
# Simple Timing Decorator
# ============================================================================

def timed(func: Callable) -> Callable:
    """
    Simple decorator to time a function and log the duration.

    Example:
        @timed
        def slow_operation():
            time.sleep(1)
    """
    @wraps(func)
    def wrapper(*args, **kwargs) -> Any:
        start_time = time.time()

        try:
            result = func(*args, **kwargs)
            return result
        finally:
            duration = time.time() - start_time
            logger.info(f"{func.__name__} completed in {duration:.4f}s")

    return wrapper
