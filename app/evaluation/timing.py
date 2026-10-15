"""Local PoC timing helpers using measured perf-counter samples only."""

import math
import time
from typing import Any, Callable


def summarize_ns(samples: list[int]) -> dict[str, Any]:
    if not samples:
        raise ValueError("at least one measured timing sample is required")
    ordered = sorted(samples)
    rank = max(1, math.ceil(0.95 * len(ordered)))
    midpoint = len(ordered) // 2
    median = (
        ordered[midpoint]
        if len(ordered) % 2
        else (ordered[midpoint - 1] + ordered[midpoint]) / 2
    )
    return {
        "unit": "nanoseconds",
        "sample_count": len(ordered),
        "median": median,
        "p95_nearest_rank": ordered[rank - 1],
        "minimum": ordered[0],
        "maximum": ordered[-1],
    }


def benchmark(callable_: Callable[[], Any], *, iterations: int, warmups: int) -> tuple[dict[str, Any], list[int]]:
    if iterations < 1:
        raise ValueError("iterations must be positive")
    if warmups < 0:
        raise ValueError("warmups must not be negative")
    for _ in range(warmups):
        callable_()
    samples: list[int] = []
    for _ in range(iterations):
        started = time.perf_counter_ns()
        callable_()
        samples.append(time.perf_counter_ns() - started)
    return summarize_ns(samples), samples
