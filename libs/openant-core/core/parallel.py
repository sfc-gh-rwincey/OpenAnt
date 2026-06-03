"""
Parallel execution helpers for per-unit / per-finding pipeline loops.

The OpenAnt pipeline is dominated by serial blocking calls to the LLM:
agentic enhancement, Stage 1 detection, Stage 2 verification, and dynamic
testing all do one finding at a time. The Anthropic SDK calls are blocking
I/O, so a simple thread pool is the right primitive — no asyncio rewrite,
and the GIL is released while the HTTP socket is busy.

Public API:
    parallel_map(fn, items, workers, ...) -> list

Semantics:
    - workers <= 1 → run sequentially in-process (preserves debug-friendly
      stack traces and avoids the executor entirely).
    - workers >= 2 → run on a ThreadPoolExecutor; results are returned in
      input order regardless of completion order.
    - on_error="raise" (default) re-raises the first exception; on_error
      ="skip" stores the exception in the result slot so the caller can
      decide what to do per-item.
    - The optional ``on_done`` callback fires once per item, in completion
      order, with ``(item, result_or_exception, elapsed_seconds)``. It is
      called from the worker thread for parallel runs and from the main
      thread for sequential runs.

This module deliberately does NOT touch token tracking or progress
reporting — those modules carry their own locks. The caller is responsible
for ensuring the function passed in is thread-safe for the data it touches.
"""

from __future__ import annotations

import time
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable, Iterable, List, Optional, TypeVar

T = TypeVar("T")
R = TypeVar("R")


def parallel_map(
    fn: Callable[[T], R],
    items: Iterable[T],
    workers: int = 1,
    on_done: Optional[Callable[[T, object, float], None]] = None,
    on_error: str = "raise",
    thread_name_prefix: str = "openant",
) -> List[R]:
    """Apply ``fn`` to each of ``items``, optionally in parallel.

    Args:
        fn: Function taking one item and returning a result. Must be
            thread-safe with respect to any state it shares with other
            invocations.
        items: Sequence of inputs. Will be materialized into a list so we
            can preserve order.
        workers: Number of worker threads. <= 1 means sequential.
        on_done: Optional callback ``(item, result_or_exception, seconds)``
            invoked once per completed item.
        on_error: ``"raise"`` (default) — first exception propagates. Any
            other value — the exception is captured and returned in the
            result slot for that item.
        thread_name_prefix: Used to name worker threads for debugging.

    Returns:
        List of results, in the same order as ``items`` (or the captured
        exception for items that failed when ``on_error != "raise"``).
    """
    item_list: List[T] = list(items)
    n = len(item_list)
    if n == 0:
        return []

    results: List[R] = [None] * n  # type: ignore[list-item]

    if workers <= 1:
        for idx, item in enumerate(item_list):
            start = time.monotonic()
            try:
                value = fn(item)
            except Exception as exc:  # noqa: BLE001
                elapsed = time.monotonic() - start
                if on_done is not None:
                    on_done(item, exc, elapsed)
                if on_error == "raise":
                    raise
                results[idx] = exc  # type: ignore[assignment]
                continue
            elapsed = time.monotonic() - start
            if on_done is not None:
                on_done(item, value, elapsed)
            results[idx] = value
        return results

    def _runner(idx_item):
        idx, item = idx_item
        start = time.monotonic()
        try:
            value = fn(item)
        except Exception as exc:  # noqa: BLE001
            elapsed = time.monotonic() - start
            return idx, item, exc, elapsed, True
        elapsed = time.monotonic() - start
        return idx, item, value, elapsed, False

    first_error: Optional[BaseException] = None

    with ThreadPoolExecutor(
        max_workers=workers, thread_name_prefix=thread_name_prefix
    ) as pool:
        futures = [
            pool.submit(_runner, (idx, item))
            for idx, item in enumerate(item_list)
        ]
        for fut in as_completed(futures):
            idx, item, value, elapsed, errored = fut.result()
            if on_done is not None:
                on_done(item, value, elapsed)
            if errored:
                if on_error == "raise":
                    if first_error is None:
                        first_error = value  # type: ignore[assignment]
                    # Keep draining so we don't leak threads, but record
                    # the exception in the slot so the caller can also see
                    # which item failed if it inspects results.
                results[idx] = value  # type: ignore[assignment]
            else:
                results[idx] = value

    if first_error is not None and on_error == "raise":
        raise first_error

    return results


def resolve_workers(requested: Optional[int], total_items: int) -> int:
    """Clamp a user-requested worker count to a sensible value.

    Args:
        requested: ``None`` or a positive int from the user. ``None`` and
            values <= 0 mean "sequential" (1).
        total_items: Number of items the loop will process.

    Returns:
        ``1`` if there are 0–1 items or the user asked for sequential;
        otherwise ``min(requested, total_items)``.
    """
    if total_items <= 1:
        return 1
    if requested is None or requested <= 1:
        return 1
    return min(requested, total_items)


def announce_parallelism(step: str, workers: int, total: int) -> None:
    """Print a one-line note to stderr about parallelism settings."""
    if workers <= 1:
        return
    print(
        f"[{step}] Parallel mode: {workers} workers across {total} items",
        file=sys.stderr,
        flush=True,
    )
