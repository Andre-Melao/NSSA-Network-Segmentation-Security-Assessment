"""Shared bounded-retry helper for LLMProvider adapters.

Which exceptions are transient is SDK-specific, so this only factors out the
generic retry loop; each adapter supplies its own is_retryable predicate.
"""

from __future__ import annotations

import time
from typing import Callable, TypeVar

T = TypeVar("T")


def with_retry(
    fn: Callable[[], T],
    *,
    is_retryable: Callable[[Exception], bool],
    max_attempts: int = 3,
    base_delay: float = 1.0,
    sleep: Callable[[float], None] | None = None,
) -> T:
    """Call fn(), retrying retryable exceptions up to max_attempts total attempts
    with exponential backoff (base_delay * 2**attempt).

    Re-raises immediately for any exception is_retryable(exc) rejects.

    sleep is injectable for tests. It is resolved to time.sleep inside the
    function (not as a default value) so monkeypatching time.sleep takes effect.
    """
    _sleep = sleep if sleep is not None else time.sleep
    attempt = 0
    while True:
        try:
            return fn()
        except Exception as exc:
            attempt += 1
            if attempt >= max_attempts or not is_retryable(exc):
                raise
            _sleep(base_delay * (2 ** (attempt - 1)))
