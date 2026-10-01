"""Shared default(s) for LLMProvider adapters.

DEFAULT_MAX_OUTPUT_TOKENS (8192) is one named constant, so the three adapters
and nssa.oae.reporting.batching cannot drift apart. Kept dependency-free: every
adapter imports it at module level, so it must not create an import cycle.
"""

from __future__ import annotations

DEFAULT_MAX_OUTPUT_TOKENS: int = 8192
