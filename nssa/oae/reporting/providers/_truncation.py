"""Shared truncation-hint text for LLMProvider adapters.

Each SDK signals "why generation stopped" differently (Anthropic stop_reason ==
"max_tokens", Gemini finish_reason ending in "MAX_TOKENS", OpenAI-compatible
finish_reason == "length"). Each adapter extracts its own signal; this module
keeps the resulting message consistent. A truncated response typically shows up
as a JSONDecodeError or, with Anthropic tool-use, a missing/incomplete tool_use
block; the same message covers both.
"""

from __future__ import annotations


def build_hint(description: str, *, provider_class_name: str) -> str:
    """description names the raw field/value that indicated truncation, e.g.
    "stop_reason is 'max_tokens'", built by the adapter; this supplies the shared
    remainder of the message. Only called once truncation is confirmed.
    """
    return (
        f" -- the response's {description}: it was cut off before "
        f"completion. Increase max_output_tokens ({provider_class_name}'s "
        f"own constructor argument) rather than treating this as a data "
        f"or schema problem."
    )
