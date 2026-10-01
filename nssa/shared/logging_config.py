"""Centralized logging configuration for NSSA's CLI entrypoints.

Every nssa-* CLI wants NSSA's own nssa.* loggers to respect --verbose while
third-party libraries (WeasyPrint, FontTools, LLM SDKs, their HTTP transport)
do not inherit that level, which a bare basicConfig(level=DEBUG) would allow.
Those loggers are capped at WARNING regardless of verbose, so real problems
(e.g. a malformed font) remain visible but not routine DEBUG chatter. nssa.*
loggers have no level of their own and follow basicConfig().

Logger names (confirmed against each library's source):
  weasyprint     - "weasyprint".
  fontTools      - used by WeasyPrint for font subsetting; the "fontTools"
                   parent covers all submodules.
  httpx/httpcore - HTTP transport under the anthropic/openai/google-genai SDKs.
  anthropic      - "anthropic" (also the logger ANTHROPIC_LOG enables).
  google_genai   - "google_genai.<submodule>" (underscore, not "google.genai").
  openai         - "openai", same convention as httpx/httpcore.
"""

from __future__ import annotations

import logging

NOISY_THIRD_PARTY_LOGGERS: tuple[str, ...] = (
    "weasyprint",
    "fontTools",
    "httpx",
    "httpcore",
    "anthropic",
    "google_genai",
    "openai",
)

_LOG_FORMAT = "%(asctime)s [%(levelname)s] %(name)s - %(message)s"
_LOG_DATEFMT = "%H:%M:%S"


def configure_logging(*, verbose: bool = False) -> None:
    """Configure logging for one nssa-* CLI process; call once at the top of main().

    verbose controls only nssa.* loggers (DEBUG vs INFO); every logger in
    NOISY_THIRD_PARTY_LOGGERS is capped at WARNING. Harmless if a listed
    package is not installed.
    """
    level = logging.DEBUG if verbose else logging.INFO
    # Not force=True: basicConfig() is a no-op if the root logger already has a
    # handler, so a caller that configured logging (test runner, embedding app)
    # is not overridden. The .setLevel() calls below are unconditional.
    logging.basicConfig(level=level, format=_LOG_FORMAT, datefmt=_LOG_DATEFMT)

    for name in NOISY_THIRD_PARTY_LOGGERS:
        logging.getLogger(name).setLevel(logging.WARNING)
