"""Boundary contracts between APU and OAE.

The formal interface between the two trust domains: ProbeState (shared outcome
vocabulary) and validate_result_file() (OAE-side validation of APU output). The
APU may run in untrusted segments, so the OAE validates every field.

Import rules:
  - apu/ imports ProbeState; oae/ imports ProbeState + validate_result_file().
  - oae/ imports IntegrityError + verify_artifact() (signature check).
  - This module never imports from apu/ or oae/.

OAE ingestion order: parse JSON, verify_artifact() (integrity), then
validate_result_file() (structure); then it is safe to analyse.
"""

from __future__ import annotations

import logging
from enum import Enum
from typing import Any

# Re-exported so the OAE needs one import point (apu/ imports from integrity directly).
from nssa.shared.integrity import IntegrityError, verify_artifact  # noqa: F401

logger = logging.getLogger(__name__)

# ── Stdout-mode artifact markers ──
# The APU wraps stdout-mode artifacts in these markers to locate the JSON in
# mixed output; file-mode artifacts have none. The OAE strips them before parsing.
ARTIFACT_BEGIN = "-----BEGIN NSSA ARTIFACT-----"
ARTIFACT_END = "-----END NSSA ARTIFACT-----"


def strip_artifact_markers(text: str) -> str:
    """Return *text* with stdout-mode BEGIN/END markers removed, if present."""
    stripped = text.strip()
    if stripped.startswith(ARTIFACT_BEGIN):
        stripped = stripped[len(ARTIFACT_BEGIN):]
        end_idx = stripped.rfind(ARTIFACT_END)
        if end_idx != -1:
            stripped = stripped[:end_idx]
    return stripped.strip()


# ── ProbeState ──

class ProbeState(str, Enum):
    """Outcome of a single connectivity probe; the string values are the APU/OAE contract."""

    OPEN = "open"
    CLOSED = "closed"
    FILTERED = "filtered"
    OPEN_FILTERED = "open|filtered"
    INCONCLUSIVE = "inconclusive"
    UNREACHABLE = "unreachable"
    ERROR = "error"


# ── Valid protocol identifiers ──
VALID_PROTOS = frozenset({"tcp", "udp"})


# ── Observation field names ──
# Keys of a probe entry holding its observed state and planning strategy.
STATE_KEY = "state"
STRATEGY_KEY = "strategy"


def probe_strategy_key(entry: dict) -> str:
    """The key a probe entry carries its strategy under."""
    return STRATEGY_KEY


def probe_state_value(entry: dict, default: Any = None) -> Any:
    """Raw observed-state value of a probe entry; *default* if absent."""
    return entry.get(STATE_KEY, default)


def probe_strategy_value(entry: dict, default: Any = None) -> Any:
    """Raw planning-strategy value of a probe entry; *default* if absent."""
    return entry.get(STRATEGY_KEY, default)


# ── Result file validation (OAE ingestion boundary) ──

class ContractViolation(Exception):
    """Raised when an APU result file violates the boundary contract."""


def validate_result_file(raw: dict[str, Any]) -> None:
    """Validate an APU result file against the boundary contract.

    The OAE's first line of defence: checks presence, type, and semantics of
    every field. Raises ContractViolation on any problem.
    """
    # ── Top-level required fields ──
    # Identity is "segment" (single-segment artifacts) or "probe_id"
    # (Deployment-resolved); at least one is required. vantage_ip is required
    # either way, as a property of the Probe itself.
    if "segment" not in raw and "probe_id" not in raw:
        raise ContractViolation(
            "Missing artifact identity: expected 'segment' (legacy) or 'probe_id'."
        )
    if "segment" in raw:
        _require_str(raw, "segment")
    if "probe_id" in raw:
        _require_str(raw, "probe_id")
    _require_str(raw, "vantage_ip")
    _require_number(raw, "start_time")
    _require_number(raw, "total_probes")

    # ── Probes array ──
    probes = raw.get("probes")
    if not isinstance(probes, list):
        raise ContractViolation(
            f"'probes' must be a list, got {type(probes).__name__}"
        )

    declared_total = raw["total_probes"]
    if len(probes) != declared_total:
        raise ContractViolation(
            f"Declared total_probes={declared_total} but found "
            f"{len(probes)} probe entries"
        )

    for i, probe in enumerate(probes):
        _validate_probe_entry(probe, index=i)


def _validate_probe_entry(probe: dict, index: int) -> None:
    """Validate a single probe entry within the result file."""
    prefix = f"probes[{index}]"

    if not isinstance(probe, dict):
        raise ContractViolation(f"{prefix}: expected dict, got {type(probe).__name__}")

    _require_str(probe, "src_ip", prefix)
    _require_str(probe, "dst_ip", prefix)
    _require_int(probe, "dst_port", prefix)
    _require_str(probe, "proto", prefix)
    _require_str(probe, STATE_KEY, prefix)

    # Proto validation
    proto = probe["proto"]
    if proto not in VALID_PROTOS:
        raise ContractViolation(f"{prefix}.proto: invalid '{proto}', expected {VALID_PROTOS}")

    # State validation — must be a known ProbeState value
    state = probe[STATE_KEY]
    valid_states = {s.value for s in ProbeState}
    if state not in valid_states:
        raise ContractViolation(
            f"{prefix}.{STATE_KEY}: invalid '{state}', expected one of {valid_states}"
        )

    # Port range validation
    port = probe["dst_port"]
    if not (0 <= port <= 65535):
        raise ContractViolation(f"{prefix}.dst_port: {port} out of range [0, 65535]")


# ── Validation helpers ──

def _require_str(d: dict, key: str, prefix: str = "") -> None:
    loc = f"{prefix}.{key}" if prefix else key
    if key not in d:
        raise ContractViolation(f"Missing required field: '{loc}'")
    if not isinstance(d[key], str):
        raise ContractViolation(f"'{loc}' must be a string, got {type(d[key]).__name__}")


def _require_int(d: dict, key: str, prefix: str = "") -> None:
    loc = f"{prefix}.{key}" if prefix else key
    if key not in d:
        raise ContractViolation(f"Missing required field: '{loc}'")
    if not isinstance(d[key], int):
        raise ContractViolation(f"'{loc}' must be an int, got {type(d[key]).__name__}")


def _require_number(d: dict, key: str, prefix: str = "") -> None:
    loc = f"{prefix}.{key}" if prefix else key
    if key not in d:
        raise ContractViolation(f"Missing required field: '{loc}'")
    if not isinstance(d[key], (int, float)):
        raise ContractViolation(f"'{loc}' must be a number, got {type(d[key]).__name__}")
