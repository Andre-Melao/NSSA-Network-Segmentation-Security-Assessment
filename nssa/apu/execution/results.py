"""Probe results data structures.

Every connectivity test is recorded as a :class:`ProbeResult` and serialised to
JSON for the OAE; no policy interpretation is stored.

Artifact extraction modes:

* **File mode** (default): writes ``<probe_id>_results.json`` to a directory.
* **Stdout mode** (``--export -``): writes the JSON artifact to stdout between
  ``-----BEGIN NSSA-----`` / ``-----END NSSA-----`` markers, so it can be
  captured through the channel used to run the probe (``docker exec``, GNS3
  console, ssh).
"""

from __future__ import annotations

import json
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from nssa.shared.contracts import (
    ARTIFACT_BEGIN,
    ARTIFACT_END,
    STATE_KEY,
    STRATEGY_KEY,
    ProbeState,
    probe_state_value,
    probe_strategy_value,
)
from nssa.shared.integrity import sign_artifact

_MISSING = object()

@dataclass(slots=True)
class ProbeResult:
    """Raw outcome of one connectivity test; a pure evidence record with no policy judgement."""

    src_ip: str
    dst_ip: str
    dst_port: int
    proto: str                  # "tcp" | "udp"
    state: ProbeState
    strategy: str = ""              # planning strategy that produced the test
    context: str = ""               # canonical scope hint
    rtt_ms: float | None = None     # round-trip time if measurable
    detail: str = ""                # optional scanner output
    service: str | None = None
    service_banner: str | None = None
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        payload = {
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "dst_port": self.dst_port,
            "proto": self.proto,
            STATE_KEY: self.state.value,
            "detail": self.detail,
            STRATEGY_KEY: self.strategy,
            "context": self.context,
            "rtt_ms": self.rtt_ms,
            "timestamp": self.timestamp,
        }
        if self.state == ProbeState.OPEN:
            payload["service"] = self.service
            payload["service_banner"] = self.service_banner
        return payload

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ProbeResult":
        """Reconstruct a ProbeResult from its to_dict() form.

        Needed because Host Mode round-trips ProbeResults through a remote
        nssa-probe's JSON output. Fields to_dict() omits default to None.
        """
        state = probe_state_value(data, _MISSING)
        if state is _MISSING:
            raise KeyError(STATE_KEY)
        return cls(
            src_ip=data["src_ip"],
            dst_ip=data["dst_ip"],
            dst_port=data["dst_port"],
            proto=data["proto"],
            state=ProbeState(state),
            strategy=probe_strategy_value(data, ""),
            context=data.get("context", ""),
            rtt_ms=data.get("rtt_ms"),
            detail=data.get("detail", ""),
            service=data.get("service"),
            service_banner=data.get("service_banner"),
            timestamp=data.get("timestamp", 0.0),
        )


@dataclass(slots=True)
class ProbeResults:
    """Aggregated results from one Probe execution.

    The artifact's identity is probe_id (the Probe that produced it).
    segment_name is a legacy/display field and is optional; a Probe's groups
    live in deployment.json.

    Attributes:
        src_ip:       vantage point IP for this Probe.
        segment_name: single-segment label (None when identity is probe_id).
        probes:       individual probe results, each with its own src_ip
                      (per-host granularity).
        start_time:   scan start epoch.
        end_time:     scan end epoch (set on completion).
    """

    src_ip: str
    segment_name: str | None = None
    probes: list[ProbeResult] = field(default_factory=list)
    start_time: float = field(default_factory=time.time)
    end_time: float | None = None

    # ── Optional integrity fields ──
    # Set before save()/to_stdout() for a signed artifact.
    #   signing_key     : nacl.signing.SigningKey from load_signing_key()
    #   probe_id        : the artifact's identity and signing identity ("signed_by")
    #   policy_hash     : SHA-256 of the parsed SPM bytes
    #   deployment_hash : SHA-256 of the parsed deployment.json bytes; None
    #                     when no Deployment was used
    signing_key: Any = field(default=None, repr=False, compare=False)
    probe_id: str = field(default="", compare=False)
    policy_hash: Optional[str] = field(default=None, compare=False)
    deployment_hash: Optional[str] = field(default=None, compare=False)

    def add(self, result: ProbeResult) -> None:
        self.probes.append(result)

    def finalise(self) -> None:
        """Mark the scan as complete."""
        self.end_time = time.time()

    # ── Serialisation ──
    def _build_payload(self) -> dict[str, Any]:
        """Build the JSON-serialisable payload dict.

        segment/probe_id/policy_hash/deployment_hash are included only when set.
        If *signing_key* is set, the payload is signed with Ed25519.
        """
        payload: dict[str, Any] = {
            "vantage_ip": self.src_ip,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "total_probes": len(self.probes),
            "probes": [p.to_dict() for p in self.probes],
        }

        if self.segment_name is not None:
            payload["segment"] = self.segment_name

        # probe_id is included independently of signing (also for --no-sign).
        if self.probe_id:
            payload["probe_id"] = self.probe_id

        # Bind the artifact to the executed policy/deployment versions
        if self.policy_hash is not None:
            payload["policy_hash"] = self.policy_hash
        if self.deployment_hash is not None:
            payload["deployment_hash"] = self.deployment_hash

        # Sign before returning; the OAE verifies at ingestion
        if self.signing_key is not None:
            payload = sign_artifact(payload, self.signing_key, self.probe_id)

        return payload

    def save(self, directory: str | Path) -> Path:
        """Write results to <probe_id>_results.json in *directory* and return the path."""
        directory = Path(directory)
        directory.mkdir(parents=True, exist_ok=True)
        out = directory / f"{self.probe_id}_results.json"
        out.write_text(json.dumps(self._build_payload(), indent=2), encoding="utf-8")
        return out

    def to_stdout(self) -> None:
        """Write the artifact to stdout between ASCII BEGIN/END markers."""
        payload_json = json.dumps(self._build_payload(), indent=2)

        sys.stdout.write(f"{ARTIFACT_BEGIN}\n")
        sys.stdout.write(payload_json)
        sys.stdout.write(f"\n{ARTIFACT_END}\n")

        sys.stdout.flush()
