"""Deployment model.

Frozen dataclasses, the execution-configuration counterpart to
SegmentationPolicy: the SPM says what the intended policy is, the Deployment
says how the audit runs (which Probes exist, what they represent, how they run).

A Deployment is optional; without one, segment/src_ip resolve via CLI flags or
auto-detection.

target_workloads() combines both models (a host-mode Probe's groups resolved to
SPM workloads) so the OAE ingest and the Host Mode orchestrator share one
implementation.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from nssa.shared.models import Server
    from nssa.shared.policy import SegmentationPolicy


@dataclass(frozen=True, slots=True)
class ProbeConfig:
    """One declared Probe: an execution unit that produces exactly one artifact.

    name          - the Probe's identity; becomes the artifact's probe_id.
                    Optional in the single-probe shorthand, unique otherwise.
    probing_mode  - "representative" (runs the APU locally) or "host"
                    (orchestrates the APU remotely per workload, see
                    nssa.apu.orchestrator).
    ip            - optional vantage IP; overrides auto-detection, not --src-ip.
    groups        - optional groups this Probe represents; overrides
                    auto-detection, not --segment. Empty means resolve as before.
    execution     - "manual" (default) or "automated": whether nssa-run runs
                    this Probe itself (via SSHRunner) or the auditor does.
                    Unknown to the APU and OAE.
    ssh_profile   - optional name of an authentication.ssh_profiles entry used
                    by SSHRunner; never the credential itself. Not required for
                    "automated" (ambient SSH config is used), validated at parse
                    time when given, unused for "manual".
    """

    name: str | None = None
    probing_mode: str = "representative"
    ip: str | None = None
    groups: tuple[str, ...] = ()
    execution: str = "manual"
    ssh_profile: str | None = None


@dataclass(slots=True)
class Deployment:
    """Fully parsed Deployment: the set of Probes an audit run consists of."""

    probes: tuple[ProbeConfig, ...] = field(default_factory=tuple)

    def get_probe(self, name: str) -> ProbeConfig | None:
        """Return the declared Probe with this name, or None if not found."""
        for p in self.probes:
            if p.name == name:
                return p
        return None

    def target_workloads(self, probe_id: str, policy: "SegmentationPolicy") -> list | None:
        """Every SPM workload this host-mode Probe's groups span, deduplicated by IP.

        Host mode only. None means nothing to resolve: the Probe is undeclared,
        has no groups, or is not host mode.
        """
        probe = self.get_probe(probe_id)
        if probe is None or not probe.groups or probe.probing_mode != "host":
            return None
        seen: dict[str, "Server"] = {}
        for group in probe.groups:
            for srv in policy.workloads_in_group(group):
                seen[srv.ip] = srv
        return list(seen.values())

    def allowed_ips_for_probe(self, probe_id: str, policy: "SegmentationPolicy") -> set[str] | None:
        """Every IP the SPM declares in this host-mode Probe's groups.

        Host mode only: each src_ip is a declared workload's own address, a
        stronger check than CIDR. Returns None for representative mode (see
        allowed_networks_for_probe()). None means no enforceable check, never
        an empty/always-fail set.
        """
        workloads = self.target_workloads(probe_id, policy)
        if workloads is None:
            return None
        return {srv.ip for srv in workloads}

    def allowed_networks_for_probe(self, probe_id: str, policy: "SegmentationPolicy") -> list | None:
        """CIDR networks a representative-mode Probe's declared groups span.

        Representative mode only: src_ip must fall in a CIDR declared for one of
        the groups. None means no enforceable check (undeclared, no groups,
        wrong mode, or no group has a CIDR).
        """
        probe = self.get_probe(probe_id)
        if probe is None or not probe.groups or probe.probing_mode != "representative":
            return None
        networks = [
            segment.network
            for group in probe.groups
            if (segment := policy.get_segment(group)) is not None and segment.network is not None
        ]
        return networks or None
