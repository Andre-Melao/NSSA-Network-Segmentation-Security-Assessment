"""APU engine: minimal orchestration layer.

Resolves the vantage point (--segment/--src-ip, then a Deployment-declared
Probe, then CIDR auto-detection), builds the scheduler, generates and runs the
tests, and persists results. Policy reasoning, conversion, and metrics live in
the planner, scheduler, and results layers.
"""

from __future__ import annotations

import logging
import socket
from dataclasses import dataclass
from pathlib import Path

from nssa.apu.execution.net_detect import DetectedSegment, detect_segment, infer_src_ip
from nssa.apu.planning.planner import TestCase, generate_tests
from nssa.apu.planning.priority import build_segment_sensitivity_index, segment_sensitivity
from nssa.apu.execution.probes.nmap_probe import NmapProbe
from nssa.apu.execution.probes.base import BaseProbe
from nssa.apu.execution.probes.tcp_probe import TCPProbe
from nssa.apu.execution.results import ProbeResults
from nssa.apu.execution.scheduler import ProbeScheduler, ProbeTask
from nssa.shared.deployment import Deployment, ProbeConfig
from nssa.shared.policy import SegmentationPolicy
from nssa.shared.reachability import ExpectedConnectivityModel, build_expected_connectivity

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class APUConfig:
    timeout: float = 1.0
    rate_limit_ms: int = 50
    output_dir: str = "results"
    max_workers: int = 50
    max_host_parallel: int = 5
    # Off by default: only tests what the SPM declares unless the auditor opts into
    # lateral visibility probing (nssa-probe --discovery). True enables BOTH intra-
    # and inter-segment discovery.
    enable_lateral_discovery: bool = False
    # Narrower opt-in: intra-segment discovery only, even if
    # enable_lateral_discovery is False. Only set True by the Host Mode fan-out
    # (nssa.apu.orchestrator), which audits real workloads. Representative Mode
    # never sets it.
    enable_intra_segment_discovery: bool = False


def resolve_probe_config(
    deployment: Deployment | None,
    probe_name: str | None,
) -> ProbeConfig | None:
    """Select which declared Probe (if any) this APU run corresponds to.

    None when no Deployment was given (vantage resolution falls through to
    --segment/--src-ip or auto-detection). A single-probe Deployment needs no
    --probe-name; several probes require it. Public because apu/cli.py also
    calls it to choose between APUEngine and the Host Mode orchestrator.
    """
    if deployment is None:
        return None
    if probe_name is not None:
        probe = deployment.get_probe(probe_name)
        if probe is None:
            raise ValueError(
                f"Probe '{probe_name}' not found in deployment. "
                f"Declared: {[p.name for p in deployment.probes]}"
            )
        return probe
    if len(deployment.probes) == 1:
        return deployment.probes[0]
    raise ValueError(
        "Deployment declares multiple probes; pass --probe-name to select one. "
        f"Declared: {[p.name for p in deployment.probes]}"
    )


class APUEngine:
    def __init__(
        self,
        policy: SegmentationPolicy,
        config: APUConfig | None = None,
        segment_override: str | None = None,
        src_ip_override: str | None = None,
        deployment: Deployment | None = None,
        deployment_hash: str | None = None,
        probe_name: str | None = None,
        probe_id_override: str | None = None,
    ) -> None:
        self.policy = policy
        self.config = config or APUConfig()
        self.output_dir = Path(self.config.output_dir)
        self.deployment_hash = deployment_hash

        probe_config = resolve_probe_config(deployment, probe_name)
        if probe_config is not None and probe_config.probing_mode != "representative":
            raise ValueError(
                f"Probe '{probe_config.name}' declares probing_mode="
                f"'{probe_config.probing_mode}'. APUEngine only ever runs a "
                "single, already-resolved vantage identity directly -- a "
                "'host' Probe must be started through the Host Mode "
                "orchestrator (nssa.apu.orchestrator.run_host_mode), which "
                "invokes APUEngine once per resolved workload instead."
            )

        # Precedence: explicit --segment/--src-ip > Deployment-declared groups/ip >
        # SPM-derived groups for --src-ip alone > CIDR auto-detection. A minimal
        # Deployment has empty groups and falls through.
        # Host-mode flag, True only for the src_ip-only/SPM-resolved branch: src_ip
        # is then the exact declared workload, so the Planner's own-group skip
        # (see entries_to_probe_for_groups()) is dropped only there.
        self.is_host_mode: bool = False

        if segment_override:
            if policy.get_segment(segment_override) is None:
                raise ValueError(
                    f"Segment '{segment_override}' not found in SPM. "
                    f"Available: {policy.segment_names()}"
                )
            self.groups: tuple[str, ...] = (segment_override,)
            self.display_group = segment_override
            # One segment, so the artifact carries "segment".
            self._legacy_segment: str | None = segment_override
            self.src_ip = src_ip_override or infer_src_ip(policy.get_segment(segment_override))
            logger.info("Segment override: segment='%s', src_ip='%s'", self.display_group, self.src_ip)
        elif probe_config is not None and probe_config.groups:
            self.groups = probe_config.groups
            # groups[0] is display/logging only, not the artifact identity: setting
            # "segment" for a multi-group Probe would send ingest.py down the
            # single-CIDR validation path and discard the other groups. Identity
            # is probe_id; deployment.json says what it represents.
            self.display_group = probe_config.groups[0]
            self._legacy_segment = None
            if src_ip_override:
                self.src_ip = src_ip_override
            elif probe_config.ip:
                self.src_ip = probe_config.ip
            else:
                raise ValueError(
                    f"Probe '{probe_config.name}' declares groups but no 'ip'; "
                    "pass --src-ip or add 'ip' to its deployment entry."
                )
            logger.info(
                "Deployment-resolved: groups=%s, src_ip='%s' (probe='%s')",
                self.groups, self.src_ip, probe_config.name,
            )
        elif src_ip_override is not None:
            # --src-ip with no --segment or Deployment groups: resolve groups from
            # the SPM via policy.groups_for_ip() (used by Host Mode sub-invocations).
            groups = policy.groups_for_ip(src_ip_override)
            if not groups:
                raise ValueError(
                    f"--src-ip {src_ip_override} is not a declared workload "
                    "in the SPM; its groups cannot be resolved. Pass "
                    "--segment to declare a single group explicitly instead."
                )
            self.groups = groups
            self.display_group = groups[0]
            self._legacy_segment = None
            self.src_ip = src_ip_override
            self.is_host_mode = True
            logger.info("SPM-resolved: src_ip='%s', groups=%s", self.src_ip, self.groups)
        else:
            detected: DetectedSegment = detect_segment(policy)
            self.display_group = detected.segment.name
            self.groups = (self.display_group,)
            self._legacy_segment = self.display_group
            self.src_ip = src_ip_override or detected.local_ip
            logger.info(
                "Auto-detected: segment='%s', local_ip='%s' (iface: %s)",
                self.display_group,
                self.src_ip,
                detected.interface,
            )

        # probe_id: explicit override > Deployment Probe name > hostname.
        self.probe_id = (
            probe_id_override
            or (probe_config.name if probe_config is not None and probe_config.name else None)
            or socket.gethostname()
        )

        self._probes: dict[str, BaseProbe] = {
            "nmap": NmapProbe(),
            "tcp_fallback": TCPProbe(),
        }
        self._scheduler = ProbeScheduler(
            probes=self._probes,
            timeout=self.config.timeout,
            rate_limit_ms=self.config.rate_limit_ms,
            max_workers=self.config.max_workers,
            max_host_parallel=self.config.max_host_parallel,
        )

        _idx = build_segment_sensitivity_index(self.policy)
        self._sensitivity_fn = lambda seg: segment_sensitivity(seg, sensitivity_by_segment=_idx)

    def run(self, save: bool = True) -> ProbeResults:
        results = ProbeResults(
            src_ip=self.src_ip,
            segment_name=self._legacy_segment,
            probe_id=self.probe_id,
            deployment_hash=self.deployment_hash,
        )
        # The "starting"/"completed" bookends are logged by nssa.apu.cli and
        # nssa.apu.orchestrator; run()'s own logs are internal detail at DEBUG.
        logger.debug(
            "APU starting: probe_id='%s', groups=%s (vantage: %s)",
            self.probe_id, self.groups, self.src_ip,
        )

        tests = self.generate_tests()
        tasks = [ProbeTask.from_testcase(t) for t in tests]
        probe_results, stats = self._scheduler.run(src_ip=self.src_ip, tasks=tasks)
        for r in probe_results:
            results.add(r)

        results.finalise()
        # tasks and results are different units (a host-scan task expands into
        # 0..N results), not a planned-vs-completed pair.
        logger.debug(
            "Scheduler: %d task(s) dispatched, %d result(s), %d retr(y/ies), "
            "%d timeout(s), avg_rtt=%.2fms",
            stats.tasks, stats.results, stats.retries, stats.timeouts, stats.avg_rtt_ms,
        )
        if save:
            out_path = results.save(self.output_dir)
            logger.info("Probe artifact written to %s", out_path)
        else:
            logger.debug(
                "APU finished probe '%s': %d probe(s) (export deferred to CLI)",
                self.probe_id, len(results.probes),
            )
        return results

    def generate_tests(
        self,
        *,
        reachability: ExpectedConnectivityModel | None = None,
    ) -> list[TestCase]:
        if reachability is None:
            reachability = build_expected_connectivity(self.policy)

        tests = generate_tests(
            policy=self.policy,
            reachability=reachability,
            config=self.config,
            groups=self.groups,
            src_ip=self.src_ip,
            segment_sensitivity_fn=self._sensitivity_fn,
            is_host_mode=self.is_host_mode,
        )
        logger.debug("Planned %d test(s) for groups=%s", len(tests), self.groups)
        return tests
