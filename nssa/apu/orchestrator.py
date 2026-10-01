"""Host Mode orchestration: the Host Mode extension of nssa-probe.

When a Probe declares probing_mode="host", resolve the SPM workloads its groups
span, run the APU once per workload over SSH, and aggregate the results into one
ProbeResults (the same shape as a representative-mode run).

Each remote invocation is an ordinary nssa-probe run; APUEngine never knows it
is orchestrated. Representative and Host Observation remain distinct claims:
a representative probe speaks on behalf of a group, a host-mode sub-run is the
workload itself.
"""

from __future__ import annotations

import json
import logging
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass

from nssa.apu.engine import APUConfig
from nssa.apu.execution.results import ProbeResult, ProbeResults
from nssa.shared.contracts import strip_artifact_markers, validate_result_file, ContractViolation
from nssa.shared.deployment import Deployment, ProbeConfig
from nssa.shared.models import Server
from nssa.shared.policy import SegmentationPolicy

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class OrchestratorConfig:
    """Tuning for this Host Mode Probe's SSH fan-out (separate from APUConfig,
    which governs probes within one workload's run).

    ssh_connect_timeout is ssh's ConnectTimeout (TCP + handshake).
    remote_execution_timeout bounds the whole SSH session plus remote run. It is
    a hang safety net, sized generously: a run against a default-deny topology
    took ~42s, so 30s killed healthy runs.
    """

    max_parallel_sessions: int = 10
    ssh_connect_timeout: float = 10.0
    remote_execution_timeout: float = 1800.0
    ssh_retries: int = 1
    ssh_user: str = "root"


@dataclass(slots=True)
class WorkloadOutcome:
    """Result of running the APU on one workload over SSH.

    succeeded separates a failure from a workload with zero results. error is
    the final attempt's reason (None on success). elapsed times the SSH session,
    not queueing.
    """

    workload: Server
    succeeded: bool
    elapsed: float
    probe_results: list[ProbeResult]
    error: str | None = None


def run_host_mode(
    *,
    policy: SegmentationPolicy,
    deployment: Deployment,
    probe_config: ProbeConfig,
    spm_bytes: bytes,
    config: APUConfig,
    orchestrator_config: OrchestratorConfig | None = None,
    probe_id: str,
    deployment_hash: str | None = None,
) -> ProbeResults:
    """Run the APU once per resolved workload, aggregated into one ProbeResults.

    Returns the same shape as APUEngine.run(). src_ip on the result is this
    Probe's own IP (metadata); each ProbeResult keeps its real src_ip.
    deployment_hash is forwarded from the caller (cli.py), not computed here.
    """
    if probe_config.probing_mode != "host":
        raise ValueError(
            f"run_host_mode() requires a 'host' Probe, got probing_mode="
            f"'{probe_config.probing_mode}'."
        )
    if not probe_config.ip:
        raise ValueError(
            f"Probe '{probe_config.name}' declares probing_mode='host' but no 'ip'; "
            "a Host Mode Probe needs its own vantage IP for the aggregated artifact."
        )

    orchestrator_config = orchestrator_config or OrchestratorConfig()

    # deployment_parser rejects host mode with no 'groups'; this catches 'groups'
    # that resolve to zero policy-declared workloads (e.g. a typo'd name). A hard
    # failure, so Host Mode never silently orchestrates nothing.
    targets = deployment.target_workloads(probe_config.name, policy) or []
    if not targets:
        raise ValueError(
            f"Probe '{probe_config.name}' declares groups {probe_config.groups} but "
            "they resolve to zero SPM workloads -- nothing to orchestrate. Check for "
            "a misspelled group name, or a group with no servers assigned to it."
        )

    results = ProbeResults(src_ip=probe_config.ip, probe_id=probe_id, deployment_hash=deployment_hash)
    total = len(targets)
    logger.info(
        "Host Mode Probe '%s' orchestrating %d workload(s) across groups=%s",
        probe_id, total, probe_config.groups,
    )

    completed = 0
    failed: list[WorkloadOutcome] = []

    with ThreadPoolExecutor(max_workers=max(1, orchestrator_config.max_parallel_sessions)) as pool:
        futures = {
            pool.submit(_run_remote_workload, workload, spm_bytes, orchestrator_config, config): workload
            for workload in targets
        }
        for future in as_completed(futures):
            workload = futures[future]
            outcome = future.result()  # _run_remote_workload never raises
            completed += 1
            if outcome.succeeded:
                logger.info(
                    "[%d/%d] %s (%s): completed (%.1fs, %d probe result(s))",
                    completed, total, workload.name, workload.ip,
                    outcome.elapsed, len(outcome.probe_results),
                )
            else:
                failed.append(outcome)
                logger.warning(
                    "[%d/%d] %s (%s): failed after %.1fs (%s)",
                    completed, total, workload.name, workload.ip,
                    outcome.elapsed, outcome.error,
                )
            for r in outcome.probe_results:
                results.add(r)

    results.finalise()
    succeeded = total - len(failed)
    logger.info(
        "Host Mode Probe '%s' finished: %d/%d workload(s) succeeded, %d total probe results",
        probe_id, succeeded, total, len(results.probes),
    )
    if failed:
        logger.warning(
            "%d workload(s) failed: %s",
            len(failed),
            ", ".join(f"{o.workload.name} ({o.workload.ip}): {o.error}" for o in failed),
        )
    return results


def _remote_command(workload: Server, config: APUConfig) -> list[str]:
    """The remote nssa-probe invocation for one workload.

    Only --src-ip: the workload's groups resolve from the SPM sent over stdin.
    --no-sign: only the aggregated artifact is signed. Tuning is forwarded from
    APUConfig. --discovery/--no-lateral-discovery mirrors enable_lateral_discovery,
    but --intra-segment-discovery is always added: Host Mode exists to verify
    intra-segment isolation. Representative Mode and nssa-probe defaults are
    unaffected.
    """
    cmd = [
        "nssa-probe", "/dev/stdin",
        "--src-ip", workload.ip,
        "--probe-id", workload.name,
        "--no-sign",
        "--timeout", str(config.timeout),
        "--rate-limit", str(config.rate_limit_ms),
        "--max-workers", str(config.max_workers),
        "--max-host-parallel", str(config.max_host_parallel),
    ]
    # Always passed explicitly so the remote run matches this Probe's config.
    cmd.append("--discovery" if config.enable_lateral_discovery else "--no-lateral-discovery")
    cmd.append("--intra-segment-discovery")
    return cmd


def _run_remote_workload(
    workload: Server,
    spm_bytes: bytes,
    orchestrator_config: OrchestratorConfig,
    config: APUConfig,
) -> WorkloadOutcome:
    """Run the APU on one workload over SSH; never raises.

    Retries ssh_retries times (connection, timeout, non-zero exit, malformed
    response) with backoff. On final failure, logs and returns a failed
    WorkloadOutcome; the workload is absent from the artifact's probes[].

    ServerAliveInterval/CountMax let ssh detect a dead connection (~45s), while
    remote_execution_timeout covers a live connection with a hung process.
    """
    ssh_target = f"{orchestrator_config.ssh_user}@{workload.ip}"
    ssh_cmd = [
        "ssh",
        "-o", "BatchMode=yes",
        "-o", f"ConnectTimeout={int(orchestrator_config.ssh_connect_timeout)}",
        "-o", "ServerAliveInterval=15",
        "-o", "ServerAliveCountMax=3",
        ssh_target,
        *_remote_command(workload, config),
    ]

    logger.info("-> %s (%s): running...", workload.name, workload.ip)
    start = time.time()
    attempts = orchestrator_config.ssh_retries + 1
    for attempt in range(1, attempts + 1):
        try:
            proc = subprocess.run(
                ssh_cmd,
                input=spm_bytes,
                capture_output=True,
                timeout=orchestrator_config.remote_execution_timeout,
            )
            if proc.returncode != 0:
                raise RuntimeError(
                    f"nssa-probe exited {proc.returncode}: "
                    f"{proc.stderr.decode('utf-8', errors='replace').strip()}"
                )

            text = strip_artifact_markers(proc.stdout.decode("utf-8", errors="replace"))
            raw = json.loads(text)
            validate_result_file(raw)

            probe_results = [ProbeResult.from_dict(p) for p in raw["probes"]]
            return WorkloadOutcome(
                workload=workload, succeeded=True,
                elapsed=time.time() - start, probe_results=probe_results,
            )

        except (subprocess.TimeoutExpired, RuntimeError, json.JSONDecodeError,
                ContractViolation, KeyError, OSError) as exc:
            error = "timeout" if isinstance(exc, subprocess.TimeoutExpired) else str(exc)
            if attempt < attempts:
                logger.warning(
                    "Workload '%s' (%s): attempt %d/%d failed (%s), retrying",
                    workload.name, workload.ip, attempt, attempts, error,
                )
                time.sleep(1.0)
                continue
            logger.error(
                "Workload '%s' (%s): giving up after %d attempt(s): %s",
                workload.name, workload.ip, attempts, error,
            )
            return WorkloadOutcome(
                workload=workload, succeeded=False,
                elapsed=time.time() - start, probe_results=[], error=error,
            )

    # Unreachable, satisfies static analysis.
    return WorkloadOutcome(
        workload=workload, succeeded=False, elapsed=time.time() - start,
        probe_results=[], error="unreachable",
    )
