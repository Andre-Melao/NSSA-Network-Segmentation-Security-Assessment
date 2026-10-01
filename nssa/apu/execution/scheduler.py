"""Probe scheduling and execution primitives (planning is separate from execution)."""

from __future__ import annotations

import random
import threading
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, replace

from nssa.apu.execution.probes.base import BaseProbe
from nssa.apu.execution.probes.service_probe import enrich_service
from nssa.apu.execution.results import ProbeResult
from nssa.shared.contracts import ProbeState

MAX_RETRIES_PER_RUN = 100

STATE_PRIORITY: dict[ProbeState, int] = {
    ProbeState.OPEN: 5,
    ProbeState.CLOSED: 4,
    ProbeState.OPEN_FILTERED: 3,
    ProbeState.FILTERED: 2,
    ProbeState.UNREACHABLE: 1,
    ProbeState.INCONCLUSIVE: 0,
    ProbeState.ERROR: 0,
}


@dataclass(slots=True, frozen=True)
class ProbeTask:
    """Single probe execution task produced by the planning layer."""

    dst_ip: str
    dst_port: int
    proto: str
    strategy: str
    context: str = "segment_level"
    priority: int = 0
    scan_mode: str = "single_probe"  # "host_scan" | "single_probe"

    @classmethod
    def from_testcase(cls, tc) -> ProbeTask:
        """Convert a planning-layer TestCase to an execution-layer ProbeTask."""
        return cls(
            dst_ip=tc.dst_ip,
            dst_port=tc.dst_port,
            proto=tc.proto,
            strategy=tc.strategy,
            context=tc.context,
            priority=tc.priority,
            scan_mode=tc.scan_mode,
        )


def _is_host_scan(task: ProbeTask) -> bool:
    """True when a task should trigger a full host discovery scan (by scan_mode, not priority)."""
    return task.scan_mode == "host_scan"


@dataclass(slots=True)
class SchedulerStats:
    """Execution metrics emitted by the scheduler.

    tasks: ProbeTasks dispatched (after _prepare_tasks()'s host-scan collapse),
    which may differ from the Planner's TestCase count. results: ProbeResults
    collected; a host-scan task expands into 0..N of them, so the two are
    different units.
    """

    tasks: int = 0
    results: int = 0
    retries: int = 0
    timeouts: int = 0
    avg_rtt_ms: float = 0.0


class ProbeScheduler:
    """Executes probe tasks with global and per-host concurrency controls."""

    def __init__(
        self,
        probes: dict[str, BaseProbe],
        timeout: float,
        rate_limit_ms: int,
        max_workers: int,
        max_host_parallel: int,
    ) -> None:
        self._probes = probes
        self._timeout = timeout
        self._rate_limit_ms = max(0, rate_limit_ms)
        self._max_workers = max(1, max_workers)
        self._max_host_parallel = max(1, max_host_parallel)

        self._rate_lock = threading.Lock()
        self._next_slot = 0.0

        self._host_locks: dict[str, threading.Semaphore] = defaultdict(
            lambda: threading.Semaphore(self._max_host_parallel)
        )

    def run(self, src_ip: str, tasks: list[ProbeTask]) -> tuple[list[ProbeResult], SchedulerStats]:
        """Run all tasks and return collected ProbeResult objects plus execution stats."""
        prepared = self._prepare_tasks(tasks)
        stats = SchedulerStats(tasks=len(prepared))
        collected: list[ProbeResult] = []
        stats_lock = threading.Lock()

        def worker(task: ProbeTask) -> list[ProbeResult]:
            primary_key = "nmap" if "nmap" in self._probes else task.proto
            probe_impl = self._probes.get(primary_key)
            if probe_impl is None:
                # Defensive guard: callers always include "nmap" in probes today.
                return []

            with self._host_locks[task.dst_ip]:
                if _is_host_scan(task) and hasattr(probe_impl, "scan_discovery"):
                    return self._run_host_scan(
                        src_ip=src_ip, task=task, probe_impl=probe_impl
                    )
                return [
                    self._run_task(
                        src_ip=src_ip,
                        task=task,
                        probe_impl=probe_impl,
                        primary_key=primary_key,
                        stats=stats,
                        stats_lock=stats_lock,
                    )
                ]

        with ThreadPoolExecutor(max_workers=self._max_workers) as pool:
            futures = [pool.submit(worker, task) for task in prepared]
            for future in as_completed(futures):
                collected.extend(future.result())

        for r in collected:
            if r.state == ProbeState.OPEN:
                enrich_service(r)

        self._finalise_stats(stats, collected)
        return collected, stats

    @staticmethod
    def _prepare_tasks(tasks: list[ProbeTask]) -> list[ProbeTask]:
        """Collapse discovery host-scan tasks to one scan per dst_ip.

        _run_host_scan always scans TCP, so dedup by dst_ip is correct; the
        highest-priority task is kept. Other tasks pass through unchanged.
        """
        host_scans: dict[str, ProbeTask] = {}
        passthrough: list[ProbeTask] = []

        for task in tasks:
            if not _is_host_scan(task):
                passthrough.append(task)
                continue
            existing = host_scans.get(task.dst_ip)
            if existing is None or task.priority > existing.priority:
                host_scans[task.dst_ip] = task

        return passthrough + list(host_scans.values())

    def _run_host_scan(
        self,
        src_ip: str,
        task: ProbeTask,
        probe_impl: BaseProbe,
    ) -> list[ProbeResult]:
        """Expand one discovery host into N ProbeResults via a TCP scan.

        Generic UDP discovery is not run: unsolicited UDP scans return ambiguous
        open|filtered far more often, with little policy-validation payoff. UDP
        is still validated when the policy declares a UDP rule (BaseProbe.probe()).
        Discovered ports inherit the task's strategy and context.
        """
        results = probe_impl.scan_discovery(
            src_ip=src_ip,
            dst_ip=task.dst_ip,
            proto="tcp",
            timeout=self._timeout,
        )
        for r in results:
            r.strategy = task.strategy
            r.context = task.context
        return results

    def _run_task(
        self,
        src_ip: str,
        task: ProbeTask,
        probe_impl: BaseProbe,
        primary_key: str,
        stats: SchedulerStats,
        stats_lock: threading.Lock,
    ) -> ProbeResult:
        """Execute one task with retry policy."""
        max_retries = self._retry_budget(task)
        attempts = max_retries + 1
        best_result: ProbeResult | None = None
        attempt_count = 0

        for attempt in range(attempts):
            self._apply_global_rate_limit()
            if primary_key == "nmap":
                result = probe_impl.probe(
                    src_ip=src_ip,
                    dst_ip=task.dst_ip,
                    port=task.dst_port,
                    timeout=self._timeout,
                    proto=task.proto,
                )
            else:
                result = probe_impl.probe(
                    src_ip=src_ip,
                    dst_ip=task.dst_ip,
                    port=task.dst_port,
                    timeout=self._timeout,
                )

            if (
                primary_key == "nmap"
                and task.proto == "tcp"
                and result.state == ProbeState.OPEN
                and "tcp_fallback" in self._probes
            ):
                fallback = self._probes["tcp_fallback"].probe(
                    src_ip=src_ip,
                    dst_ip=task.dst_ip,
                    port=task.dst_port,
                    timeout=self._timeout,
                )
                result.detail = f"{result.detail} | fallback:{fallback.state.value}"

            # Keep planning metadata in raw evidence for the OAE.
            result.strategy = task.strategy
            result.context = task.context
            attempt_count += 1
            if self._is_better_result(result, best_result):
                best_result = result

            if attempt < attempts - 1 and self._should_retry(task, result):
                with stats_lock:
                    if stats.retries >= MAX_RETRIES_PER_RUN:
                        break
                    stats.retries += 1
                # Small jitter/backoff to avoid repeating the same transient condition.
                time.sleep(0.05 + random.uniform(0.0, 0.1))
                continue
            break

        assert best_result is not None
        final_result = replace(best_result)
        if attempt_count > 1:
            if final_result.detail:
                final_result.detail = f"{final_result.detail} | attempts={attempt_count}"
            else:
                final_result.detail = f"attempts={attempt_count}"
        return final_result

    @staticmethod
    def _is_better_result(candidate: ProbeResult, current: ProbeResult | None) -> bool:
        if current is None:
            return True
        candidate_priority = STATE_PRIORITY.get(candidate.state, -1)
        current_priority = STATE_PRIORITY.get(current.state, -1)
        if candidate_priority > current_priority:
            return True
        if candidate_priority < current_priority:
            return False
        # Prefer latest observation when evidence strength is equivalent.
        return True

    def _apply_global_rate_limit(self) -> None:
        if self._rate_limit_ms <= 0:
            return

        interval = self._rate_limit_ms / 1_000
        with self._rate_lock:
            now = time.monotonic()
            if now < self._next_slot:
                time.sleep(self._next_slot - now)
            now = time.monotonic()
            self._next_slot = now + interval

    @staticmethod
    def _retry_budget(task: ProbeTask) -> int:
        if task.priority >= 90:
            return 2
        if task.priority >= 70:
            return 1
        return 0

    @staticmethod
    def _should_retry(task: ProbeTask, result: ProbeResult) -> bool:
        # Retry only uncertain outcomes.
        if result.state != ProbeState.FILTERED:
            return False

        # Retry only ambiguous FILTERED evidence.
        if not result.detail or "no-response" not in result.detail.lower():
            return False

        # Ignore low-value discovery noise.
        if task.strategy != "policy_validation":
            return False

        # Always retry transitive bypass checks.
        if task.context == "transitive_rule_bypass":
            return True

        # Risk-gated retries for policy validation.
        if task.context in {"segment_level", "host_constrained", "inter_segment"}:
            return task.priority >= 70

        return False

    @staticmethod
    def _finalise_stats(stats: SchedulerStats, results: list[ProbeResult]) -> None:
        stats.results = len(results)
        rtts = [r.rtt_ms for r in results if r.rtt_ms is not None]
        if rtts:
            stats.avg_rtt_ms = sum(rtts) / len(rtts)
        stats.timeouts = sum(
            1
            for r in results
            if "timeout" in r.detail.lower() or r.state == ProbeState.INCONCLUSIVE
        )
