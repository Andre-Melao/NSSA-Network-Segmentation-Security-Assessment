"""Presentation layer for nssa-run.

All formatting and printing lives here, separate from plan/executor/runners.
nssa.run.executor never imports this module (it takes injected callables); this
module imports check_existing_artifact() only to render status.

Output goes to stderr, like nssa-probe/nssa-evaluate, so stdout stays free for
redirection.
"""

from __future__ import annotations

import sys
from pathlib import Path

from nssa.run.executor import check_existing_artifact
from nssa.run.plan import ExecutionPlan, ProbeExecutionStep
from nssa.run.runners import ManualRunner, StepOutcome

_WIDTH = 40


def _write(text: str = "") -> None:
    sys.stderr.write(text + "\n")


def print_banner() -> None:
    _write("=" * _WIDTH)
    _write("NSSA Audit")
    _write("=" * _WIDTH)
    _write()
    sys.stderr.flush()


def print_plan(plan: ExecutionPlan, expected_policy_hash: str) -> None:
    """Print the initial plan, with each step's current resume status."""
    _write("✓ AuditConfiguration loaded")
    _write(f"✓ {len(plan.steps)} probe(s) discovered")
    _write("-" * _WIDTH)

    manual = [s for s in plan.steps if s.probe.execution == "manual"]
    ssh = [s for s in plan.steps if s.probe.execution == "automated"]

    if manual:
        _write("Manual probes")
        for step in manual:
            _print_step_status(step, expected_policy_hash)
        _write("-" * _WIDTH)

    if ssh:
        _write("Automated probes")
        for step in ssh:
            _print_step_status(step, expected_policy_hash)
        _write("-" * _WIDTH)

    sys.stderr.flush()


def _step_label(step: ProbeExecutionStep) -> str:
    label = step.probe.name
    if step.probe.probing_mode == "host":
        label += " (host)"
    return label


def _print_step_status(step: ProbeExecutionStep, expected_policy_hash: str) -> None:
    label = _step_label(step)
    check = check_existing_artifact(step, expected_policy_hash)
    if check.ok:
        _write(f"✓ {label} (already collected)")
    elif check.reason:
        _write(f"⚠ {label} -- {check.reason}, will re-collect")
    else:
        _write(f"○ {label}")


def render_manual_instructions(
    steps: list[ProbeExecutionStep], runtime_config_path: Path, *,
    discovery: bool = False, trust_store_dir: Path | None = None,
) -> None:
    """The default render_instructions callback for execute_plan().

    runtime_config_path is the tempfile holding the RuntimeConfiguration (never
    the original AuditConfiguration). discovery mirrors --discovery into the
    printed commands (nssa-run cannot enforce what is typed by hand).
    trust_store_dir adds a key-registration step for Probes whose key is
    missing (see ManualRunner.instructions()).
    """
    _write()
    _write("=" * _WIDTH)
    _write("Manual probes")
    _write("=" * _WIDTH)
    _write("The following probes require manual execution. You may either:")
    _write("  • SSH into the probe and execute NSSA manually")
    _write("or")
    _write("  • Access the probe locally and execute NSSA directly from the machine.")
    _write()
    runner = ManualRunner()
    for step in steps:
        _write(runner.instructions(
            step, runtime_config_path, discovery=discovery, trust_store_dir=trust_store_dir,
        ))
        _write()
    sys.stderr.flush()


def confirm(message: str) -> None:
    """The default confirm callback wired into execute_plan()."""
    input(f"\n{message} ")


def print_ssh_step_start(step: ProbeExecutionStep) -> None:
    """The default before_ssh_step callback for execute_plan().

    Says "running", not "connecting": the message stays on screen for the whole
    remote run (SSHRunner.run() blocks), and "connecting" would look stalled.
    """
    _write(f"-> {step.probe.name} ({step.probe.ip}): running via ssh (this may take a while)...")
    sys.stderr.flush()


def print_trust_store_bootstrap_start() -> None:
    _write("Bootstrapping trust store...")
    sys.stderr.flush()


def print_trust_store_fetch_start(step: ProbeExecutionStep) -> None:
    """The default on_missing callback wired into bootstrap_trust_store()."""
    _write(f"-> {step.probe.name}: fetching public key...")
    sys.stderr.flush()


def print_trust_store_fetched(step: ProbeExecutionStep, path: Path) -> None:
    """The default on_fetched callback wired into bootstrap_trust_store()."""
    _write(f"   saved {path}")
    sys.stderr.flush()


def print_trust_store_fetch_failed(step: ProbeExecutionStep) -> None:
    """The default on_failed callback wired into bootstrap_trust_store()."""
    _write(f"   could not fetch a public key for {step.probe.name} -- nssa-evaluate may reject its artifact")
    sys.stderr.flush()


def print_collection_summary(outcomes: list[StepOutcome]) -> None:
    _write("-" * _WIDTH)
    collected = [o for o in outcomes if o.status in ("completed", "already_collected")]
    missing = [o for o in outcomes if o.status == "failed"]
    _write("Collected:")
    for o in collected:
        suffix = f" ({o.detail})" if o.detail else ""
        _write(f"  ✓ {o.probe_name}{suffix}")
    if missing:
        _write("Missing:")
        for o in missing:
            suffix = f" -- {o.detail}" if o.detail else ""
            _write(f"  ○ {o.probe_name}{suffix}")
    sys.stderr.flush()


def confirm_partial(missing_names: list[str]) -> bool:
    """Ask whether to evaluate with a partial artifact set (only called when a probe is missing)."""
    _write()
    _write("Evaluation will proceed using the collected artifacts.")
    _write("Missing probes:")
    for name in missing_names:
        _write(f"  - {name}")
    sys.stderr.flush()
    answer = input("Continue? [Y/n] ").strip().lower()
    return answer in ("", "y", "yes")


def print_evaluation_start() -> None:
    _write("-" * _WIDTH)
    _write("Running evaluation...")
    sys.stderr.flush()


# Written by run_reporting(): always audit-report.md, plus .html/.pdf when
# authentication.llm is declared and rendering succeeds. Checked on disk rather
# than returned through oae_main(), as the names are a fixed contract.
_REPORTING_DELIVERABLE_NAMES = ("audit-report.md", "audit-report.html", "audit-report.pdf")


def print_evaluation_done(report_path: str) -> None:
    _write("✓ Completed")
    _write()
    _write("Report written to:")
    _write(f"  {report_path}")
    reports_dir = Path(report_path).parent
    for name in _REPORTING_DELIVERABLE_NAMES:
        candidate = reports_dir / name
        if candidate.exists():
            _write(f"  {candidate}")
    _write()
    _write("Audit completed.")
    sys.stderr.flush()
