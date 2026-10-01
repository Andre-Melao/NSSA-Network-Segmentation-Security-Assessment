"""Executor: decides whether each ProbeExecutionStep still needs to run,
dispatches to the right ProbeRunner, and reports what happened.

"Already collected"/"pending"/"resume" logic lives here, not in nssa.run.plan
(a static description) or in a ProbeRunner. Nothing is printed here:
render_instructions/confirm are injected callables (wired by nssa.run.cli), so
execute_plan() is testable without real stdin/stdout.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from nssa.run.plan import ExecutionPlan, ProbeExecutionStep
from nssa.run.runners import ProbeRunner, SSHRunner, StepOutcome
from nssa.shared.authentication import SSHAuth
from nssa.shared.contracts import strip_artifact_markers


@dataclass(frozen=True, slots=True)
class ArtifactCheckResult:
    """Whether an existing artifact at a step's expected path counts as "already collected".

    ok=True requires the file to exist, parse as JSON (after stripping
    stdout-mode markers), and have a 'probe_id' matching the step's Probe and a
    'policy_hash' matching the current AuditConfiguration. A cheap sanity check,
    not a trust boundary; signature verification stays with the OAE.
    """

    ok: bool
    reason: str | None = None


def check_existing_artifact(step: ProbeExecutionStep, expected_policy_hash: str) -> ArtifactCheckResult:
    if not step.artifact_path.exists():
        return ArtifactCheckResult(ok=False)

    try:
        raw_text = strip_artifact_markers(step.artifact_path.read_text(encoding="utf-8"))
        raw = json.loads(raw_text)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        return ArtifactCheckResult(ok=False, reason=f"existing file is not a readable artifact ({exc})")

    if not isinstance(raw, dict):
        return ArtifactCheckResult(ok=False, reason="existing file is not a JSON object")

    artifact_probe_id = raw.get("probe_id")
    if artifact_probe_id != step.probe.name:
        return ArtifactCheckResult(
            ok=False,
            reason=f"existing artifact belongs to probe_id '{artifact_probe_id}', expected '{step.probe.name}'",
        )

    if raw.get("policy_hash") != expected_policy_hash:
        return ArtifactCheckResult(
            ok=False,
            reason="existing artifact's policy_hash does not match the current AuditConfiguration",
        )

    return ArtifactCheckResult(ok=True)


def execute_plan(
    plan: ExecutionPlan,
    expected_policy_hash: str,
    runners: dict[str, ProbeRunner],
    *,
    render_instructions: Callable[[list[ProbeExecutionStep]], None] = lambda steps: None,
    confirm: Callable[[str], None] = lambda message: input(f"\n{message} "),
    before_ssh_step: Callable[[ProbeExecutionStep], None] = lambda step: None,
) -> list[StepOutcome]:
    """Run every pending step in *plan*, skipping already-collected ones.

    Manual steps are one batch: instructions rendered once (render_instructions),
    one confirmation (confirm), then each re-validated, re-prompting only for
    those still missing (no polling or timeout). SSH steps run sequentially;
    before_ssh_step() is for progress reporting only.
    """
    outcomes: list[StepOutcome] = []
    pending: list[ProbeExecutionStep] = []

    for step in plan.steps:
        if check_existing_artifact(step, expected_policy_hash).ok:
            outcomes.append(StepOutcome(probe_name=step.probe.name, status="already_collected"))
        else:
            pending.append(step)

    manual_steps = [s for s in pending if s.probe.execution == "manual"]
    ssh_steps = [s for s in pending if s.probe.execution == "automated"]

    if manual_steps:
        render_instructions(manual_steps)
        confirm("Press ENTER once all manual artifacts have been collected.")
        still_missing = [
            s for s in manual_steps if not check_existing_artifact(s, expected_policy_hash).ok
        ]
        while still_missing:
            names = ", ".join(s.probe.name for s in still_missing)
            confirm(f"Still missing: {names}. Press ENTER once ready (Ctrl+C to abort).")
            still_missing = [
                s for s in manual_steps if not check_existing_artifact(s, expected_policy_hash).ok
            ]
        for step in manual_steps:
            outcomes.append(runners["manual"].run(step))

    for step in ssh_steps:
        before_ssh_step(step)
        outcomes.append(runners["ssh"].run(step))

    return outcomes


def missing_ssh_private_keys(plan: ExecutionPlan, ssh_profiles: dict[str, SSHAuth]) -> list[str]:
    """Human-readable errors for SSH-mode Probes whose ssh_profile private_key
    does not exist on disk; empty if all declared keys exist.

    A configuration problem caught once upfront (fatal in nssa.run.cli). A Probe
    with no ssh_profile or no private_key is fine (ambient SSH config is used).
    """
    errors: list[str] = []
    for step in plan.steps:
        probe = step.probe
        if probe.execution != "automated" or probe.ssh_profile is None:
            continue
        profile = ssh_profiles.get(probe.ssh_profile)
        if profile is None or not profile.private_key:
            continue
        key_path = Path(profile.private_key).expanduser()
        if not key_path.exists():
            errors.append(
                f"Probe '{probe.name}': ssh_profile '{probe.ssh_profile}' declares "
                f"private_key '{profile.private_key}' (resolved: {key_path}), which does not exist"
            )
    return errors


def bootstrap_trust_store(
    plan: ExecutionPlan,
    trust_store_dir: Path,
    ssh_runner: SSHRunner,
    *,
    on_missing: Callable[[ProbeExecutionStep], None] = lambda step: None,
    on_fetched: Callable[[ProbeExecutionStep, Path], None] = lambda step, path: None,
    on_failed: Callable[[ProbeExecutionStep], None] = lambda step: None,
) -> None:
    """Fetch each SSH-mode Probe's public key into trust_store_dir if absent,
    via "nssa-probe --get-pubkey" (SSHRunner.fetch_pubkey()).

    Manual-mode Probes are left to the auditor. Idempotent: an existing
    "<probe-name>.pub" is never re-fetched. A failed fetch is reported
    (on_failed) and otherwise ignored; nssa-evaluate raises its own trust-store
    error later. Never raises, and never verifies the key.
    """
    ssh_steps = [s for s in plan.steps if s.probe.execution == "automated"]
    if not ssh_steps:
        return

    trust_store_dir.mkdir(parents=True, exist_ok=True)
    for step in ssh_steps:
        pub_path = trust_store_dir / f"{step.probe.name}.pub"
        if pub_path.exists():
            continue
        on_missing(step)
        pubkey = ssh_runner.fetch_pubkey(step)
        if pubkey is None:
            on_failed(step)
            continue
        pub_path.write_bytes(pubkey)
        on_fetched(step, pub_path)
