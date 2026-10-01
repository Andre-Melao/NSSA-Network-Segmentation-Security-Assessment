"""ExecutionPlan: a pure, static description of what an audit run needs.

Carries no execution state: build_execution_plan() never touches the filesystem
and gives the same plan for the same AuditConfiguration and --only/--skip
filters. The executor decides whether a step still needs to run (see
check_existing_artifact()), so a probe collected by hand mid-run is picked up
correctly.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from nssa.shared.audit_config import AuditConfiguration
from nssa.shared.deployment import ProbeConfig


@dataclass(frozen=True, slots=True)
class ProbeExecutionStep:
    """One Probe this audit run needs an artifact from.

    probe          - the declared ProbeConfig, as parsed.
    artifact_path  - where the artifact should end up:
                     results_dir / "<probe.name>_results.json", the name
                     ProbeResults.save() produces for a named Probe.
    """

    probe: ProbeConfig
    artifact_path: Path


@dataclass(frozen=True, slots=True)
class ExecutionPlan:
    """A static description of one audit run; never mutated after construction."""

    steps: tuple[ProbeExecutionStep, ...]
    results_dir: Path


class PlanBuildError(Exception):
    """Raised when an AuditConfiguration cannot be turned into a plan.

    - No Deployment probes. nssa-probe and nssa-evaluate accept a deployment-less
      config, but nssa-run exists to coordinate declared Probes. Enforced only
      here, not in audit_config_parser.

    - A declared Probe with no 'name'. nssa-run must predict each artifact
      filename (results_dir/<name>_results.json), and an unnamed Probe's probe_id
      falls back to the remote hostname, unknown in advance. A limit of this
      layer only.
    """


def build_execution_plan(
    config: AuditConfiguration,
    results_dir: Path,
    *,
    only: frozenset[str] | None = None,
    skip: frozenset[str] | None = None,
) -> ExecutionPlan:
    """Build the static plan for *config*, optionally filtered by name.

    only: keep only Probes whose name is in this set.
    skip: drop Probes whose name is in this set; applied after *only*, so skip wins.

    Raises PlanBuildError if config.deployment.probes is empty or a Probe has
    no name.
    """
    if not config.deployment.probes:
        raise PlanBuildError(
            "nssa-run requires an AuditConfiguration with at least one "
            "declared Probe in deployment.probes[] -- found none. "
            "nssa-probe and nssa-evaluate both support a traditional, "
            "deployment-less SPM file directly; nssa-run does not, since "
            "its whole purpose is coordinating Probe execution from a "
            "Deployment. Add a \"deployment\" section declaring at least "
            "one Probe, or invoke nssa-probe/nssa-evaluate directly "
            "instead of nssa-run."
        )

    probes = config.deployment.probes
    if only is not None:
        probes = tuple(p for p in probes if p.name in only)
    if skip is not None:
        probes = tuple(p for p in probes if p.name not in skip)

    steps = []
    for probe in probes:
        if not probe.name:
            raise PlanBuildError(
                "nssa-run requires every Probe to declare a 'name' in "
                "deployment.probes[] -- found one with none. Add an "
                "explicit \"name\" so its artifact's filename can be "
                "predicted ahead of time."
            )
        steps.append(
            ProbeExecutionStep(
                probe=probe,
                artifact_path=results_dir / f"{probe.name}_results.json",
            )
        )

    return ExecutionPlan(steps=tuple(steps), results_dir=results_dir)
