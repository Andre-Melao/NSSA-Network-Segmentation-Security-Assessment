"""nssa-run: coordination layer over the nssa-probe/nssa-evaluate pipeline.

Adds no audit logic: it builds a static ExecutionPlan (nssa.run.plan), runs it
(nssa.run.executor), then hands off to nssa.oae.cli.main() as an auditor
running nssa-evaluate by hand would. nssa-probe and nssa-evaluate remain
independently usable.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import tempfile
from pathlib import Path

from nssa.run import report
from nssa.run.executor import bootstrap_trust_store, execute_plan, missing_ssh_private_keys
from nssa.run.plan import PlanBuildError, build_execution_plan
from nssa.run.runners import ManualRunner, SSHRunner
from nssa.shared.audit_config_parser import (
    parse_audit_config,
    policy_slice_bytes,
    runtime_configuration_bytes,
)
from nssa.shared.integrity import compute_policy_hash
from nssa.shared.logging_config import configure_logging

# ── Internal tool state (never audit evidence), under ~/.nssa/ like probe.key.
# Safe to delete; recreated from the AuditConfiguration. The RuntimeConfiguration
# (policy + deployment, 'authentication' stripped) is not kept here: it is
# deterministic, so it lives only as a tempfile for this invocation.
DEFAULT_TRUST_STORE = Path.home() / ".nssa" / "trust-store"

# ── Audit evidence: in the working directory by default, to be archived with
# the AuditConfiguration.
DEFAULT_ARTIFACTS_DIR = "artifacts"
DEFAULT_REPORT_OUTPUT = str(Path("reports") / "audit-report-raw.json")


def _parse_name_set(value: str | None) -> frozenset[str] | None:
    if not value:
        return None
    return frozenset(name.strip() for name in value.split(",") if name.strip())


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        prog="nssa-run",
        description=(
            "NSSA audit coordination layer: coordinates collecting probe "
            "artifacts (manual or SSH, per-Probe -- see \"execution\" in "
            "the AuditConfiguration) and running nssa-evaluate, from a "
            "single AuditConfiguration. Does not replace nssa-probe or "
            "nssa-evaluate -- both remain fully supported and usable on "
            "their own."
        ),
    )
    parser.add_argument(
        "audit_config",
        help="Path to the AuditConfiguration JSON file.",
    )
    parser.add_argument(
        "--artifacts-dir",
        default=DEFAULT_ARTIFACTS_DIR,
        help=f"Directory where signed probe artifacts are expected/written -- audit evidence, meant to be "
             f"archived alongside the AuditConfiguration (default: {DEFAULT_ARTIFACTS_DIR}/).",
    )
    parser.add_argument(
        "--trust-store",
        default=str(DEFAULT_TRUST_STORE),
        help=f"Directory with probe public keys (*.pub), forwarded to nssa-evaluate unchanged -- internal "
             f"tool state, not audit evidence (default: {DEFAULT_TRUST_STORE}). Missing keys for SSH-mode "
             f"Probes are fetched automatically (see 'nssa-probe --get-pubkey'); manual-mode Probes still "
             f"need theirs collected by hand, exactly as before.",
    )
    parser.add_argument(
        "--report-output",
        default=DEFAULT_REPORT_OUTPUT,
        help=f"Where nssa-evaluate writes the full report bundle (default: {DEFAULT_REPORT_OUTPUT}).",
    )
    parser.add_argument(
        "--only",
        default=None,
        metavar="NAME,NAME,...",
        help="Comma-separated Probe names to include; every other declared Probe is excluded from the plan.",
    )
    parser.add_argument(
        "--skip",
        default=None,
        metavar="NAME,NAME,...",
        help="Comma-separated Probe names to exclude from the plan.",
    )
    parser.add_argument(
        "--require-all",
        action="store_true",
        help="Abort instead of proceeding to evaluation if any probe's artifact could not be collected.",
    )
    parser.add_argument(
        "--discovery",
        action="store_true",
        help=(
            "Request full (intra- and inter-segment) discovery from every "
            "SSH-mode Probe this run collects -- forwarded as nssa-probe's "
            "own --discovery flag. Off by default, same as nssa-probe "
            "itself; a Host Mode Probe already runs intra-segment discovery "
            "regardless of this flag (see nssa.apu.orchestrator), so this "
            "only adds inter-segment coverage for Host Mode, and both for "
            "Representative Mode. Manual-mode Probes are unaffected -- the "
            "printed instructions include --discovery so the auditor can "
            "mirror this themselves, but nssa-run cannot enforce what a "
            "manually-run command actually does."
        ),
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable debug logging.",
    )
    args = parser.parse_args(argv)

    configure_logging(verbose=args.verbose)
    logger = logging.getLogger("nssa.run")

    audit_config_path = Path(args.audit_config)
    artifacts_dir = Path(args.artifacts_dir)

    report.print_banner()

    # runtime_config_path is created in the try block below but must be cleaned
    # up on every exit path (PlanBuildError, empty plan, --require-all failure,
    # oae_main() exiting), hence one try/finally around the rest of main().
    runtime_config_path: Path | None = None
    try:
        try:
            raw_bytes = audit_config_path.read_bytes()
            raw = json.loads(raw_bytes.decode("utf-8"))
            # parse_audit_config() already validates across sections (ssh_profile references).
            config = parse_audit_config(raw)
            artifacts_dir.mkdir(parents=True, exist_ok=True)
            # Fail fast if *config* has no usable Deployment, before any hashing
            # (see PlanBuildError; specific to nssa-run).
            plan = build_execution_plan(
                config,
                artifacts_dir,
                only=_parse_name_set(args.only),
                skip=_parse_name_set(args.skip),
            )
            # A built plan means a merged config with a real Deployment; hash its
            # policy slice, as nssa-probe/nssa-evaluate do.
            expected_policy_hash = compute_policy_hash(policy_slice_bytes(raw))
            # The only bytes any Probe receives: policy + deployment with
            # 'authentication' stripped (see runtime_configuration_bytes()).
            # Written to a tempfile for ManualRunner's instructions (SSHRunner
            # gets the bytes directly) and deleted in the finally block.
            runtime_config_bytes = runtime_configuration_bytes(raw)
            fd, tmp_name = tempfile.mkstemp(prefix="nssa-run-runtime-", suffix=".json")
            with os.fdopen(fd, "wb") as f:
                f.write(runtime_config_bytes)
            runtime_config_path = Path(tmp_name)
        except PlanBuildError as exc:
            logger.error("Could not build execution plan: %s", exc)
            sys.exit(1)
        except Exception as exc:
            logger.error("Failed to load AuditConfiguration: %s", exc)
            sys.exit(1)

        if not plan.steps:
            logger.error("No probes to run (check deployment.probes and any --only/--skip filters).")
            sys.exit(1)

        report.print_plan(plan, expected_policy_hash)

        ssh_profiles = config.authentication.ssh_profiles if config.authentication else {}

        # Fatal and upfront: a missing private_key is a configuration problem to fix.
        key_errors = missing_ssh_private_keys(plan, ssh_profiles)
        if key_errors:
            for error in key_errors:
                logger.error(error)
            sys.exit(1)

        runners = {
            "manual": ManualRunner(),
            "ssh": SSHRunner(
                ssh_profiles=ssh_profiles, runtime_config_bytes=runtime_config_bytes,
                discovery=args.discovery,
            ),
        }

        # Removes the manual "nssa-probe --get-pubkey" step for SSH-mode Probes;
        # manual-mode Probes still print it (ManualRunner.instructions()). The
        # trust-store format is the same either way.
        trust_store_dir = Path(args.trust_store)
        ssh_step_count = sum(1 for s in plan.steps if s.probe.execution == "automated")
        if ssh_step_count:
            report.print_trust_store_bootstrap_start()
            bootstrap_trust_store(
                plan, trust_store_dir, runners["ssh"],
                on_missing=report.print_trust_store_fetch_start,
                on_fetched=report.print_trust_store_fetched,
                on_failed=report.print_trust_store_fetch_failed,
            )

        outcomes = execute_plan(
            plan,
            expected_policy_hash,
            runners,
            render_instructions=lambda steps: report.render_manual_instructions(
                steps, runtime_config_path, discovery=args.discovery, trust_store_dir=trust_store_dir,
            ),
            confirm=report.confirm,
            before_ssh_step=report.print_ssh_step_start,
        )

        report.print_collection_summary(outcomes)

        missing = [o for o in outcomes if o.status == "failed"]
        if missing:
            if args.require_all:
                logger.error(
                    "Missing probe artifact(s): %s (--require-all set, aborting)",
                    ", ".join(o.probe_name for o in missing),
                )
                sys.exit(1)
            if not report.confirm_partial([o.probe_name for o in missing]):
                logger.info("Aborted by auditor.")
                sys.exit(1)

        report.print_evaluation_start()

        # Exactly what nssa-evaluate would do by hand; all validation stays in the
        # OAE. May sys.exit() on failure, deliberately left to propagate.
        from nssa.oae.cli import main as oae_main

        oae_argv = [
            str(artifacts_dir),
            str(audit_config_path),
            "--trust-store",
            args.trust_store,
            "--report-output",
            args.report_output,
        ]
        oae_main(oae_argv)

        report.print_evaluation_done(args.report_output)
    finally:
        if runtime_config_path is not None:
            runtime_config_path.unlink(missing_ok=True)


if __name__ == "__main__":
    main()
