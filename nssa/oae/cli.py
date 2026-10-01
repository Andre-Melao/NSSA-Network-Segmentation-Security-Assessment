from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path
from typing import TYPE_CHECKING

from nssa.oae.audit.serialization import serialize_audit_finding
from nssa.oae.engine import OAEEngine
from nssa.oae.reporting.pipeline import run_reporting
from nssa.shared.audit_config_parser import (
    AuditConfigValidationError,
    deployment_slice_bytes,
    extract_policy_raw,
    is_audit_configuration,
    parse_audit_config,
)
from nssa.shared.audit_config import extract_runtime_configuration
from nssa.shared.authentication_parser import AuthenticationValidationError
from nssa.shared.contracts import ContractViolation
from nssa.shared.deployment_parser import DeploymentValidationError
from nssa.shared.integrity import IntegrityError, compute_deployment_hash, load_verify_key
from nssa.shared.logging_config import configure_logging
from nssa.shared.spm_parser import SPMValidationError, parse_spm

if TYPE_CHECKING:
    from nacl.signing import VerifyKey

DEFAULT_TRUST_STORE = Path.home() / ".nssa" / "trust-store"


def _load_verify_keys(trust_store: Path) -> dict[str, "VerifyKey"]:
    if not trust_store.exists() or not trust_store.is_dir():
        raise FileNotFoundError(f"Trust store not found: {trust_store}")

    key_files = sorted(trust_store.glob("*.pub"))
    if not key_files:
        raise FileNotFoundError(f"No .pub keys found in trust store: {trust_store}")

    verify_keys: dict[str, "VerifyKey"] = {}
    for key_file in key_files:
        signer = key_file.stem
        verify_keys[signer] = load_verify_key(key_file)
    return verify_keys


def _collect_result_files(results_dir: Path) -> list[Path]:
    if not results_dir.exists() or not results_dir.is_dir():
        raise FileNotFoundError(f"Results directory not found: {results_dir}")

    result_files = sorted(results_dir.glob("*_results.json"))
    if not result_files:
        raise FileNotFoundError(f"No result files found in directory: {results_dir}")
    return result_files


def _print_banner(*, results_dir: Path, spm_path: Path, trust_store: Path) -> None:
    sys.stderr.write("\n")
    sys.stderr.write("╔══════════════════════════════════════════════╗\n")
    sys.stderr.write("║ NSSA OAE (Offline Analysis Engine)           ║\n")
    sys.stderr.write(f"║ Results : {str(results_dir):<35.35s}║\n")
    sys.stderr.write(f"║ SPM     : {str(spm_path):<35.35s}║\n")
    sys.stderr.write(f"║ Trust   : {str(trust_store):<35.35s}║\n")
    sys.stderr.write("╚══════════════════════════════════════════════╝\n")
    sys.stderr.flush()


def _build_summary(*, analysis, result_files: list[Path]) -> dict:
    """High-level execution summary for an auditor or LLM; implementation-level
    statistics belong in the detailed report sections."""
    return {
        "artifacts_ingested": len(result_files),
        "audit_findings": len(analysis.audit_findings),
    }


def _build_report_bundle(
    *,
    analysis,
    summary: dict,
    host_names: dict[str, str],
    dst_groups: dict[str, tuple[str, ...]] | None = None,
) -> dict:
    return {
        "summary": summary,
        "audit_findings": [
            serialize_audit_finding(f, host_names, dst_groups) for f in analysis.audit_findings
        ],
    }


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        prog="nssa-evaluate",
        description=(
            "NSSA OAE: validates signed APU artifacts and builds expected/observed matrices."
        ),
    )
    parser.add_argument(
        "results_dir",
        help="Path to the directory containing *_results.json files from all APUs.",
    )
    parser.add_argument(
        "spm",
        help=(
            "Path to the Segmentation Policy Model JSON file used by the "
            "APUs, or to a merged AuditConfiguration file (SPM + deployment "
            "+ authentication in one document -- see "
            "nssa.shared.audit_config_parser). Detected automatically; "
            "'authentication', if present, is never read by this tool."
        ),
    )
    parser.add_argument(
        "--trust-store",
        default=str(DEFAULT_TRUST_STORE),
        help=(
            "Directory with probe public keys (*.pub). File name stem must match "
            "artifact 'signed_by'."
        ),
    )
    parser.add_argument(
        "--output",
        default=None,
        help="Optional output JSON file for evaluation summary.",
    )
    parser.add_argument(
        "--report-output",
        default=None,
        help="Optional output JSON file for full audit report bundle.",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable debug logging.",
    )
    args = parser.parse_args(argv)

    configure_logging(verbose=args.verbose)
    logger = logging.getLogger("nssa.oae")

    results_dir = Path(args.results_dir)
    spm_path = Path(args.spm)
    trust_store = Path(args.trust_store)

    _print_banner(results_dir=results_dir, spm_path=spm_path, trust_store=trust_store)

    try:
        result_files = _collect_result_files(results_dir)
        verify_keys = _load_verify_keys(trust_store)

        # Read and parse the raw document once: deployment resolution, the
        # reporting hook (authentication section) and policy extraction all need it.
        spm_raw = json.loads(spm_path.read_bytes().decode("utf-8"))
        # extract_policy_raw() resolves merged-vs-standalone SPM shape ('policy'
        # key vs the document itself).
        policy = parse_spm(extract_policy_raw(spm_raw))
        audit_config = parse_audit_config(spm_raw) if is_audit_configuration(spm_raw) else None

        # None for a plain SPM with no embedded 'deployment': probe_groups stays
        # None and evaluation uses declared membership + CIDR resolution.
        deployment = None
        expected_deployment_hash: str | None = None
        if audit_config is not None:
            runtime = extract_runtime_configuration(audit_config)
            if runtime.deployment.probes:
                deployment = runtime.deployment
                expected_deployment_hash = compute_deployment_hash(
                    deployment_slice_bytes(spm_raw)
                )

        engine = OAEEngine(
            policy, deployment=deployment, expected_deployment_hash=expected_deployment_hash,
        )
        observed = engine.ingest(
            result_files=result_files, spm_path=spm_path, verify_keys=verify_keys,
        )
    except IntegrityError as exc:
        logger.error("Integrity error: %s", exc)
        sys.exit(2)
    except ContractViolation as exc:
        logger.error("Schema violation: %s", exc)
        sys.exit(3)
    except (
        SPMValidationError,
        DeploymentValidationError,
        AuthenticationValidationError,
        AuditConfigValidationError,
    ) as exc:
        # Catch parse errors here so a malformed section gives a clean CLI error,
        # not a traceback.
        logger.error("Configuration validation failed: %s", exc)
        sys.exit(1)
    except (FileNotFoundError, ValueError, RuntimeError) as exc:
        logger.error("Evaluation failed: %s", exc)
        sys.exit(1)

    analysis = engine.evaluate(observed)
    summary = _build_summary(analysis=analysis, result_files=result_files)

    if args.output:
        out_path = Path(args.output)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")
        logger.info("Summary written to %s", out_path)

    if args.report_output:
        # analysis.host_names is the resolution used for every AuditFinding
        # (declared servers plus "probe-<group(s)>"), reused so path hops resolve
        # identically.
        # Every group a destination belongs to: dst_segment is None for
        # multi-group destinations, so serialization prefers this mapping.
        dst_groups = {s.ip: policy.groups_for_ip(s.ip) for s in policy.servers}
        report_bundle = _build_report_bundle(
            analysis=analysis, summary=summary, host_names=analysis.host_names, dst_groups=dst_groups,
        )
        report_out_path = Path(args.report_output)
        report_out_path.parent.mkdir(parents=True, exist_ok=True)
        report_out_path.write_text(
            json.dumps(report_bundle, indent=2),
            encoding="utf-8",
        )
        logger.info("Report bundle written to %s", report_out_path)

        # Automatic: always writes a deterministic audit-report.md next to the raw
        # report JSON, and adds AI enrichment (.md/.html/.pdf) only when
        # authentication.llm is declared. run_reporting() catches and logs its
        # own failures; reporting never blocks this run.
        run_reporting(
            report_bundle, audit_config, report_out_path.parent,
            logger=logging.getLogger("nssa.oae.reporting"),
            policy_reference=spm_path.name,
        )

    logger.info("Evaluation input validation succeeded")
    logger.info("Artifacts ingested: %d (validated + trusted)", len(result_files))
    logger.info("Audit findings: %d", len(analysis.audit_findings))


if __name__ == "__main__":
    main()
