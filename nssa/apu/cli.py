"""NSSA Probe: runs connectivity checks and exports a signed artifact.

All I/O flows over the SSH session (stdout = artifact, stderr = logs). The key
pair is auto-generated on first run at ~/.nssa/probe.key.

Usage::

    # First time on a new probe: generate key and save the public key
    ssh probe-vm "nssa-probe --get-pubkey" > trust-store/probe-vm.pub

    # Every audit run ("-" reads the SPM/AuditConfiguration from stdin)
    ssh probe-vm "nssa-probe policy.json" > results.json
    ssh probe-vm "nssa-probe -" < audit-config.json > results.json

    # Other options
    nssa-probe policy.json --export /tmp/results    # file mode
    nssa-probe policy.json --no-sign               # skip signing
    nssa-probe policy.json --segment users --src-ip 10.10.10.10

A merged AuditConfiguration (see nssa.shared.audit_config_parser) is also
accepted: its 'deployment' section is resolved automatically and
'authentication' never leaves the auditor's machine.
"""

from __future__ import annotations

import argparse
import logging
import sys
import time
from pathlib import Path

# Default Ed25519 private key, auto-generated on first run.
DEFAULT_KEY_PATH = Path.home() / ".nssa" / "probe.key"


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        prog="nssa-probe",
        description=(
            "NSSA Probe: auto-detects the local segment "
            "and probes connectivity according to the SPM."
        ),
    )

    # ── Positional: the SPM file (optional with --get-pubkey) ──
    parser.add_argument(
        "spm",
        nargs="?",
        default=None,
        help=(
            "Path to the Segmentation Policy Model JSON file, or to a "
            "merged AuditConfiguration file (SPM + deployment + "
            "authentication in one document -- see "
            "nssa.shared.audit_config_parser). Detected automatically. "
            "Use '-' to read from stdin (recommended, portable); "
            "/dev/stdin also still works."
        ),
    )

    # ── Optional tuning ──
    parser.add_argument(
        "--export",
        default=None,
        help=(
            "Where to write the result artifact. Omit the flag to write "
            "to stdout (ideal for SSH piping)."
            "Otherwise, provide a directory "
            "path after the flag."
        ),
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=2.0,
        help="Per-probe timeout in seconds (default: 2.0).",
    )
    parser.add_argument(
        "--rate-limit",
        type=int,
        default=50,
        help="Minimum ms between probes (default: 50).",
    )
    parser.add_argument(
        "--max-workers",
        type=int,
        default=50,
        help="Max concurrent probe workers (default: 50).",
    )
    parser.add_argument(
        "--max-host-parallel",
        type=int,
        default=5,
        help="Max concurrent probes per destination host (default: 5).",
    )
    parser.add_argument(
        "--discovery",
        action="store_true",
        help=(
            "Enable phase-4 lateral visibility probes (off by default -- "
            "NSSA is policy-driven, so an audit run only tests what the SPM "
            "declares unless this is explicitly requested)."
        ),
    )
    parser.add_argument(
        "--no-lateral-discovery",
        action="store_true",
        help=(
            "Explicitly disable discovery for this run, overriding --discovery "
            "if both are given. Discovery is already off by default, so this "
            "is rarely needed by hand -- Host Mode orchestration passes it to "
            "every remote workload it runs so a workload's own default can "
            "never silently disagree with the locally selected setting."
        ),
    )
    parser.add_argument(
        "--intra-segment-discovery",
        action="store_true",
        help=(
            "Enable intra-segment discovery only (never inter-segment), "
            "independent of --discovery. Off by default here too -- the only "
            "current caller is nssa.apu.orchestrator's own Host Mode fan-out, "
            "which always passes this to every workload it runs remotely."
        ),
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable debug logging.",
    )

    # ── Deployment (optional; resolves groups/src_ip/probe_id) ──
    parser.add_argument(
        "--probe-name",
        default=None,
        metavar="NAME",
        help=(
            "Which declared Probe in 'spm's embedded 'deployment' section "
            "this run corresponds to. Only needed when the deployment "
            "declares more than one probe."
        ),
    )

    # ── Host Mode orchestration (only when the Probe's probing_mode is "host") ──
    parser.add_argument(
        "--max-parallel-sessions",
        type=int,
        default=10,
        help="Host Mode only: max concurrent SSH sessions to workloads (default: 10).",
    )
    parser.add_argument(
        "--ssh-connect-timeout",
        type=float,
        default=10.0,
        help=(
            "Host Mode only: max seconds for TCP connect + SSH handshake to "
            "a workload (default: 10.0). Does not bound the remote "
            "nssa-probe run itself -- see --remote-execution-timeout."
        ),
    )
    parser.add_argument(
        "--remote-execution-timeout",
        type=float,
        default=1800.0,
        help=(
            "Host Mode only: upper bound in seconds for a workload's SSH "
            "session plus its entire remote nssa-probe run (default: "
            "1800.0 / 30 min). A deadlock safety net, not a normal-"
            "completion bound -- the remote run already has its own "
            "controls (--timeout/--rate-limit/--max-workers/"
            "--max-host-parallel). Should never fire during a legitimate "
            "run; only lower it if you have a specific reason to want "
            "hung workloads detected sooner."
        ),
    )
    parser.add_argument(
        "--ssh-retries",
        type=int,
        default=1,
        help="Host Mode only: retries per workload on SSH/response failure (default: 1).",
    )
    parser.add_argument(
        "--ssh-user",
        default="root",
        help="Host Mode only: SSH user for workload connections (default: root).",
    )

    # ── Manual overrides ──
    parser.add_argument(
        "--segment",
        default=None,
        help=(
            "Override auto-detection: force segment name.  "
            "Source IP is inferred from local interfaces if "
            "--src-ip is not given. Takes precedence over a resolved Deployment."
        ),
    )
    parser.add_argument(
        "--src-ip",
        default=None,
        help="Override auto-detection: force source IP. Takes precedence over a resolved Deployment.",
    )
    # ── Artifact signing (on by default) ──
    parser.add_argument(
        "--get-pubkey",
        action="store_true",
        help=(
            "Generate the key pair if needed, then print the public key "
            "to stdout and exit.  Redirect to a file on the OAE machine: "
            "ssh probe 'nssa-probe --get-pubkey' > trust-store/probe.pub"
        ),
    )
    parser.add_argument(
        "--no-sign",
        action="store_true",
        help="Disable artifact signing (not recommended).",
    )
    parser.add_argument(
        "--sign-with",
        default=None,
        metavar="KEY_FILE",
        help=f"Override the signing key path (default: {DEFAULT_KEY_PATH}).",
    )
    parser.add_argument(
        "--probe-id",
        default=None,
        metavar="ID",
        help="Probe identifier stored in the artifact (default: hostname).",
    )
    args = parser.parse_args(argv)
    # ── --get-pubkey: generate key if needed, print pubkey, exit ──
    if args.get_pubkey:
        import base64
        from nssa.shared.integrity import generate_key_pair, load_signing_key
        key_path = Path(args.sign_with) if args.sign_with else DEFAULT_KEY_PATH
        if not key_path.exists():
            generate_key_pair(key_path)
        pub_path = key_path.with_suffix(key_path.suffix + ".pub")
        pub_b64 = base64.b64encode(pub_path.read_bytes()).decode("ascii")
        sys.stdout.write("-----BEGIN NSSA PUBLIC KEY-----\n")
        sys.stdout.write(f"{pub_b64}\n")
        sys.stdout.write("-----END NSSA PUBLIC KEY-----\n")
        sys.stdout.flush()
        return

    if not args.spm:
        parser.error("the following argument is required: spm")

    # ── Logging ──
    from nssa.shared.logging_config import configure_logging

    configure_logging(verbose=args.verbose)
    logger = logging.getLogger("nssa.probe")

    # ── Load SPM / AuditConfiguration ──
    # Read the raw bytes once (stdin can be read only once). "-" is the portable
    # stdin sentinel; /dev/stdin still works.
    #
    # args.spm is a plain SPM or a merged AuditConfiguration (detected by
    # is_audit_configuration()). For a merged file, spm_bytes is
    # policy_slice_bytes(raw), not raw_bytes, so 'authentication' is never
    # hashed into policy_hash or forwarded to a Host Mode workload.
    from nssa.shared.spm_parser import parse_spm
    from nssa.shared.integrity import compute_policy_hash, compute_deployment_hash
    from nssa.shared.audit_config_parser import (
        is_audit_configuration,
        parse_audit_config,
        policy_slice_bytes,
        deployment_slice_bytes,
    )
    from nssa.shared.audit_config import extract_runtime_configuration
    import json

    embedded_deployment = None
    embedded_deployment_hash = None
    try:
        raw_bytes = sys.stdin.buffer.read() if args.spm == "-" else Path(args.spm).read_bytes()
        raw = json.loads(raw_bytes.decode("utf-8"))
        if is_audit_configuration(raw):
            audit_config = parse_audit_config(raw)
            runtime = extract_runtime_configuration(audit_config)
            policy = runtime.policy
            spm_bytes = policy_slice_bytes(raw)
            if runtime.deployment.probes:
                embedded_deployment = runtime.deployment
                embedded_deployment_hash = compute_deployment_hash(deployment_slice_bytes(raw))
        else:
            policy = parse_spm(raw)
            spm_bytes = raw_bytes
        policy_hash = compute_policy_hash(spm_bytes)
    except Exception as exc:
        logger.error("Failed to load SPM: %s", exc)
        sys.exit(1)

    # ── Load Deployment (optional) ──
    # Without one, groups/src_ip resolve via --segment/--src-ip or
    # auto-detection and the artifact has no deployment_hash.
    deployment = embedded_deployment
    deployment_hash = embedded_deployment_hash

    # ── Build engine or dispatch to Host Mode orchestration ──
    from nssa.apu.engine import APUConfig, APUEngine, resolve_probe_config

    stdout_mode = args.export is None

    config = APUConfig(
        timeout=args.timeout,
        rate_limit_ms=args.rate_limit,
        output_dir="results" if stdout_mode else args.export,
        max_workers=args.max_workers,
        max_host_parallel=args.max_host_parallel,
        # --no-lateral-discovery overrides --discovery; Host Mode uses it to pin
        # the setting on every remote invocation.
        enable_lateral_discovery=args.discovery and not args.no_lateral_discovery,
        enable_intra_segment_discovery=args.intra_segment_discovery,
    )
    export_label = "stdout" if stdout_mode else str(args.export)

    try:
        probe_config = resolve_probe_config(deployment, args.probe_name)
    except Exception as exc:
        logger.error("Probe initialisation failed: %s", exc)
        sys.exit(1)

    if probe_config is not None and probe_config.probing_mode == "host":
        # Host Mode: orchestrate the APU remotely, once per workload
        # (nssa.apu.orchestrator); APUEngine is not constructed here.
        from nssa.apu.orchestrator import OrchestratorConfig, run_host_mode

        probe_id = args.probe_id or probe_config.name or "cloud-probe"
        sys.stderr.write("╔══════════════════════════════════════════════╗\n")
        sys.stderr.write("║  NSSA - Probe (Host Mode)                    ║\n")
        sys.stderr.write(f"║  Probe   : {probe_id:<33s}║\n")
        sys.stderr.write(f"║  Groups  : {','.join(probe_config.groups):<33s}║\n")
        sys.stderr.write(f"║  Vantage : {probe_config.ip or '?':<33s}║\n")
        sys.stderr.write(f"║  Export  : {export_label:<33s}║\n")
        sys.stderr.write("╚══════════════════════════════════════════════╝\n")
        sys.stderr.flush()

        try:
            results = run_host_mode(
                policy=policy,
                deployment=deployment,
                probe_config=probe_config,
                spm_bytes=spm_bytes,
                config=config,
                orchestrator_config=OrchestratorConfig(
                    max_parallel_sessions=args.max_parallel_sessions,
                    ssh_connect_timeout=args.ssh_connect_timeout,
                    remote_execution_timeout=args.remote_execution_timeout,
                    ssh_retries=args.ssh_retries,
                    ssh_user=args.ssh_user,
                ),
                probe_id=probe_id,
                deployment_hash=deployment_hash,
            )
        except Exception as exc:
            logger.error("Host Mode orchestration failed: %s", exc)
            sys.exit(1)
    else:
        try:
            engine = APUEngine(
                policy=policy,
                config=config,
                segment_override=args.segment,
                src_ip_override=args.src_ip,
                deployment=deployment,
                deployment_hash=deployment_hash,
                probe_name=args.probe_name,
                probe_id_override=args.probe_id,
            )
        except Exception as exc:
            logger.error("Probe initialisation failed: %s", exc)
            sys.exit(1)

        sys.stderr.write("╔══════════════════════════════════════════════╗\n")
        sys.stderr.write("║  NSSA - Probe (Active Probe Unit)            ║\n")
        sys.stderr.write(f"║  Probe   : {engine.probe_id:<33s}║\n")
        sys.stderr.write(f"║  Groups  : {','.join(engine.groups):<33s}║\n")
        sys.stderr.write(f"║  Vantage : {engine.src_ip:<33s}║\n")
        sys.stderr.write(f"║  Export  : {export_label:<33s}║\n")
        sys.stderr.write("╚══════════════════════════════════════════════╝\n")
        sys.stderr.flush()

        # Same running/completed log lines as Host Mode's per-workload runs.
        logger.info("-> %s (%s): running...", engine.probe_id, engine.src_ip)
        _start = time.time()
        results = engine.run(save=not stdout_mode)
        logger.info(
            "%s (%s): completed (%.1fs, %d probe(s))",
            engine.probe_id, engine.src_ip, time.time() - _start, len(results.probes),
        )

    # ── Artifact signing ──
    # Uses DEFAULT_KEY_PATH unless --sign-with is given; a missing key is
    # auto-generated. probe_id is already set on results by APUEngine.
    if not args.no_sign:
        from nssa.shared.integrity import generate_key_pair, load_signing_key
        key_path = Path(args.sign_with) if args.sign_with else DEFAULT_KEY_PATH
        if not key_path.exists():
            generate_key_pair(key_path)
            logger.warning(
                "Key pair generated at '%s'. "
                "Run 'nssa-probe --get-pubkey' to retrieve the public key "
                "and register it in the OAE trust store.",
                key_path,
            )
        try:
            results.signing_key = load_signing_key(key_path)
            results.policy_hash = policy_hash
        except Exception as exc:
            logger.error("Failed to load signing key: %s", exc)
            sys.exit(1)
    else:
        logger.warning("Signing disabled (--no-sign). OAE cannot verify integrity.")

    # ── Export artifact ──
    if stdout_mode:
        # Artifact to stdout
        results.to_stdout()
        # Completion message goes to stderr so redirected stdout stays clean.
        sys.stderr.write(f"\nProbe complete: {len(results.probes)} probes.\n")
        sys.stderr.write("  Artifact written to stdout.\n")
        sys.stderr.flush()
    else:
        # File mode: write the artifact to a file, print completion to stdout.
        out_path = results.save(args.export)
        sys.stdout.write(f"\nProbe complete: {len(results.probes)} probes recorded.\n")
        sys.stdout.write(f"  Artifact written to {out_path}\n")
        sys.stdout.flush()


if __name__ == "__main__":
    main()
