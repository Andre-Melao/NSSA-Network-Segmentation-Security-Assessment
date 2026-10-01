"""ProbeRunner: the interface every probe-execution strategy implements.

A runner only makes one probe's artifact happen; whether to run is the
executor's job (nssa.run.executor).

  ManualRunner - renders instructions and validates that the artifact appeared.
  SSHRunner    - runs nssa-probe over SSH, one session per Probe, and can fetch
                 the probe's public key. It never parses the artifact or
                 verifies signatures; that is nssa-evaluate's job.
"""

from __future__ import annotations

import shlex
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

from nssa.run.plan import ProbeExecutionStep
from nssa.shared.authentication import SSHAuth


def _forward_stderr(stderr: bytes) -> None:
    """Forward a remote ssh command's stderr to this process's stderr."""
    if stderr:
        sys.stderr.buffer.write(stderr)
        sys.stderr.flush()


@dataclass(frozen=True, slots=True)
class StepOutcome:
    """Result of collecting one Probe's artifact.

    status  - "already_collected" (set by the executor) | "completed" | "failed".
    detail  - context on failure; None on plain success.
    """

    probe_name: str
    status: str
    detail: str | None = None


class ProbeRunner(Protocol):
    """Executes exactly one ProbeExecutionStep and reports what happened."""

    def run(self, step: ProbeExecutionStep) -> StepOutcome: ...


@dataclass(slots=True)
class ManualRunner:
    """Validates a manually-collected artifact.

    instructions() only renders text; run() only validates. Confirmation is
    handled by the executor.
    """

    def instructions(
        self, step: ProbeExecutionStep, runtime_config_path: Path, *,
        discovery: bool = False, trust_store_dir: Path | None = None,
    ) -> str:
        """Render the SSH and local-execution example commands for one Probe.

        --src-ip is included when the Probe declares one (deterministic group
        resolution). trust_store_dir adds a key-registration step when the
        Probe's key is missing. discovery mirrors nssa-run's --discovery.
        runtime_config_path is a tempfile with the RuntimeConfiguration
        ('authentication' stripped); Probes are never given the original
        AuditConfiguration.
        """
        probe_name = step.probe.name
        ssh_target = f"root@{step.probe.ip}" if step.probe.ip else "<user>@<probe-host>"
        discovery_flag = " --discovery" if discovery else ""
        src_ip_flag = f" --src-ip {step.probe.ip}" if step.probe.ip else ""
        lines = [f"Probe: {probe_name}", ""]

        pub_path = trust_store_dir / f"{probe_name}.pub" if trust_store_dir is not None else None
        if pub_path is not None and not pub_path.exists():
            lines += [
                "  1) Register this Probe's signing key (only needed once -- nssa-evaluate",
                "     rejects the artifact with 'unknown signer' otherwise):",
                f"     ssh {ssh_target} \"nssa-probe --get-pubkey\" > {pub_path}",
                "",
                "  2) Collect the artifact -- SSH example:",
            ]
        else:
            lines.append("  SSH example:")
        lines += [
            f"    ssh {ssh_target} \\",
            f"        \"nssa-probe - --probe-name {probe_name}{src_ip_flag}{discovery_flag}\" \\",
            f"        < {runtime_config_path} \\",
            f"        > {step.artifact_path}",
            "",
            "  Local execution example (run directly on the probe machine):",
            f"    nssa-probe {runtime_config_path.name} \\",
            f"        --probe-name {probe_name}{src_ip_flag}{discovery_flag} \\",
            f"        > {probe_name}_results.json",
            f"    (copy the signed artifact afterwards to {step.artifact_path})",
        ]
        return "\n".join(lines)

    def run(self, step: ProbeExecutionStep) -> StepOutcome:
        if step.artifact_path.exists():
            return StepOutcome(probe_name=step.probe.name, status="completed")
        return StepOutcome(
            probe_name=step.probe.name,
            status="failed",
            detail=f"artifact not found at {step.artifact_path}",
        )


@dataclass(slots=True)
class SSHRunner:
    """Runs one Probe's nssa-probe remotely over SSH.

    ssh_profiles          - authentication.ssh_profiles (name -> SSHAuth); empty
                            means ambient SSH config/agent is used.
    runtime_config_bytes  - bytes piped to the remote nssa-probe: policy +
                            deployment, 'authentication' stripped.
    connect_timeout       - ssh ConnectTimeout, seconds.
    remote_timeout        - timeout for the whole remote run, seconds.
    known_hosts_path      - NSSA's own known_hosts file, used with
                            StrictHostKeyChecking=accept-new: trust on first
                            use, refuse changed keys.
    discovery             - mirrors --discovery: adds inter-segment coverage
                            for Host Mode, and full discovery for Representative.
    """

    ssh_profiles: dict[str, SSHAuth] = field(default_factory=dict)
    runtime_config_bytes: bytes = b"{}"
    connect_timeout: float = 10.0
    remote_timeout: float = 1800.0
    known_hosts_path: Path = Path.home() / ".nssa" / "known_hosts"
    discovery: bool = False

    def _resolve(self, probe) -> tuple[str, list[str], None] | tuple[None, None, str]:
        """Resolve (target, base ssh_cmd) for one Probe, or (None, None, error).

        Shared by run() and fetch_pubkey() so both use the same connection.
        """
        profile: SSHAuth | None = None
        if probe.ssh_profile is not None:
            profile = self.ssh_profiles.get(probe.ssh_profile)
            if profile is None:
                # Unreachable in practice (validated at load); checked anyway.
                return None, None, f"ssh_profile '{probe.ssh_profile}' not found in authentication.ssh_profiles"

        if not probe.ip:
            return None, None, "Probe has execution=\"automated\" but no \"ip\" declared -- cannot open an SSH session"

        target = f"{profile.username}@{probe.ip}" if profile and profile.username else probe.ip
        self.known_hosts_path.parent.mkdir(parents=True, exist_ok=True)
        ssh_cmd = [
            "ssh",
            "-o", "BatchMode=yes",
            "-o", f"ConnectTimeout={int(self.connect_timeout)}",
            "-o", "StrictHostKeyChecking=accept-new",
            "-o", f"UserKnownHostsFile={self.known_hosts_path}",
        ]
        if profile and profile.private_key:
            ssh_cmd += ["-i", str(Path(profile.private_key).expanduser())]
        return target, ssh_cmd, None

    def run(self, step: ProbeExecutionStep) -> StepOutcome:
        probe = step.probe
        target, ssh_cmd, error = self._resolve(probe)
        if error:
            return StepOutcome(probe_name=probe.name, status="failed", detail=error)

        # "-" is nssa-probe's portable stdin sentinel.
        #
        # --src-ip is passed when declared so groups resolve via
        # policy.groups_for_ip() instead of the remote machine auto-detecting
        # its network position (fragile, and broken for group-only SPMs).
        remote_command = f"nssa-probe - --probe-name {shlex.quote(probe.name)}"
        if probe.ip:
            remote_command += f" --src-ip {shlex.quote(probe.ip)}"
        if self.discovery:
            remote_command += " --discovery"
        full_cmd = [*ssh_cmd, target, remote_command]

        start = time.time()
        try:
            result = subprocess.run(
                full_cmd,
                input=self.runtime_config_bytes,
                capture_output=True,
                timeout=self.remote_timeout,
            )
        except subprocess.TimeoutExpired:
            return StepOutcome(
                probe_name=probe.name, status="failed",
                detail=f"ssh timed out after {self.remote_timeout:.0f}s",
            )
        except OSError as exc:
            return StepOutcome(probe_name=probe.name, status="failed", detail=f"could not run ssh: {exc}")

        # Forward the remote nssa-probe's stderr to the auditor, even on success.
        _forward_stderr(result.stderr)

        if result.returncode != 0:
            stderr = result.stderr.decode("utf-8", errors="replace").strip()
            return StepOutcome(
                probe_name=probe.name, status="failed",
                detail=f"ssh exited {result.returncode}: {stderr[:200] or '(no stderr)'}",
            )

        if not result.stdout:
            return StepOutcome(probe_name=probe.name, status="failed", detail="remote command produced no output")

        step.artifact_path.parent.mkdir(parents=True, exist_ok=True)
        step.artifact_path.write_bytes(result.stdout)
        return StepOutcome(probe_name=probe.name, status="completed", detail=f"{time.time() - start:.1f}s")

    def fetch_pubkey(self, step: ProbeExecutionStep) -> bytes | None:
        """Run 'nssa-probe --get-pubkey' remotely; return the raw bytes, or None on failure.

        Never writes or verifies the key; that is the caller's decision.
        """
        target, ssh_cmd, error = self._resolve(step.probe)
        if error:
            return None
        full_cmd = [*ssh_cmd, target, "nssa-probe --get-pubkey"]
        try:
            result = subprocess.run(
                full_cmd, input=b"", capture_output=True, timeout=self.connect_timeout + 10,
            )
        except (subprocess.TimeoutExpired, OSError):
            return None
        _forward_stderr(result.stderr)
        if result.returncode != 0 or not result.stdout:
            return None
        return result.stdout
