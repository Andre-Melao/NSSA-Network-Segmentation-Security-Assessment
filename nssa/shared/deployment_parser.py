"""Parser for the Deployment configuration JSON file.

Mirrors spm_parser.py's design goals: fast (single pass), fail-early,
deterministic.

Usage::

    from pathlib import Path
    from nssa.shared.deployment_parser import parse_deployment_bytes

    deployment = parse_deployment_bytes(Path("path/to/deployment.json").read_bytes())
"""

from __future__ import annotations

import ipaddress
import json
from typing import Any

from nssa.shared.deployment import Deployment, ProbeConfig

_KNOWN_PROBING_MODES = frozenset({"representative", "host"})
# "manual"/"automated" drives nssa-run's ManualRunner/SSHRunner split.
_KNOWN_EXECUTION_MODES = frozenset({"manual", "automated"})
# Keys _parse_probe() reads; only used to detect shorthand/array mixing.
_PROBE_KEYS = frozenset({"name", "probing_mode", "ip", "groups", "execution", "ssh_profile"})


def parse_deployment_bytes(data: bytes) -> Deployment:
    """Parse a Deployment from raw bytes (read once, reusable for deployment_hash)."""
    raw: dict[str, Any] = json.loads(data.decode("utf-8"))
    return parse_deployment(raw)


def parse_deployment(raw: dict[str, Any]) -> Deployment:
    """Parse an already-loaded JSON dict into a Deployment.

    Two shapes are accepted:

      {"probes": [{"name": "...", "probing_mode": "...", ...}, ...]}
        Explicit array, one entry per Probe (canonical).

      {"probing_mode": "representative", ...}
        Shorthand for a single unnamed Probe. With no groups/ip, vantage
        resolution falls through to CLI flags / auto-detection.
    """
    if "probes" in raw:
        # Reject a stray Probe-shaped key next to 'probes' (e.g. a leftover
        # 'probing_mode'): it would be silently ignored, though it looks like a default.
        stray = _PROBE_KEYS & raw.keys()
        if stray:
            raise DeploymentValidationError(
                f"'deployment' declares both 'probes' (the explicit array form) and "
                f"{sorted(stray)} at the same level -- the latter would be silently "
                f"ignored. Move {sorted(stray)} into the relevant entry inside 'probes', "
                f"or remove 'probes' to use the single-Probe shorthand instead."
            )
        items = raw["probes"]
        if not isinstance(items, list):
            raise DeploymentValidationError("'probes' must be a JSON array")
        # An unnamed Probe among several can never be selected via --probe-name;
        # fail at parse time.
        if len(items) > 1:
            unnamed = [i for i, item in enumerate(items) if isinstance(item, dict) and not item.get("name")]
            if unnamed:
                raise DeploymentValidationError(
                    f"Every Probe must have a 'name' when 'probes' declares more than one "
                    f"(entries at index {unnamed} do not) -- an unnamed Probe in a multi-probe "
                    f"deployment can never be selected via --probe-name."
                )
        probes = tuple(_parse_probe(item) for item in items)
    else:
        probes = (_parse_probe(raw),)

    names = [p.name for p in probes if p.name is not None]
    if len(names) != len(set(names)):
        raise DeploymentValidationError("Duplicate probe 'name' in deployment.")

    return Deployment(probes=probes)


def _parse_probe(data: dict[str, Any]) -> ProbeConfig:
    # 'groups' means different things per mode (CIDR check for 'representative',
    # fan-out for 'host'), and defaulting silently ran an intended Host Mode
    # fan-out as a single scan. Require the mode whenever 'groups' is present.
    if "groups" in data and "probing_mode" not in data:
        raise DeploymentValidationError(
            "Probe declares 'groups' but no 'probing_mode' -- state explicitly whether "
            "this is 'representative' (CIDR-network validation) or 'host' (workload "
            "fan-out); silently defaulting to 'representative' has previously masked an "
            "intended Host Mode probe running as a single local scan instead."
        )
    probing_mode_raw = data.get("probing_mode", "representative")
    if not isinstance(probing_mode_raw, str):
        raise DeploymentValidationError(
            f"Probe 'probing_mode' must be a string, got {type(probing_mode_raw).__name__}"
        )
    probing_mode = probing_mode_raw.strip().lower()
    if probing_mode not in _KNOWN_PROBING_MODES:
        raise DeploymentValidationError(
            f"Unknown probing_mode '{probing_mode_raw}'. Expected one of {sorted(_KNOWN_PROBING_MODES)}"
        )
    groups = data.get("groups")
    ip = data.get("ip")
    name = data.get("name")
    # An ssh_profile only has effect with execution == "automated"; declaring
    # one while execution defaults to "manual" would silently do nothing.
    if "ssh_profile" in data and "execution" not in data:
        raise DeploymentValidationError(
            "Probe declares 'ssh_profile' but no 'execution' -- an ssh_profile has no "
            "effect unless execution='automated' is also stated explicitly; leaving "
            "'execution' to default to 'manual' here would silently discard the "
            "automation this Probe was apparently meant to have."
        )
    execution_raw = data.get("execution", "manual")
    if not isinstance(execution_raw, str):
        raise DeploymentValidationError(
            f"Probe 'execution' must be a string, got {type(execution_raw).__name__}"
        )
    execution = execution_raw.strip().lower()
    ssh_profile = data.get("ssh_profile")
    if name is not None and not isinstance(name, str):
        raise DeploymentValidationError(f"Probe 'name' must be a string, got {type(name).__name__}")
    if ip is not None and not isinstance(ip, str):
        raise DeploymentValidationError(f"Probe 'ip' must be a string, got {type(ip).__name__}")
    # Unlike Server.ip/Group.cidr, this field accepted any string, failing late
    # or never matching.
    if ip is not None:
        try:
            ipaddress.IPv4Address(ip)
        except ValueError as exc:
            raise DeploymentValidationError(f"Probe 'ip' is not a valid IPv4 address: {ip!r} ({exc})") from exc
    if groups is not None and not isinstance(groups, list):
        raise DeploymentValidationError(f"Probe 'groups' must be a JSON array, got {type(groups).__name__}")
    if execution not in _KNOWN_EXECUTION_MODES:
        raise DeploymentValidationError(
            f"Unknown execution mode '{execution_raw}'. Expected one of {sorted(_KNOWN_EXECUTION_MODES)}"
        )
    if ssh_profile is not None and not isinstance(ssh_profile, str):
        raise DeploymentValidationError(
            f"Probe 'ssh_profile' must be a string, got {type(ssh_profile).__name__}"
        )
    # Host Mode has nothing to orchestrate without a group; fail at parse time.
    # run_host_mode() separately covers groups with zero policy-declared workloads.
    if probing_mode == "host" and not groups:
        raise DeploymentValidationError(
            "Probe declares probing_mode='host' but no 'groups' -- Host Mode has "
            "nothing to orchestrate without at least one declared group."
        )
    # Same reasoning as the 'groups' check above. run_host_mode() keeps its own
    # check for ProbeConfig built directly rather than through this parser.
    if probing_mode == "host" and not ip:
        raise DeploymentValidationError(
            "Probe declares probing_mode='host' but no 'ip' -- a Host Mode Probe needs "
            "its own vantage IP for the aggregated artifact."
        )

    return ProbeConfig(
        name=name,
        probing_mode=probing_mode,
        ip=ip,
        groups=tuple(groups) if groups else (),
        execution=execution,
        # Normalized (.strip().lower()) to match authentication.ssh_profiles' keys.
        ssh_profile=ssh_profile.strip().lower() if ssh_profile is not None else None,
    )


class DeploymentValidationError(Exception):
    """Raised when a deployment.json is structurally or semantically invalid."""
