"""Parser for a single-file AuditConfiguration (policy/deployment/
authentication in one JSON document).

Thin: spm_parser and deployment_parser do the structural parsing; this module
detects the shape, extracts each section, and calls them. See
nssa.shared.audit_config for the container types.

Schema:
  AuditConfiguration = {"policy": <SPM>, "deployment": {...}?, "authentication": {...}?}
  Standalone SPM     = <SPM> directly, with no wrapper.

A document with a top-level 'deployment' and/or 'authentication' key is a merged
AuditConfiguration. It must declare its SPM under 'policy' and must not also
declare SPM fields at its root. extract_policy_raw() resolves this distinction
for every call site.

Hashing: policy_slice_bytes()/deployment_slice_bytes() return the canonical
re-serialisation to hash (and, for policy, to forward to a remote APU), never
the original bytes, which may contain an 'authentication' section. The same
policy hashes identically whether standalone or embedded under 'policy'.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from nssa.shared.audit_config import AuditConfiguration
from nssa.shared.authentication import Authentication
from nssa.shared.authentication_parser import parse_authentication
from nssa.shared.deployment import Deployment
from nssa.shared.deployment_parser import parse_deployment
from nssa.shared.integrity import canonical_json_bytes
from nssa.shared.spm_parser import parse_spm

_NON_POLICY_KEYS = frozenset({"deployment", "authentication"})
# Top-level keys parse_spm() reads; a merged AuditConfiguration must not declare
# them at its root alongside 'policy'.
_SPM_ROOT_KEYS = frozenset({
    "groups", "servers", "rules", "mandatory_transit_paths",
})


def is_audit_configuration(raw: dict[str, Any]) -> bool:
    """Whether *raw* is a merged AuditConfiguration (has 'deployment' or 'authentication')."""
    return bool(_NON_POLICY_KEYS & raw.keys())


def extract_policy_raw(raw: dict[str, Any]) -> dict[str, Any]:
    """Resolve *raw* to the SPM document it declares.

    A merged AuditConfiguration keeps its SPM under 'policy'; a standalone SPM
    is the policy itself.

    Raises AuditConfigValidationError if 'policy' is missing or not an object,
    or if SPM fields are also declared at the root.
    """
    if not is_audit_configuration(raw):
        return raw

    hybrid = _SPM_ROOT_KEYS & raw.keys()
    if hybrid:
        raise AuditConfigValidationError(
            f"AuditConfiguration must not declare SPM fields "
            f"{sorted(hybrid)} at its own root -- the SPM belongs entirely "
            f"under 'policy'."
        )

    policy_raw = raw.get("policy")
    if policy_raw is None:
        raise AuditConfigValidationError(
            "AuditConfiguration requires a 'policy' section containing the "
            "SPM (groups/servers/rules/mandatory_transit_paths)."
        )
    if not isinstance(policy_raw, dict):
        raise AuditConfigValidationError("'policy' must be a JSON object.")
    return policy_raw


def policy_slice_bytes(raw: dict[str, Any]) -> bytes:
    """Canonical bytes of the SPM *raw* declares: what policy_hash covers and what is sent to an APU."""
    return canonical_json_bytes(extract_policy_raw(raw))


def deployment_slice_bytes(raw: dict[str, Any]) -> bytes | None:
    """Canonical bytes of the 'deployment' section, or None if absent."""
    if "deployment" not in raw:
        return None
    return canonical_json_bytes(raw["deployment"])


def runtime_configuration_bytes(raw: dict[str, Any]) -> bytes:
    """Canonical bytes of every top-level key except 'authentication'.

    Unlike policy_slice_bytes(), 'deployment' is kept, for a remote nssa-probe
    that resolves a named Probe (see nssa.run.runners.SSHRunner).
    """
    runtime_slice = {k: v for k, v in raw.items() if k != "authentication"}
    return canonical_json_bytes(runtime_slice)


def parse_audit_config(raw: dict[str, Any]) -> AuditConfiguration:
    """Parse an already-loaded JSON dict into an AuditConfiguration.

    Accepts a merged document or a plain SPM dict (empty Deployment(),
    authentication=None). This is where Deployment is cross-checked against
    Authentication (see _validate_ssh_profile_references()).
    """
    policy = parse_spm(extract_policy_raw(raw))

    deployment_raw = raw.get("deployment")
    deployment = parse_deployment(deployment_raw) if deployment_raw is not None else Deployment()

    auth_raw = raw.get("authentication")
    authentication = parse_authentication(auth_raw) if auth_raw is not None else None

    _validate_ssh_profile_references(deployment, authentication)

    return AuditConfiguration(policy=policy, deployment=deployment, authentication=authentication)


def _validate_ssh_profile_references(
    deployment: Deployment, authentication: Authentication | None
) -> None:
    """Every Probe naming an ssh_profile must reference an existing
    authentication.ssh_profiles entry, when an 'authentication' section exists.

    Probes with no ssh_profile are fine (ambient SSH config is used), and manual
    Probes may declare one unused. authentication is None means nothing to
    validate against, which keeps a RuntimeConfiguration (authentication
    stripped) valid on its own.
    """
    if authentication is None:
        return
    known_profiles = authentication.ssh_profiles
    for probe in deployment.probes:
        if probe.ssh_profile is not None and probe.ssh_profile not in known_profiles:
            raise AuditConfigValidationError(
                f"Probe '{probe.name}' references ssh_profile '{probe.ssh_profile}', "
                f"which is not declared in authentication.ssh_profiles. "
                f"Declared: {sorted(known_profiles)}"
            )


def parse_audit_config_bytes(data: bytes) -> AuditConfiguration:
    """Parse an AuditConfiguration from raw bytes (read once, reusable for hashing)."""
    return parse_audit_config(json.loads(data.decode("utf-8")))


def load_audit_config(path: str | Path) -> AuditConfiguration:
    """Parse an AuditConfiguration JSON file and return it fully parsed."""
    return parse_audit_config_bytes(Path(path).read_bytes())


class AuditConfigValidationError(Exception):
    """Raised on container-level validation failures: bad 'policy', hybrid root
    SPM fields, or an ssh_profile with no matching authentication entry.
    Section-level errors come from that section's own parser."""
