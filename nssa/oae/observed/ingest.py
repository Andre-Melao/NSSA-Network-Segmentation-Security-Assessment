from __future__ import annotations

import ipaddress
import json
from json import JSONDecodeError
from pathlib import Path
from typing import TYPE_CHECKING

from nssa.oae.observed.matrix import ObservedEdge, ObservedKey, ObservedMatrix
from nssa.shared.audit_config_parser import (
    extract_policy_raw,
    is_audit_configuration,
    policy_slice_bytes,
)
from nssa.shared.contracts import (
    ProbeState,
    probe_state_value,
    probe_strategy_key,
    probe_strategy_value,
    strip_artifact_markers,
    validate_result_file,
)
from nssa.shared.deployment import Deployment
from nssa.shared.integrity import IntegrityError, compute_policy_hash, verify_artifact
from nssa.shared.policy import SegmentationPolicy
from nssa.shared.spm_parser import parse_spm

if TYPE_CHECKING:
    from nacl.signing import VerifyKey


def _normalise_proto_fields(raw: dict) -> dict:
    """Normalize probe protocol values to lowercase in-place."""
    probes = raw.get("probes")
    if not isinstance(probes, list):
        return raw

    for probe in probes:
        if not isinstance(probe, dict):
            continue
        proto = probe.get("proto")
        if isinstance(proto, str):
            probe["proto"] = proto.lower()

    return raw


def ingest_result(
    matrix: ObservedMatrix,
    raw: dict,
    segment_networks: dict[str, ipaddress.IPv4Network | None],
    policy: SegmentationPolicy,
    deployment: Deployment | None = None,
    source_path: Path | None = None,
) -> tuple[set[str], set[tuple[str, str, int, str]]]:
    """Ingest one validated result artifact into the observed matrix.

    Returns (individually_observed, directly_refuted_tuples).

    individually_observed: src_ips verifiably observed as themselves (Host Mode
    only). Empty for 'segment' artifacts and representative probes, whose
    src_ip is a vantage sensor.

    directly_refuted_tuples: (src_ip, dst_ip, port, proto) tuples where a
    policy_validation probe (context 'segment_level' or 'host_constrained')
    came back FILTERED. Classification uses it to avoid promoting an inferred
    path to a violation. Both are ephemeral and never stored on ObservedEdge.

    Identity comes from 'segment' or 'probe_id' (exactly one is present). The
    src_ip check depends on it:

      'segment'                  - src_ip must fall in the segment's CIDR.
      'probe_id', host mode      - src_ip must be in
                                   deployment.allowed_ips_for_probe().
      'probe_id', representative - src_ip is checked against
                                   deployment.allowed_networks_for_probe(), a
                                   CIDR union over the Probe's groups.

    A None from those helpers means "no enforceable check", not "always fail".
    """
    def _err(msg: str) -> str:
        return f"{source_path}: {msg}" if source_path else msg

    vantage_segment = raw.get("segment")
    probe_id = raw.get("probe_id")

    allowed_ips: set[str] | None = None
    allowed_networks: list | None = None
    segment_network: ipaddress.IPv4Network | None = None
    individually_observed: set[str] = set()
    directly_refuted_tuples: set[tuple[str, str, int, str]] = set()
    _REFUTING_CONTEXTS = frozenset({"segment_level", "host_constrained"})

    if vantage_segment is not None:
        if not isinstance(vantage_segment, str) or not vantage_segment:
            raise IntegrityError(_err("invalid 'segment'"))
        # Membership check, not .get() is None: a group without a CIDR exists with network None.
        if vantage_segment not in segment_networks:
            raise IntegrityError(_err(f"segment '{vantage_segment}' not found in SPM"))
        segment_network = segment_networks[vantage_segment]
    else:
        if not isinstance(probe_id, str) or not probe_id:
            raise IntegrityError(_err("invalid 'probe_id'"))
        if deployment is not None:
            # host mode: src_ip must be a declared workload. representative:
            # checked against a CIDR union. At most one helper is non-None.
            allowed_ips = deployment.allowed_ips_for_probe(probe_id, policy)
            allowed_networks = deployment.allowed_networks_for_probe(probe_id, policy)

    for probe in raw["probes"]:
        detail = probe.get("detail")
        if detail is not None and not isinstance(detail, str):
            raise IntegrityError(_err("probe has invalid 'detail' type"))

        strategy = probe_strategy_value(probe)
        if strategy is not None and not isinstance(strategy, str):
            raise IntegrityError(_err(f"probe has invalid '{probe_strategy_key(probe)}' type"))

        context = probe.get("context")
        if context is not None and not isinstance(context, str):
            raise IntegrityError(_err("probe has invalid 'context' type"))

        timestamp = probe.get("timestamp")
        if timestamp is not None and not isinstance(timestamp, (int, float)):
            raise IntegrityError(_err("probe has invalid 'timestamp' type"))

        rtt_ms = probe.get("rtt_ms")
        if rtt_ms is not None and not isinstance(rtt_ms, (int, float)):
            raise IntegrityError(_err("probe has invalid 'rtt_ms' type"))

        service = probe.get("service")
        if service is not None and not isinstance(service, str):
            raise IntegrityError(_err("probe has invalid 'service' type"))

        service_banner = probe.get("service_banner")
        if service_banner is not None and not isinstance(service_banner, str):
            raise IntegrityError(_err("probe has invalid 'service_banner' type"))

        src_ip = probe["src_ip"]
        try:
            src_addr = ipaddress.IPv4Address(src_ip)
        except ValueError as exc:
            raise IntegrityError(_err(f"invalid src_ip '{src_ip}'")) from exc

        if vantage_segment is not None:
            if segment_network is None or src_addr not in segment_network:
                raise IntegrityError(
                    _err(
                        f"src_ip '{src_ip}' does not belong to segment '{vantage_segment}'"
                        + (f" ({segment_network})" if segment_network is not None else "")
                    )
                )
        elif allowed_ips is not None:
            if src_ip not in allowed_ips:
                raise IntegrityError(
                    _err(
                        f"src_ip '{src_ip}' is not a declared member of any group "
                        f"probe '{probe_id}' represents in the deployment"
                    )
                )
            # Passed the membership check: a verified SPM workload, not a stand-in sensor.
            individually_observed.add(src_ip)
        elif allowed_networks is not None and not any(src_addr in net for net in allowed_networks):
            raise IntegrityError(
                _err(
                    f"src_ip '{src_ip}' does not belong to any network declared "
                    f"for the groups probe '{probe_id}' represents"
                )
            )

        proto = probe["proto"]
        key: ObservedKey = (probe["dst_ip"], probe["dst_port"], proto)
        incoming = ObservedEdge(
            state=ProbeState(probe_state_value(probe)),
            detail=detail,
            strategy=strategy,
            context=context,
            rtt_ms=float(rtt_ms) if rtt_ms is not None else None,
            timestamp=float(timestamp) if timestamp is not None else None,
            service=service,
            service_banner=service_banner,
        )

        matrix.data.setdefault(key, {}).setdefault(src_ip, []).append(incoming)

        if (
            strategy == "policy_validation"
            and context in _REFUTING_CONTEXTS
            and incoming.state == ProbeState.FILTERED
        ):
            directly_refuted_tuples.add((src_ip, probe["dst_ip"], probe["dst_port"], proto))

    return individually_observed, directly_refuted_tuples


def build_observed_matrix(
    result_files: list[Path],
    spm_path: Path,
    verify_keys: dict[str, "VerifyKey"],
    policy: SegmentationPolicy | None = None,
    deployment: Deployment | None = None,
    expected_deployment_hash: str | None = None,
    individually_observed_ips: set[str] | None = None,
    directly_refuted_tuples: set[tuple[str, str, int, str]] | None = None,
) -> ObservedMatrix:
    """Build the observed matrix after strict integrity and schema validation.

    Validation order per artifact: signature, contract/schema, SPM policy hash,
    and (when a Deployment is resolved) deployment hash.

    Pass a pre-parsed *policy* to avoid reloading the SPM. spm_path may be a
    plain SPM or a merged AuditConfiguration.

    deployment / expected_deployment_hash: pass when the caller already parsed
    the Deployment. Omitting both means artifacts identify themselves via
    'segment' (CIDR-checked) and 'probe_id' artifacts resolve no groups (weak
    guarantee). With a Deployment, every artifact needs a matching
    deployment_hash and gets the stronger SPM-derived src_ip check.

    individually_observed_ips / directly_refuted_tuples: optional sets updated
    in place across all artifacts (see ingest_result()); pass the same objects
    to evaluate() afterwards.

    Any failure raises and aborts execution.
    """
    matrix = ObservedMatrix()
    spm_raw_bytes = spm_path.read_bytes()
    spm_raw = json.loads(spm_raw_bytes.decode("utf-8"))
    if policy is None:
        # extract_policy_raw() resolves merged-vs-standalone SPM shape.
        policy = parse_spm(extract_policy_raw(spm_raw))
    segment_networks: dict[str, ipaddress.IPv4Network | None] = {
        segment.name: segment.network for segment in policy.segments
    }
    if is_audit_configuration(spm_raw):
        # Merged AuditConfiguration: policy_hash covers only the policy slice.
        expected_hash = compute_policy_hash(policy_slice_bytes(spm_raw))
    else:
        expected_hash = compute_policy_hash(spm_raw_bytes)

    for path in sorted(result_files):
        try:
            raw = json.loads(strip_artifact_markers(path.read_text(encoding="utf-8")))
        except JSONDecodeError as exc:
            raise IntegrityError(f"{path}: invalid JSON: {exc}") from exc

        if not isinstance(raw, dict):
            raise IntegrityError(f"{path}: top-level JSON must be an object")

        if "signature" not in raw:
            raise IntegrityError(f"{path}: missing signature")

        signed_by = raw.get("signed_by")
        if not isinstance(signed_by, str) or not signed_by:
            raise IntegrityError(f"{path}: missing or invalid 'signed_by'")

        verify_key = verify_keys.get(signed_by)
        if verify_key is None:
            raise IntegrityError(f"{path}: unknown signer '{signed_by}'")

        verify_artifact(raw, verify_key)

        has_segment = "segment" in raw
        has_probe_id = "probe_id" in raw
        if not has_segment and not has_probe_id:
            raise IntegrityError(f"{path}: missing artifact identity ('segment' or 'probe_id')")
        if has_segment:
            segment = raw.get("segment")
            if not isinstance(segment, str) or not segment:
                raise IntegrityError(f"{path}: missing or invalid 'segment'")
        if has_probe_id:
            probe_id = raw.get("probe_id")
            if not isinstance(probe_id, str) or not probe_id:
                raise IntegrityError(f"{path}: missing or invalid 'probe_id'")

        normalised = _normalise_proto_fields(raw)
        validate_result_file(normalised)

        if "policy_hash" not in normalised:
            raise IntegrityError(f"{path}: missing policy_hash")

        if not isinstance(normalised["policy_hash"], str) or not normalised["policy_hash"]:
            raise IntegrityError(f"{path}: invalid policy_hash")

        if normalised["policy_hash"] != expected_hash:
            raise IntegrityError(f"{path}: policy hash mismatch")

        if expected_deployment_hash is not None:
            artifact_deployment_hash = normalised.get("deployment_hash")
            if not isinstance(artifact_deployment_hash, str) or not artifact_deployment_hash:
                raise IntegrityError(f"{path}: missing deployment_hash")
            if artifact_deployment_hash != expected_deployment_hash:
                raise IntegrityError(f"{path}: deployment hash mismatch")

        artifact_individually_observed, artifact_directly_refuted = ingest_result(
            matrix,
            normalised,
            segment_networks=segment_networks,
            policy=policy,
            deployment=deployment,
            source_path=path,
        )
        if individually_observed_ips is not None:
            individually_observed_ips.update(artifact_individually_observed)
        if directly_refuted_tuples is not None:
            directly_refuted_tuples.update(artifact_directly_refuted)

    return matrix
