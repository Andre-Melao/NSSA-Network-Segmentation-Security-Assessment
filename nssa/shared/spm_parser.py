"""Parser for the Segmentation Policy Model (SPM) JSON file.

Fast (single pass), fail-early, and deterministic.

Usage:

    from nssa.shared.spm_parser import load_spm

    policy = load_spm("path/to/policy.json")
"""

from __future__ import annotations

import dataclasses
import json
import logging
from pathlib import Path
from typing import Any

from nssa.shared.models import Group, Rule, Server, MandatoryTransitPath
from nssa.shared.policy import SegmentationPolicy

logger = logging.getLogger(__name__)


# ── Public API ──

def load_spm(path: str | Path) -> SegmentationPolicy:
    """Parse an SPM JSON file and return a fully indexed policy."""
    path = Path(path)
    logger.info("Loading SPM from %s", path)

    policy = parse_spm_bytes(path.read_bytes())
    logger.info("SPM loaded: %s", policy.summary())
    return policy


def parse_spm_bytes(data: bytes) -> SegmentationPolicy:
    """Parse an SPM from raw bytes (read once, reusable for the integrity hash)."""
    raw: dict[str, Any] = json.loads(data.decode("utf-8"))
    return parse_spm(raw)


def parse_spm(raw: dict[str, Any]) -> SegmentationPolicy:
    """Parse an already-loaded JSON dict into a SegmentationPolicy.

    Every cross-reference (server groups; rule src/dst; transit rule
    src/dst/via) is matched case-insensitively and rewritten to the declared
    name's casing, so downstream code can use exact-match lookups.
    """

    # 1. Groups (top-level array "groups").
    segments = _parse_list(raw, "groups", Group.from_dict)
    seg_names: set[str] = {s.name for s in segments}
    # Case-insensitive name -> declared-casing lookup for groups (servers reference groups only).
    group_lookup: dict[str, str] = {s.name.lower(): s.name for s in segments}

    # 2. Servers: resolve each server's .groups to the declared casing, or reject unknown groups.
    servers_raw = _parse_list(raw, "servers", Server.from_dict)
    servers = []
    for srv in servers_raw:
        resolved_groups = []
        unknown = []
        for g in srv.groups:
            canonical = group_lookup.get(g.lower())
            (resolved_groups if canonical is not None else unknown).append(canonical or g)
        if unknown:
            raise SPMValidationError(
                f"Server '{srv.name}' references unknown group(s) "
                f"{unknown}. Declared groups: {sorted(seg_names)}"
            )
        servers.append(dataclasses.replace(srv, groups=tuple(resolved_groups)))
    servers = tuple(servers)

    # Combined case-insensitive lookup for rule/transit src/dst/via (groups or servers).
    name_lookup: dict[str, str] = {**group_lookup, **{s.name.lower(): s.name for s in servers}}

    # 3. Rules
    rules_raw = _parse_list(raw, "rules", Rule.from_dict)
    rules = []
    for r in rules_raw:
        src = name_lookup.get(r.src.lower())
        if src is None:
            raise SPMValidationError(
                f"Rule src '{r.src}' is neither a segment nor a server. Rule: {r}"
            )
        dst = name_lookup.get(r.dst.lower())
        if dst is None:
            raise SPMValidationError(
                f"Rule dst '{r.dst}' is neither a segment nor a server. Rule: {r}"
            )
        rules.append(dataclasses.replace(r, src=src, dst=dst))
    rules = tuple(rules)

    # 4. Mandatory transit paths (top-level array "mandatory_transit_paths",
    #    matching the OAE's MANDATORY_TRANSIT_PATH_BYPASS finding type).
    transitive_rules: tuple[MandatoryTransitPath, ...] = ()
    transitive_key = "mandatory_transit_paths"
    if transitive_key in raw:
        transitive_rules_raw = _parse_list(raw, transitive_key, MandatoryTransitPath.from_dict)
        resolved_transitive = []
        for tr in transitive_rules_raw:
            src = name_lookup.get(tr.src.lower())
            if src is None:
                raise SPMValidationError(f"Transitive rule src '{tr.src}' is unknown.")
            dst = name_lookup.get(tr.dst.lower())
            if dst is None:
                raise SPMValidationError(f"Transitive rule dst '{tr.dst}' is unknown.")
            via = name_lookup.get(tr.via.lower())
            if via is None:
                raise SPMValidationError(
                    f"Transitive rule via '{tr.via}' is neither a declared server "
                    "nor a segment/group."
                )
            resolved_transitive.append(dataclasses.replace(tr, src=src, dst=dst, via=via))
        transitive_rules = tuple(resolved_transitive)

    # 5. Stable rule identity (explicit or synthesized)
    rules, transitive_rules = _finalize_rule_ids(rules, transitive_rules)

    # 6. Semantic validation (requires stable rule IDs for error messages)
    _validate_transitive_rule_conflicts(transitive_rules)

    # 7. Assemble & index
    return SegmentationPolicy(segments=segments, servers=servers, rules=rules, mandatory_transit_paths=transitive_rules)


def _validate_transitive_rule_conflicts(transitive_rules: tuple) -> None:
    """Reject transitive rules covering the same flow with different via hosts.

    Overlapping (src, dst, port, proto) rules with different transit hosts make
    bypass detection contradictory. Same-via overlaps are redundant but allowed.
    Wildcard rules (no ports/proto) cover all traffic, so a wildcard with a
    different via than a specific rule for the same (src, dst) is rejected too.
    """
    # (src, dst, port, proto) → (via, rule_id) for specific rules
    specific: dict[tuple[str, str, int, str], tuple[str, str]] = {}
    # (src, dst) → (via, rule_id) for wildcard rules
    wildcard: dict[tuple[str, str], tuple[str, str]] = {}

    for tr in transitive_rules:
        via = tr.via

        if tr.ports:
            for port in tr.ports:
                key = (tr.src, tr.dst, port, tr.proto)
                if key in specific and specific[key][0] != via:
                    existing_via, existing_id = specific[key]
                    raise SPMValidationError(
                        f"Conflicting transitive rules for flow "
                        f"({tr.src} → {tr.dst} {tr.proto}/{port}): "
                        f"'{existing_id}' mandates transit via '{existing_via}', "
                        f"but '{tr.rule_id}' mandates transit via '{via}'. "
                        f"A path authorised by one rule is a bypass of the other. "
                        f"Use distinct ports or combine into a single rule."
                    )
                specific[key] = (via, tr.rule_id)
        else:
            wc_key = (tr.src, tr.dst)
            if wc_key in wildcard and wildcard[wc_key][0] != via:
                existing_via, existing_id = wildcard[wc_key]
                raise SPMValidationError(
                    f"Conflicting wildcard transitive rules for "
                    f"({tr.src} → {tr.dst}): "
                    f"'{existing_id}' mandates transit via '{existing_via}', "
                    f"but '{tr.rule_id}' mandates transit via '{via}'."
                )
            wildcard[wc_key] = (via, tr.rule_id)

    # Cross-check: specific rules must agree with any wildcard for the same (src, dst).
    for (src, dst, port, proto), (via, rule_id) in specific.items():
        wc = wildcard.get((src, dst))
        if wc and wc[0] != via:
            raise SPMValidationError(
                f"Transitive rule '{rule_id}' ({proto}/{port}) conflicts with "
                f"wildcard rule '{wc[1]}' for ({src} → {dst}): "
                f"different mandatory transit hosts ('{via}' vs '{wc[0]}')."
            )


def _finalize_rule_ids(
    rules: tuple[Rule, ...],
    transitive_rules: tuple[MandatoryTransitPath, ...],
) -> tuple[tuple[Rule, ...], tuple[MandatoryTransitPath, ...]]:
    """Guarantee every rule has a unique, stable rule_id.

    Author-provided ids must be unique; the rest are synthesized (``R###``
    direct, ``T###`` transitive) without colliding.
    """
    taken: set[str] = set()
    for rule in (*rules, *transitive_rules):
        if not rule.rule_id:
            continue
        if rule.rule_id in taken:
            raise SPMValidationError(f"Duplicate rule_id '{rule.rule_id}' in SPM.")
        taken.add(rule.rule_id)

    rules = _assign_rule_ids(rules, "R", taken)
    transitive_rules = _assign_rule_ids(transitive_rules, "T", taken)
    return rules, transitive_rules


def _assign_rule_ids(items, prefix: str, taken: set[str]):
    result = []
    counter = 1
    for rule in items:
        if rule.rule_id:
            result.append(rule)
            continue
        while True:
            candidate = f"{prefix}{counter:03d}"
            counter += 1
            if candidate not in taken:
                break
        taken.add(candidate)
        result.append(dataclasses.replace(rule, rule_id=candidate))
    return tuple(result)


# ── Internal helpers ──

def _parse_list(raw: dict, key: str, factory):
    items = raw.get(key)
    if items is None:
        raise SPMValidationError(f"Missing required top-level key: '{key}'")
    if not isinstance(items, list):
        raise SPMValidationError(f"'{key}' must be a JSON array")
    results = []
    for index, item in enumerate(items):
        try:
            results.append(factory(item))
        except (KeyError, ValueError, TypeError) as exc:
            # Include the offending item's 'name' (if any) to identify the broken entry.
            label = item.get("name") if isinstance(item, dict) else None
            where = f"'{key}[{index}]'" + (f" ('{label}')" if label else "")
            raise SPMValidationError(f"Error parsing {where}: {exc}") from exc
    return tuple(results)


class SPMValidationError(Exception):
    """Raised when the SPM JSON is structurally or semantically invalid."""
