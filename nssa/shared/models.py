"""SPM data models: frozen, read-only dataclasses used by both APU and OAE."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass

from nssa.shared.criticality import normalize_criticality


class AmbiguousSegmentError(ValueError):
    """Raised by Server.segment for a workload with zero or multiple groups.

    Such a workload cannot be projected onto a single segment; use
    Server.groups instead.
    """


# ── Group (a CIDR-based "segment" is its single-group special case) ──

@dataclass(frozen=True, slots=True)
class Group:
    """A named zone of workloads; network is optional (group-based models have no CIDR)."""

    name: str
    network: ipaddress.IPv4Network | None = None
    criticality: str = "medium"

    @classmethod
    def from_dict(cls, data: dict) -> Group:
        network = None
        if "cidr" in data:
            # strict=False normalizes host bits (192.168.1.5/24 -> 192.168.1.0/24).
            network = ipaddress.IPv4Network(data["cidr"], strict=False)
        # .get() with the field's own default, so criticality stays optional.
        return cls(
            name=data["name"],
            network=network,
            criticality=normalize_criticality(data.get("criticality", "medium")),
        )

    def __str__(self) -> str:  # pragma: no cover
        if self.network is not None:
            return f"{self.name} ({self.network}, criticality={self.criticality})"
        return f"{self.name} (criticality={self.criticality})"


# Backward-compat alias: a Segment is a (CIDR-bearing) Group.
Segment = Group


# ── Server ──

@dataclass(frozen=True, slots=True, init=False)
class Server:
    """A single workload, identified by IP, belonging to one or more groups.

    groups is the sole membership field; no group is "primary". See
    Server.segment for the single-group view.
    """

    name: str
    ip: str
    addr: ipaddress.IPv4Address
    groups: tuple[str, ...]

    def __init__(
        self,
        *,
        name: str,
        ip: str,
        addr: ipaddress.IPv4Address,
        groups: tuple[str, ...] = (),
    ) -> None:
        if not groups:
            raise ValueError(f"Server '{name}' requires 'groups'.")
        object.__setattr__(self, "name", name)
        object.__setattr__(self, "ip", ip)
        object.__setattr__(self, "addr", addr)
        object.__setattr__(self, "groups", tuple(groups))

    @classmethod
    def from_dict(cls, data: dict) -> Server:
        addr = ipaddress.IPv4Address(data["ip"])
        if "groups" not in data:
            raise ValueError(f"Server '{data['name']}' requires 'groups'.")
        return cls(name=data["name"], ip=data["ip"], addr=addr, groups=tuple(data["groups"]))

    @property
    def segment(self) -> str:
        """Single-group view; raises AmbiguousSegmentError unless len(groups) == 1."""
        if len(self.groups) != 1:
            raise AmbiguousSegmentError(
                f"Server '{self.name}' belongs to {len(self.groups)} groups "
                f"{self.groups!r}; it cannot be represented as a single "
                f"segment. Use '.groups' instead of '.segment'."
            )
        return self.groups[0]

    def __str__(self) -> str:  # pragma: no cover
        return f"{self.name} ({self.ip})"


# ── Rule ──

@dataclass(frozen=True, slots=True)
class Rule:
    """An explicitly authorised point-to-point flow."""

    src: str
    dst: str
    proto: str
    ports: tuple[int, ...]
    purpose: str
    # Stable id for audit attribution; set by the SPM author or synthesized by the parser.
    rule_id: str = ""

    @classmethod
    def from_dict(cls, data: dict) -> Rule:
        return cls(
            src=data["src"], dst=data["dst"],
            proto=data["proto"].strip().lower(), ports=tuple(data["ports"]),
            purpose=data.get("purpose", ""),
            rule_id=data.get("rule_id") or data.get("id", ""),
        )

    def __str__(self) -> str:  # pragma: no cover
        ports_str = ",".join(str(p) for p in self.ports)
        return f"{self.src} → {self.dst} [{self.proto}/{ports_str}]"


# ── MandatoryTransitPath ──

@dataclass(frozen=True, slots=True)
class MandatoryTransitPath:
    """An authorised path requiring a mandatory transit host.

    src and dst are segment or server names, as in Rule. via is the transit
    server, or a group where transiting through ANY member satisfies the
    constraint (see resolve_principal_ips); bypassing all of via's resolved
    hosts is a violation.

    proto and ports are optional: both omitted means all traffic between the
    endpoints; otherwise only matching traffic is constrained.
    """

    src: str
    dst: str
    via: str            # mandatory transit server name
    purpose: str
    rule_id: str = ""
    proto: str = ""                 # "" = all protocols
    ports: tuple[int, ...] = ()     # () = all ports

    @classmethod
    def from_dict(cls, data: dict) -> MandatoryTransitPath:
        via = data["via"]
        if not isinstance(via, str):
            raise ValueError(
                f"'via' must be a server name string, got {type(via).__name__!r}. "
                "Update your SPM to the simplified format: \"via\": \"<server-name>\"."
            )
        proto = data["proto"].strip().lower() if "proto" in data else ""
        ports = tuple(data["ports"]) if "ports" in data else ()
        return cls(
            src=data["src"],
            dst=data["dst"],
            via=via,
            proto=proto,
            ports=ports,
            purpose=data.get("purpose", ""),
            rule_id=data.get("rule_id") or data.get("id", ""),
        )

    def __str__(self) -> str:  # pragma: no cover
        port_str = ",".join(str(p) for p in self.ports) if self.ports else "*"
        proto_str = self.proto if self.proto else "*"
        return f"{self.src} → [{self.via}] → {self.dst} [{proto_str}/{port_str}]"
