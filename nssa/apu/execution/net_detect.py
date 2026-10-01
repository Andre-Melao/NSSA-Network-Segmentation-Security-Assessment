"""Network auto-detection: identifies the local segment from the subnet.

Uses psutil to match local interfaces against the SPM segment CIDRs, so the APU
can run on any machine without --segment or --src-ip.
"""

from __future__ import annotations

import logging
import ipaddress
from dataclasses import dataclass

import psutil

from nssa.shared.policy import SegmentationPolicy
from nssa.shared.models import Segment

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class DetectedSegment:
    """Result of local network detection."""

    segment: Segment
    local_ip: str #The local IP that matched.
    interface: str #The network interface name (e.g. ``"eth0"``).


def get_local_ipv4_addresses() -> list[tuple[str, str]]:
    """Return (interface_name, ip_address) tuples for all local IPv4 addresses, excluding loopback."""
    result: list[tuple[str, str]] = []
    for iface, addrs in psutil.net_if_addrs().items():
        for addr in addrs:
            if addr.family.name == "AF_INET":  # IPv4
                ip = addr.address
                if not ip.startswith("127."):
                    result.append((iface, ip))
                    logger.debug("Found local IP: %s on %s", ip, iface)
    return result

def infer_src_ip(segment: Segment) -> str:
    """Find a local IP inside *segment* CIDR, or fall back to any local IP."""

    local_ips = get_local_ipv4_addresses()
    if not local_ips:
        raise ValueError(
            "Cannot infer source IP: no local IPv4 addresses found. "
            "Use --src-ip to specify one explicitly."
        )

    if segment.network is None:
        fallback = local_ips[0][1]
        logger.warning(
            "Segment '%s' has no declared CIDR (group-only membership) -- "
            "cannot check subnet containment; falling back to %s. "
            "Use --src-ip to specify one explicitly.",
            segment.name, fallback,
        )
        return fallback

    for iface, ip in local_ips:
        if ipaddress.IPv4Address(ip) in segment.network:
            logger.info(
                "Inferred src_ip=%s (iface %s, inside %s)",
                ip,
                iface,
                segment.network,
            )
            return ip

    fallback = local_ips[0][1]
    logger.warning("No local IP inside %s; falling back to %s", segment.network, fallback)
    return fallback

def detect_segment(policy: SegmentationPolicy) -> DetectedSegment:
    """Auto-detect which SPM segment this machine belongs to.

    Returns a DetectedSegment. Raises DetectionError if no local IP matches a
    segment CIDR or several segments match.
    """
    local_ips = get_local_ipv4_addresses()
    if not local_ips:
        raise DetectionError(
            "No local IPv4 addresses found (excluding loopback). "
            "Is the network interface up?"
        )

    matches: list[DetectedSegment] = []

    for iface, ip in local_ips:
        addr = ipaddress.IPv4Address(ip)
        for seg in policy.segments:
            # A group without a CIDR (network=None) cannot match by subnet; skip it
            # instead of crashing on `addr in None`.
            if seg.network is None:
                continue
            if addr in seg.network:
                match = DetectedSegment(
                    segment=seg, local_ip=ip, interface=iface
                )
                matches.append(match)
                logger.info(
                    "Local IP %s (%s) matches segment '%s' (%s)",
                    ip, iface, seg.name, seg.network,
                )

    if not matches:
        ip_list = ", ".join(f"{ip} ({iface})" for iface, ip in local_ips)
        seg_list = ", ".join(
            f"{s.name} ({s.network})" for s in policy.segments
        )
        raise DetectionError(
            f"No local IP matches any SPM segment.\n"
            f"  Local IPs: {ip_list}\n"
            f"  SPM segments: {seg_list}"
        )

    if len(matches) > 1:
        match_str = ", ".join(
            f"{m.local_ip} → {m.segment.name}" for m in matches
        )
        raise DetectionError(
            f"Multiple segments matched (ambiguous): {match_str}. "
            f"Use --segment to override."
        )

    return matches[0]


class DetectionError(Exception):
    """Raised when segment auto-detection fails."""
