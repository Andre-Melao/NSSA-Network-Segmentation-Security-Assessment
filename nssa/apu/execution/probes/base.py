"""Base probe interface; concrete probes (TCP, UDP, ...) implement BaseProbe."""

from __future__ import annotations

from abc import ABC, abstractmethod

from nssa.apu.execution.results import ProbeResult


class BaseProbe(ABC):
    """Abstract base class for connectivity probes."""

    @abstractmethod
    def probe(
        self,
        src_ip: str,
        dst_ip: str,
        port: int,
        timeout: float = 1.0,
    ) -> ProbeResult:
        """Execute a single connectivity test.

        Parameters:
            src_ip:  Local IP (vantage point).
            dst_ip:  Target IP.
            port:    Destination port.
            timeout: Seconds to wait before declaring *filtered*.

        Returns:
            A :class:`ProbeResult` with the raw outcome.
        """

    @property
    @abstractmethod
    def proto(self) -> str:
        """Protocol identifier: "tcp" or "udp" for a single-transport probe.

        NmapProbe is dual-protocol (transport varies per call) and returns
        "nmap"; nothing reads this property off it today, so the mismatch is a
        known, unresolved gap.
        """
