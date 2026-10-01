"""Nmap-based probe that supports TCP and UDP scans."""

from __future__ import annotations

import subprocess
import time
import xml.etree.ElementTree as ET

from nssa.apu.execution.probes.base import BaseProbe
from nssa.apu.execution.results import ProbeResult
from nssa.shared.contracts import ProbeState

# Discovery scan parameters. The executor runs one host-level scan per discovery
# target instead of guessing ports: Nmap is the tool built to discover services.
DISCOVERY_TOP_PORTS: int = 100
DISCOVERY_UDP_PORTS: tuple[int, ...] = (53, 123, 161)

# Discovery only records evidence that a port is reachable or actively refused;
# ambiguous/no-response states carry no discovery value and are dropped.
_DISCOVERY_KEEP_STATES: frozenset[ProbeState] = frozenset({
    ProbeState.OPEN,
    ProbeState.CLOSED,
    ProbeState.OPEN_FILTERED,
})


def _map_nmap_state(state: str, proto: str) -> ProbeState:
    """Map a raw Nmap port state to a ProbeState."""
    if state == "open":
        return ProbeState.OPEN
    if state == "closed":
        return ProbeState.CLOSED
    if state == "filtered":
        return ProbeState.FILTERED
    if state == "open|filtered":
        return ProbeState.OPEN_FILTERED if proto == "udp" else ProbeState.FILTERED
    return ProbeState.ERROR


class NmapProbe(BaseProbe):
    """Execute one-port Nmap scan and normalize state to ProbeState."""

    @property
    def proto(self) -> str:
        return "nmap"

    def scan_discovery(
        self,
        src_ip: str,
        dst_ip: str,
        proto: str = "tcp",
        timeout: float = 1.0,
    ) -> list[ProbeResult]:
        """Run a host-level discovery scan and expand every reported port.

        TCP scans the Nmap top ports; UDP scans the canonical discovery ports
        (DNS/NTP/SNMP). Each port Nmap reports becomes its own ProbeResult so the
        OAE receives one ObservedEdge per discovered service. Only OPEN, CLOSED
        and OPEN_FILTERED ports are retained — discovery records reachability
        evidence, not ambiguous no-response noise.

        Unlike probe(), this is a 1-scan -> N-results operation. The dst_port of
        every result is a real port number from the scan; no synthetic markers.
        """
        t0 = time.monotonic()
        if proto == "udp":
            scan_type = "-sU"
            port_args = ["-p", ",".join(str(p) for p in DISCOVERY_UDP_PORTS)]
        else:
            scan_type = "-sS"
            port_args = ["--top-ports", str(DISCOVERY_TOP_PORTS)]

        # Host-level scans need a longer budget than a single-port probe.
        host_timeout_s = max(5, int(timeout) * 30)

        cmd = [
            "nmap",
            scan_type,
            "-Pn",
            "-n",
            "--max-retries",
            "1",
            "--host-timeout",
            f"{host_timeout_s}s",
            *port_args,
            "-oX",
            "-",
            dst_ip,
        ]

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=host_timeout_s + 5,
            )
        except subprocess.TimeoutExpired:
            return []
        except FileNotFoundError:
            return []

        if proc.returncode not in (0, 1):
            return []

        try:
            root = ET.fromstring(proc.stdout)
        except ET.ParseError:
            return []

        elapsed_ms = (time.monotonic() - t0) * 1_000
        results: list[ProbeResult] = []
        for port_el in root.findall(".//port"):
            state_el = port_el.find("state")
            if state_el is None:
                continue
            try:
                portid = int(port_el.attrib.get("portid", ""))
            except ValueError:
                continue

            state = (state_el.attrib.get("state") or "").strip().lower()
            reason = (state_el.attrib.get("reason") or "").strip().lower()
            probe_state = _map_nmap_state(state, proto)
            if probe_state not in _DISCOVERY_KEEP_STATES:
                continue

            results.append(
                ProbeResult(
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    dst_port=portid,
                    proto=proto,
                    state=probe_state,
                    rtt_ms=round(elapsed_ms, 1),
                    detail=f"{state}:{reason}" if reason else (state or "no-state"),
                )
            )

        return results

    def probe(
        self,
        src_ip: str,
        dst_ip: str,
        port: int,
        timeout: float = 1.0,
        proto: str = "tcp",
    ) -> ProbeResult:
        t0 = time.monotonic()
        scan_type = "-sS" if proto == "tcp" else "-sU"
        host_timeout_s = max(1, int(timeout))

        cmd = [
            "nmap",
            scan_type,
            "-Pn",
            "-n",
            "--initial-rtt-timeout",
            "200ms",
            "--max-rtt-timeout",
            "800ms",
            "--max-retries",
            "0",
            "--host-timeout",
            f"{host_timeout_s}s",
            "-p",
            str(port),
            "-oX",
            "-",
            dst_ip,
        ]

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout + 2,
            )
            elapsed_ms = (time.monotonic() - t0) * 1_000

            if proc.returncode not in (0, 1):
                return ProbeResult(
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    dst_port=port,
                    proto=proto,
                    state=ProbeState.ERROR,
                    rtt_ms=round(elapsed_ms, 2),
                    detail=f"nmap-error: rc={proc.returncode} {proc.stderr.strip()}",
                )

            root = ET.fromstring(proc.stdout)
            port_el = root.find(".//port")

            host_status_el = root.find(".//status")
            host_state = host_status_el.attrib.get("state") if host_status_el is not None else None

            # CASE 1: no port element.
            # host_state == "down" is unreachable: -Pn always forces state="up"
            # (verified against real Nmap). Do not infer liveness; treat missing
            # port info as ambiguous (FILTERED), never OPEN/CLOSED.
            if port_el is None:
                return ProbeResult(
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    dst_port=port,
                    proto=proto,
                    state=ProbeState.FILTERED,
                    rtt_ms=round(elapsed_ms, 2),
                    detail=f"no-port-info:{host_state or 'unknown-host'}",
                )

          
            # CASE 2: port element present
          
            state_el = port_el.find("state")

            if state_el is None:
                return ProbeResult(
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    dst_port=port,
                    proto=proto,
                    state=ProbeState.ERROR,
                    rtt_ms=round(elapsed_ms, 2),
                    detail="missing-state-element",
                )

            state = (state_el.attrib.get("state") or "").strip().lower()
            reason = (state_el.attrib.get("reason") or "").strip().lower()

            probe_state = _map_nmap_state(state, proto)

            # Preserve raw Nmap evidence with both dimensions when available.
            detail = f"{state}:{reason}" if reason else (state or "no-state")

            return ProbeResult(
                src_ip=src_ip,
                dst_ip=dst_ip,
                dst_port=port,
                proto=proto,
                state=probe_state,
                rtt_ms=round(elapsed_ms, 1),
                detail=detail,
            )

        except subprocess.TimeoutExpired:
            elapsed_ms = (time.monotonic() - t0) * 1_000
            return ProbeResult(
                src_ip=src_ip,
                dst_ip=dst_ip,
                dst_port=port,
                proto=proto,
                state=ProbeState.INCONCLUSIVE,
                rtt_ms=round(elapsed_ms, 1),
                detail="timeout",
            )
        except FileNotFoundError:
            elapsed_ms = (time.monotonic() - t0) * 1_000
            return ProbeResult(
                src_ip=src_ip,
                dst_ip=dst_ip,
                dst_port=port,
                proto=proto,
                state=ProbeState.ERROR,
                rtt_ms=round(elapsed_ms, 1),
                detail="nmap-error: binary not found",
            )
        except ET.ParseError as exc:
            elapsed_ms = (time.monotonic() - t0) * 1_000
            return ProbeResult(
                src_ip=src_ip,
                dst_ip=dst_ip,
                dst_port=port,
                proto=proto,
                state=ProbeState.ERROR,
                rtt_ms=round(elapsed_ms, 1),
                detail=f"nmap-xml-parse-error: {exc}",
            )
        except Exception as exc:
            elapsed_ms = (time.monotonic() - t0) * 1_000
            return ProbeResult(
                src_ip=src_ip,
                dst_ip=dst_ip,
                dst_port=port,
                proto=proto,
                state=ProbeState.ERROR,
                rtt_ms=round(elapsed_ms, 1),
                detail=f"nmap-error: {exc}",
            )
