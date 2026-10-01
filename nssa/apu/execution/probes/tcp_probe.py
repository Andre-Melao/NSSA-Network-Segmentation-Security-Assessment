"""TCP connectivity probe using a raw socket connect (SYN scan)."""

from __future__ import annotations

import errno
import logging
import socket
import time

from nssa.apu.execution.probes.base import BaseProbe
from nssa.apu.execution.results import ProbeResult
from nssa.shared.contracts import ProbeState

logger = logging.getLogger(__name__)


class TCPProbe(BaseProbe):
    """Lightweight TCP probe — attempts a full connect() to the target.

    Uses a plain ``socket.connect_ex`` which performs the kernel-level
    3-way handshake. This is portable, requires no raw-socket
    privileges, and is sufficient for policy validation.
    """

    @property
    def proto(self) -> str:
        return "tcp"

    def probe(self, src_ip: str, dst_ip: str, port: int, timeout: float = 1.0) -> ProbeResult:

        t0 = time.monotonic()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)

        try:
            err = sock.connect_ex((dst_ip, port))
            elapsed = (time.monotonic() - t0) * 1_000  # ms

            if err == 0:
                state = ProbeState.OPEN
                detail = "TCP handshake completed"
            elif err == errno.ECONNREFUSED:
                state = ProbeState.CLOSED
                detail = "Connection refused (RST)"
            elif err in (errno.EHOSTUNREACH, errno.ENETUNREACH, errno.EHOSTDOWN):
                state = ProbeState.UNREACHABLE
                detail = f"Destination unreachable (errno {err})"
            elif err in (errno.ETIMEDOUT, errno.EAGAIN, errno.EINPROGRESS):
                state = ProbeState.FILTERED
                detail = "Timeout during TCP handshake"
            else:
                state = ProbeState.ERROR
                detail = f"Unexpected errno {err}"
                logger.debug("Unexpected connect_ex errno=%d for %s:%d", err, dst_ip, port)

        except socket.timeout:
            elapsed = (time.monotonic() - t0) * 1_000
            state = ProbeState.FILTERED
            detail = "Timeout — no response"

        except OSError as exc:
            if exc.errno in (errno.EAGAIN, errno.ETIMEDOUT):
                state = ProbeState.FILTERED
                detail = f"Timeout (errno {exc.errno})"
            else:
                state = ProbeState.ERROR
                detail = str(exc)

        finally:
            sock.close()

        result = ProbeResult(
            src_ip=src_ip,
            dst_ip=dst_ip,
            dst_port=port,
            proto=self.proto,
            state=state,
            rtt_ms=round(elapsed, 2),
            detail=detail,
        )
        logger.debug("%s:%d → %s (%.1f ms)", dst_ip, port, state.value, elapsed)
        return result
