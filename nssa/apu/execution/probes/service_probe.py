from __future__ import annotations

import socket
import ssl

from nssa.apu.execution.results import ProbeResult


def enrich_service(result: ProbeResult) -> None:
    ip = result.dst_ip
    port = result.dst_port

    probes = _select_probes(port)

    for probe in probes:
        try:
            service, banner = probe(ip, port)
            if service:
                result.service = service
                result.service_banner = banner
                return
        except Exception:
            continue

    result.service = "unknown"
    result.service_banner = None


def _select_probes(port: int):
    if port == 22:
        return [_ssh_probe]

    if port in (80, 8080):
        return [_http_probe, _tls_probe, _ssh_probe]

    if port in (443, 8443):
        return [_tls_probe, _http_probe, _ssh_probe]

    return [_tls_probe, _http_probe, _ssh_probe]


def _ssh_probe(ip: str, port: int):
    with socket.create_connection((ip, port), timeout=1) as s:
        s.settimeout(1)
        banner = s.recv(100).decode(errors="ignore").strip()

    if not banner:
        return None, None

    if banner.startswith("SSH-"):
        return "ssh", banner

    return None, None


def _http_probe(ip: str, port: int):
    with socket.create_connection((ip, port), timeout=1) as s:
        s.settimeout(1)
        s.sendall(b"GET / HTTP/1.0\r\n\r\n")
        data = s.recv(200).decode(errors="ignore")

    if "HTTP/" in data:
        first_line = data.split("\r\n")[0]
        return "http", first_line

    return None, None


def _tls_probe(ip: str, port: int):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    with socket.create_connection((ip, port), timeout=1) as sock:
        sock.settimeout(1)
        with ctx.wrap_socket(sock, server_hostname=ip) as ssock:
            ssock.settimeout(1)
            cert = ssock.getpeercert()

    if cert:
        subject = cert.get("subject", [])
        return "tls", str(subject)

    return None, None
