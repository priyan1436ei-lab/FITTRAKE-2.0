"""Bounded network probes plus native Wi-Fi observation.

These probes are diagnostic observations, not proof of internet availability.
No password or packet payload is collected. Only 1.1.1.1:443 and example.com
are contacted externally by default; users can disable external probes.
"""
from __future__ import annotations

import os
import re
import socket
import subprocess
import time
from typing import Callable

from .models import Probe, Sample, utc_now
from .wlan import WifiApiError, current_connection


def _command(args: list[str], timeout: float = 3.0) -> subprocess.CompletedProcess:
    return subprocess.run(args, capture_output=True, text=True, errors="replace",
                          timeout=timeout, check=False,
                          creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))


def default_route_gateway() -> str | None:
    """Return default route gateway (may be VPN/Ethernet, not necessarily Wi-Fi)."""
    if os.name != "nt":
        return None
    try:
        result = _command(["route", "print", "-4"], timeout=3.0)
        choices = []
        for line in result.stdout.splitlines():
            match = re.match(r"^\s*0\.0\.0\.0\s+0\.0\.0\.0\s+(\d+\.\d+\.\d+\.\d+)\s+\S+\s+(\d+)\s*$", line)
            if match:
                choices.append((int(match.group(2)), match.group(1)))
        return min(choices)[1] if choices else None
    except (OSError, subprocess.TimeoutExpired):
        return None


def ping_gateway(address: str | None) -> Probe:
    if not address:
        return Probe("unknown", "No IPv4 default-route gateway found")
    try:
        start = time.perf_counter()
        result = _command(["ping", "-4", "-n", "1", "-w", "1000", address], timeout=2.5)
        elapsed = (time.perf_counter() - start) * 1000
        return Probe("ok" if result.returncode == 0 else "fail",
                     "ICMP reply received" if result.returncode == 0 else
                     "ICMP probe failed (firewall may block echo replies)",
                     round(elapsed, 1) if result.returncode == 0 else None)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return Probe("unknown", f"ICMP probe unavailable: {type(exc).__name__}")


def probe_tcp() -> Probe:
    start = time.perf_counter()
    try:
        with socket.create_connection(("1.1.1.1", 443), timeout=1.5):
            pass
        elapsed = round((time.perf_counter() - start) * 1000, 1)
        return Probe("ok", "Connected to external IPv4 TCP 1.1.1.1:443", elapsed)
    except (OSError, TimeoutError) as exc:
        return Probe("fail", f"External TCP probe failed ({type(exc).__name__}); endpoint can be blocked")


def probe_dns() -> Probe:
    # nslookup gives a bounded child-process timeout unlike blocking getaddrinfo.
    try:
        start = time.perf_counter()
        result = _command(["nslookup", "-timeout=2", "-retry=1", "example.com"], timeout=3.5)
        elapsed = round((time.perf_counter() - start) * 1000, 1)
        if result.returncode == 0:
            return Probe("ok", "example.com lookup completed", elapsed)
        return Probe("fail", "DNS lookup failed (resolver/policy/connection may be responsible)")
    except (OSError, subprocess.TimeoutExpired) as exc:
        return Probe("unknown", f"DNS test unavailable: {type(exc).__name__}")


class LiveCollector:
    """Inject reader and probes in tests; production uses Windows WLAN API."""
    def __init__(self, external_probes: bool = True,
                 wifi_reader: Callable[[], dict] = current_connection):
        self.external_probes = external_probes
        self.wifi_reader = wifi_reader

    def collect(self) -> Sample:
        info: dict = {"link": "unknown"}
        error: str | None = None
        try:
            info = self.wifi_reader()
        except (WifiApiError, OSError, ValueError) as exc:
            error = str(exc)
        link = info.get("link", "unknown")
        gateway = default_route_gateway() if link == "connected" else None
        probes: dict[str, Probe] = {}
        if link == "connected":
            probes["gateway_icmp"] = ping_gateway(gateway)
            if self.external_probes:
                probes["external_tcp"] = probe_tcp()
                probes["dns"] = probe_dns()
            else:
                probes["external_tcp"] = Probe("skipped", "External probes disabled")
                probes["dns"] = Probe("skipped", "External probes disabled")
        else:
            for name in ("gateway_icmp", "external_tcp", "dns"):
                probes[name] = Probe("skipped", "Wi-Fi is not connected or state unavailable")
        return Sample(timestamp=utc_now(), link=link, adapter=info.get("adapter"),
                      ssid=info.get("ssid"), bssid=info.get("bssid"),
                      signal_pct=info.get("signal_pct"), channel=info.get("channel"),
                      security=info.get("security"), gateway=gateway,
                      probes=probes, collection_error=error)
