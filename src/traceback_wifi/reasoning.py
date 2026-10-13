"""Transparent heuristic differential diagnosis; no made-up confidence %.

Limits are explicit, especially ICMP filtering, VPN routes and single-endpoint
blocks. It never claims definitive ISP / DNS / router causality from one probe.
"""
from __future__ import annotations

import hashlib
import json

from .models import Assessment, Sample


def is_failure(sample: Sample) -> bool | None:
    if sample.link == "disconnected":
        return True
    if sample.link in ("unknown", "no_adapter"):
        return None
    tcp = sample.probes.get("external_tcp")
    dns = sample.probes.get("dns")
    t = tcp.status if tcp else "unknown"
    d = dns.status if dns else "unknown"
    # Endpoint-specific failures require TWO consecutive failed samples before
    # incident creation; this never asserts that the entire internet is down.
    if t == "fail" or d == "fail":
        return True
    if t == "ok" and d in ("ok", "unknown", "skipped"):
        return False
    return None


def fingerprint(sample: Sample, assessment: Assessment) -> str:
    inputs = {"category": assessment.category, "link": sample.link,
              "gateway_icmp": sample.probes.get("gateway_icmp").status
              if sample.probes.get("gateway_icmp") else "unknown",
              "dns": sample.probes.get("dns").status if sample.probes.get("dns") else "unknown",
              "external_tcp": sample.probes.get("external_tcp").status
              if sample.probes.get("external_tcp") else "unknown"}
    return hashlib.sha256(json.dumps(inputs, sort_keys=True).encode()).hexdigest()[:16]


def assess(sample: Sample) -> Assessment:
    if sample.link == "no_adapter":
        return Assessment("no_adapter", "Wireless adapter unavailable", ("No WLAN interfaces enumerated",),
                          ("Adapter may be disabled or a driver/service may be unavailable",),
                          "Check Device Manager and WLAN AutoConfig service.", "observed")
    if sample.link == "unknown":
        return Assessment("unknown", "Could not observe Wi-Fi", (sample.collection_error or "No link data",),
                          ("Windows location permissions can restrict Wi-Fi properties",),
                          "Enable Location for desktop apps if required, and confirm WLAN service is running.",
                          "insufficient")
    if sample.link == "disconnected":
        return Assessment("link_loss", "Wi-Fi link disconnected", ("WLAN reports not connected",),
                          ("Polling may miss short outages", "Reason for disconnect is not yet established"),
                          "Inspect router availability, adapter power policy and Windows WLAN report.",
                          "observed")
    tcp = sample.probes.get("external_tcp")
    dns = sample.probes.get("dns")
    gw = sample.probes.get("gateway_icmp")
    if tcp and tcp.status == "ok" and dns and dns.status == "fail":
        return Assessment("dns_suspected", "DNS-path issue suspected",
                          ("External TCP connection succeeded", "DNS lookup failed"),
                          ("A resolver-specific or policy-related failure is also possible",),
                          "Check configured DNS servers and test an alternative known domain.", "moderate")
    if tcp and tcp.status == "fail" and dns and dns.status == "ok":
        return Assessment("tcp_reachability", "External TCP reachability failure",
                          ("TCP connection to 1.1.1.1:443 failed", "DNS lookup completed"),
                          ("The remote endpoint, firewall or VPN can block this single target",
                           "Gateway may refer to a VPN or another adapter"),
                          "Try a second permitted destination, compare with browser connectivity.",
                          "limited")
    if tcp and tcp.status == "fail" and dns and dns.status == "fail":
        evidence = ("External TCP endpoint unreachable", "DNS lookup failed")
        if gw and gw.status == "ok":
            evidence += ("Default route gateway answered ICMP",)
        return Assessment("multi_probe_failure", "Multiple connectivity checks failed", evidence,
                          ("Cause may be upstream, firewall, VPN, or captive portal",
                           "Gateway ICMP can be blocked or routed over another adapter"),
                          "Compare another device, inspect VPN/firewall, then review router and ISP status.",
                          "limited")
    if tcp and tcp.status == "ok":
        return Assessment("ok", "External endpoint reachable",
                          ("TCP connection to 1.1.1.1:443 succeeded",),
                          ("This does not establish that every website/service is reachable",),
                          "Continue monitoring to capture intermittent problems.", "observed")
    return Assessment("insufficient", "Not enough probe evidence",
                      ("Wi-Fi association observed",),
                      ("External probes disabled, blocked, or unknown",),
                      "Enable external probes to investigate reachability; link metrics still work offline.",
                      "insufficient")


class IncidentTracker:
    """Two consecutive failures trigger; two successes close. Unknown pauses.

    Transition events are emitted as (kind, sample) pairs. Caller persists
    incidents; this avoids duplicating DB concerns and simplifies testing.
    """
    def __init__(self, threshold: int = 2):
        self.threshold = threshold
        self.fail_streak = 0
        self.ok_streak = 0
        self.active = False

    def process(self, sample: Sample) -> str | None:
        result = is_failure(sample)
        if result is None:
            self.fail_streak = 0
            self.ok_streak = 0
            return None
        if result:
            self.fail_streak += 1
            self.ok_streak = 0
            if not self.active and self.fail_streak >= self.threshold:
                self.active = True
                return "opened"
        else:
            self.ok_streak += 1
            self.fail_streak = 0
            if self.active and self.ok_streak >= self.threshold:
                self.active = False
                return "closed"
        return None
