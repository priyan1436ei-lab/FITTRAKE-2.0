"""Differential investigation — genuinely distinct candidate mechanisms.

Each proposal is a testable *possibility*, not a trained classification model.
Candidates never carry fabricated calibrated confidence values.
"""
from __future__ import annotations

from dataclasses import dataclass

from .models import Sample


@dataclass(frozen=True)
class Hypothesis:
    title: str
    supports: tuple[str, ...]
    contradicts: tuple[str, ...]
    unknown: tuple[str, ...]
    next_test: str


def competing_causes(sample: Sample) -> list[Hypothesis]:
    if sample.link == "disconnected":
        return [
            Hypothesis("Adapter, driver or power interruption", ("WLAN association lost",), (),
                       ("Driver reset and power state not recorded",),
                       "Inspect adapter events and power-management history around the timestamp."),
            Hypothesis("Access point or radio-path interruption", ("WLAN association lost",), (),
                       ("AP logs and RF interference not captured",),
                       "Compare disconnect timing on another authorized device near the same AP."),
            Hypothesis("Unknown or unobserved mechanism", (), (),
                       ("No direct cause evidence yet",),
                       "Preserve timeline and collect authorized AP / Windows event logs."),
        ]
    if sample.link != "connected":
        return [Hypothesis("Unknown: Wi-Fi state not measurable", (), (),
                           ("No valid native WLAN observation",),
                           "Check hardware, service state and Windows location permission.")]

    tcp = sample.probes.get("external_tcp")
    dns = sample.probes.get("dns")
    gateway = sample.probes.get("gateway_icmp")
    t = tcp.status if tcp else "unknown"
    d = dns.status if dns else "unknown"
    g = gateway.status if gateway else "unknown"

    if t == "ok" and d == "fail":
        return [
            Hypothesis("DNS resolver/path malfunction", ("External TCP endpoint was reachable", "DNS lookup failed"), (),
                       ("One hostname and default resolver tested",),
                       "Resolve a second domain and compare a permitted alternate resolver."),
            Hypothesis("DNS policy, content filtering or captive network", ("DNS lookup failed",),
                       ("TCP endpoint was reachable (not a full outage)",),
                       ("Security and captive-portal policy not observed",),
                       "Inspect VPN/filter rules and captive portal state."),
            Hypothesis("Unknown cause", (), (), ("No DNS packet or server error detail collected",),
                       "Capture precise resolver response with permitted diagnostic tools."),
        ]
    if t == "fail" and d == "ok":
        return [
            Hypothesis("Specific destination / route blocked", ("1.1.1.1:443 connection failed",),
                       ("DNS lookup to example.com succeeded",),
                       ("No second external TCP destination checked",),
                       "Try a second authorized TCP destination and compare outcomes."),
            Hypothesis("Local firewall or VPN selective egress policy", ("DNS works but one TCP endpoint fails",), (),
                       ("Firewall policy, active VPN routes not observed",),
                       "Check firewall/VPN logs and repeat the same endpoint after authorized rule change."),
            Hypothesis("Unknown cause", (), (), ("Single endpoint does not establish site-wide outage",),
                       "Capture route selection, compare IPv4 and browser access."),
        ]
    if t == "fail" and d == "fail":
        return [
            Hypothesis("Upstream or captive network disruption", ("DNS and external TCP checks both failed",),
                       (("Gateway ICMP answered",) if g == "ok" else ()),
                       ("An Ethernet or VPN default route might be selected",),
                       "Test approved second destination and compare another device on the Wi-Fi."),
            Hypothesis("Local firewall, VPN or host routing issue", ("Multiple external checks failed",), (),
                       ("Policy, routing table changes and VPN state not correlated",),
                       "Compare system default route and firewall/VPN logs at failure time."),
            Hypothesis("DNS-specific fault plus independent target blocking", ("Both probes failed",), (),
                       ("Failures may be independent",),
                       "Run permitted alternate DNS and TCP targets to separate mechanisms."),
            Hypothesis("Unknown cause", (), (), ("No isolation test yet",),
                       "Collect a controlled second measurement set before changing configuration."),
        ]
    if t == "ok" and d == "ok":
        return [
            Hypothesis("No failure on observed endpoints", ("External TCP and DNS checks succeeded",), (),
                       ("Some apps and sites may still be impaired",),
                       "Keep monitoring or test the specifically affected application."),
            Hypothesis("Intermittent, application-specific or unobserved issue", (), (),
                       ("Sampled probes cannot see packet-level events",),
                       "Reproduce with application-specific timestamps and logs."),
        ]
    return [Hypothesis("Insufficient external evidence", ("Wi-Fi association observed",), (),
                       ("External probes not usable, unknown or disabled",),
                       "Enable external checks if allowed, or investigate local link metrics only.")]
