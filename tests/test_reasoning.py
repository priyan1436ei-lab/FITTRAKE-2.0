from dataclasses import replace

from traceback_wifi.models import Probe, Sample
from traceback_wifi.reasoning import IncidentTracker, assess, fingerprint, is_failure


def observation(link="connected", tcp="ok", dns="ok", gw="ok"):
    return Sample(timestamp="2026-10-13T12:00:00+00:00", link=link,
                  ssid="Lab", signal_pct=66,
                  probes={"external_tcp": Probe(tcp, "test"),
                          "dns": Probe(dns, "test"),
                          "gateway_icmp": Probe(gw, "test")})


def test_normal_reachability_is_not_internet_certainty():
    report = assess(observation())
    assert report.category == "ok"
    assert "not establish" in report.limits[0].lower()


def test_dns_suspicion_never_claims_proven_cause():
    report = assess(observation(tcp="ok", dns="fail"))
    assert report.category == "dns_suspected"
    assert report.confidence != "certain"


def test_endpoint_block_does_not_mean_internet_down():
    report = assess(observation(tcp="fail", dns="ok"))
    assert report.category == "tcp_reachability"
    assert "endpoint" in " ".join(report.limits).lower()


def test_multi_probe_failure():
    report = assess(observation(tcp="fail", dns="fail"))
    assert report.category == "multi_probe_failure"


def test_link_loss_and_no_adapter_differ():
    assert assess(observation(link="disconnected")).category == "link_loss"
    assert assess(observation(link="no_adapter")).category == "no_adapter"
    assert is_failure(observation(link="no_adapter")) is None


def test_unknown_does_not_count_as_failed():
    assert is_failure(observation(link="unknown")) is None
    assert is_failure(observation(tcp="skipped")) is None


def test_stable_fingerprint_excludes_timestamp_and_ssid():
    s = observation(tcp="fail")
    changed = replace(s, timestamp="2027-02-03T03:00:00+00:00", ssid="Other")
    assert fingerprint(s, assess(s)) == fingerprint(changed, assess(changed))


def test_different_evidence_changes_fingerprint():
    a, b = observation(tcp="fail", dns="ok"), observation(tcp="fail", dns="fail")
    assert fingerprint(a, assess(a)) != fingerprint(b, assess(b))


def test_two_failures_open_two_successes_close():
    tr = IncidentTracker()
    bad, good = observation(tcp="fail"), observation(tcp="ok")
    assert tr.process(bad) is None
    assert tr.process(bad) == "opened"
    assert tr.process(bad) is None
    assert tr.process(good) is None
    assert tr.process(good) == "closed"
    assert tr.process(good) is None


def test_unknown_resets_consecutive_counter_without_closing():
    tr = IncidentTracker()
    bad, good, unknown = observation(tcp="fail"), observation(), observation(tcp="skipped")
    tr.process(bad)
    tr.process(unknown)
    assert tr.process(bad) is None
    assert tr.process(bad) == "opened"
    tr.process(good)
    tr.process(unknown)
    assert tr.process(good) is None
    assert tr.active
    assert tr.process(good) == "closed"


def test_competing_hypotheses_include_unknown_and_independent_tests():
    from traceback_wifi.hypotheses import competing_causes
    hypotheses = competing_causes(observation(tcp="fail", dns="fail"))
    assert len(hypotheses) >= 3
    assert any("Unknown" in h.title for h in hypotheses)
    assert len({h.next_test for h in hypotheses}) == len(hypotheses)


def test_dns_hypotheses_distinguish_resolver_from_policy():
    from traceback_wifi.hypotheses import competing_causes
    titles = [h.title for h in competing_causes(observation(dns="fail"))]
    assert any("resolver" in t.lower() for t in titles)
    assert any("policy" in t.lower() for t in titles)


def test_dns_failure_starts_incident_even_with_good_tcp():
    tr = IncidentTracker()
    sample = observation(tcp="ok", dns="fail")
    assert is_failure(sample) is True
    assert tr.process(sample) is None
    assert tr.process(sample) == "opened"
