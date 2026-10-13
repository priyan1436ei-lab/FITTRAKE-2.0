import json
from dataclasses import replace

from traceback_wifi.collector import LiveCollector
from traceback_wifi.database import Database
from traceback_wifi.models import Probe, Sample
from traceback_wifi.reasoning import assess, fingerprint
from traceback_wifi.wlan import WifiApiError


def test_collector_can_read_real_interface_contract_with_injected_reader(monkeypatch):
    import traceback_wifi.collector as m
    monkeypatch.setattr(m, "default_route_gateway", lambda: "192.0.2.1")
    monkeypatch.setattr(m, "ping_gateway", lambda _: Probe("ok", "reply", 5.0))
    monkeypatch.setattr(m, "probe_tcp", lambda: Probe("fail", "blocked"))
    monkeypatch.setattr(m, "probe_dns", lambda: Probe("ok", "resolved", 11.0))
    read = lambda: {"link": "connected", "adapter": "Card1", "ssid": "Network",
                    "signal_pct": 73, "channel": 6, "security": "WPA2-PSK"}
    sample = LiveCollector(wifi_reader=read).collect()
    assert sample.adapter == "Card1"
    assert sample.gateway == "192.0.2.1"
    assert sample.probes["external_tcp"].status == "fail"
    assert sample.signal_pct == 73


def test_disabled_external_never_invokes_probe(monkeypatch):
    import traceback_wifi.collector as m
    monkeypatch.setattr(m, "default_route_gateway", lambda: None)
    monkeypatch.setattr(m, "probe_tcp", lambda: (_ for _ in ()).throw(AssertionError("called")))
    monkeypatch.setattr(m, "probe_dns", lambda: (_ for _ in ()).throw(AssertionError("called")))
    sample = LiveCollector(external_probes=False, wifi_reader=lambda: {"link": "connected"}).collect()
    assert sample.probes["external_tcp"].status == "skipped"
    assert sample.probes["dns"].status == "skipped"


def test_native_wifi_error_is_not_faked():
    def broken():
        raise WifiApiError("access denied")
    s = LiveCollector(wifi_reader=broken).collect()
    assert s.link == "unknown"
    assert "access denied" in (s.collection_error or "")


def test_disconnected_samples_do_not_probe(monkeypatch):
    import traceback_wifi.collector as m
    monkeypatch.setattr(m, "probe_tcp", lambda: (_ for _ in ()).throw(AssertionError("called")))
    s = LiveCollector(wifi_reader=lambda: {"link": "disconnected", "adapter": "wlan0"}).collect()
    assert s.probes["dns"].status == "skipped"


def test_sample_json_roundtrip():
    obj = Sample(timestamp="2026-10-13T12:00:00+00:00", link="connected",
                 probes={"dns": Probe("ok", "resolved", 12.5)})
    assert Sample.from_dict(json.loads(json.dumps(obj.to_dict()))) == obj


def test_database_incident_and_challenge_roundtrip(tmp_path):
    db = Database(tmp_path / "nested" / "evidence.sqlite3")
    s = Sample(timestamp="2026-10-13T12:00:00+00:00", link="disconnected")
    first = db.store_sample(s)
    assert first > 0
    assert db.recent_samples() == [s]
    a = assess(s)
    iid = db.open_incident(first, s, a, fingerprint(s, a))
    assert db.open_incident_id() == iid
    assert db.incidents()[0]["assessment"]["category"] == "link_loss"
    db.close_incident(iid, "2026-10-13T12:01:00+00:00")
    assert db.open_incident_id() is None
    challenge_id = db.save_challenge([s] * 3)
    db.finish_challenge(challenge_id, [replace(s, link="connected")] * 3, "Move closer")
    assert db.challenges()[0]["comment"] == "Move closer"


def test_prune_keeps_incident_evidence(tmp_path):
    db = Database(tmp_path / "store.db")
    s = Sample(timestamp="2020-01-01T00:00:00+00:00", link="disconnected")
    id0 = db.store_sample(s)
    db.store_sample(s)
    a = assess(s)
    db.open_incident(id0, s, a, fingerprint(s, a))
    db.prune_samples(days=7)
    assert len(db.recent_samples()) == 1


def test_incident_context_and_repeated_fingerprint(tmp_path):
    db = Database(tmp_path / "x.db")
    s = Sample(timestamp="2026-10-13T12:00:00+00:00", link="disconnected")
    old_id = db.store_sample(s)
    newer_id = db.store_sample(replace(s, timestamp="2026-10-13T12:00:05+00:00"))
    f = fingerprint(s, assess(s))
    db.open_incident(newer_id, s, assess(s), f)
    db.open_incident(newer_id, s, assess(s), f)
    assert db.repeat_count(f) == 2
    assert [o.timestamp for o in db.incident_context(newer_id)] == [s.timestamp, "2026-10-13T12:00:05+00:00"]
