"""Typed observations. Unknown results are never silently converted to failures."""
from __future__ import annotations
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Literal

Status = Literal["ok", "fail", "unknown", "skipped"]
Link = Literal["connected", "disconnected", "no_adapter", "unknown"]


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@dataclass(frozen=True)
class Probe:
    status: Status
    detail: str
    latency_ms: float | None = None


@dataclass(frozen=True)
class Sample:
    timestamp: str
    link: Link
    adapter: str | None = None
    ssid: str | None = None
    bssid: str | None = None
    signal_pct: int | None = None
    channel: int | None = None
    security: str | None = None
    gateway: str | None = None
    probes: dict[str, Probe] = field(default_factory=dict)
    collection_error: str | None = None

    def to_dict(self) -> dict:
        return asdict(self)

    @staticmethod
    def from_dict(value: dict) -> Sample:
        fields = dict(value)
        fields["probes"] = {k: Probe(**v) for k, v in fields.get("probes", {}).items()}
        return Sample(**fields)


@dataclass(frozen=True)
class Assessment:
    category: str
    label: str
    evidence: tuple[str, ...]
    limits: tuple[str, ...]
    recommendation: str
    confidence: str  # descriptive level, not a calibrated numerical probability

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True)
class Incident:
    id: int
    started_at: str
    ended_at: str | None
    fingerprint: str
    assessment: Assessment
    sample_id: int
