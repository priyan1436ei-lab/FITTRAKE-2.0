"""Background poller. All Windows and SQLite I/O stays off the GUI thread."""
from __future__ import annotations

import logging
import threading

from PySide6.QtCore import QThread, Signal

from .collector import LiveCollector
from .database import Database
from .models import Sample
from .reasoning import IncidentTracker, assess, fingerprint

LOG = logging.getLogger(__name__)


class Monitor(QThread):
    observed = Signal(object, object)  # Sample, Assessment
    incident_changed = Signal(str)
    failed = Signal(str)

    def __init__(self, database: Database, interval: float = 5.0):
        super().__init__()
        self.database = database
        self.collector = LiveCollector()
        self.interval = interval
        self._stop = threading.Event()

    def stop(self) -> None:
        self._stop.set()

    def run(self) -> None:
        self.database.prune_samples(days=7)
        tracker = IncidentTracker()
        active_id = self.database.open_incident_id()
        tracker.active = active_id is not None
        while not self._stop.is_set():
            try:
                sample = self.collector.collect()
                assessment = assess(sample)
                sample_id = self.database.store_sample(sample)
                action = tracker.process(sample)
                if action == "opened":
                    active_id = self.database.open_incident(
                        sample_id, sample, assessment, fingerprint(sample, assessment))
                    self.incident_changed.emit("opened")
                elif action == "closed" and active_id is not None:
                    self.database.close_incident(active_id, sample.timestamp)
                    active_id = None
                    self.incident_changed.emit("closed")
                self.observed.emit(sample, assessment)
            except Exception as exc:  # keep monitoring after unexpected errors
                LOG.exception("Monitoring iteration failed")
                self.failed.emit(f"Monitoring error: {type(exc).__name__}: {exc}")
            self._stop.wait(self.interval)
