"""Native PySide6 cyber-console UI. All numbers originate in sampled data."""
from __future__ import annotations

import json
import os
import statistics
import sys
from datetime import datetime, timezone
from pathlib import Path

import pyqtgraph as pg
from PySide6.QtCore import Qt
from PySide6.QtGui import QFont
from PySide6.QtWidgets import (
    QAbstractItemView, QApplication, QCheckBox, QFileDialog, QFrame, QGridLayout, QHBoxLayout,
    QLabel, QLineEdit, QMainWindow, QMessageBox, QPlainTextEdit, QPushButton,
    QProgressBar, QStackedWidget, QTableWidget, QTableWidgetItem, QVBoxLayout,
    QWidget,
)

from .database import Database
from .hypotheses import competing_causes
from .models import Assessment, Sample, utc_now
from .service import Monitor

BG = "#070B12"
PANEL = "#111A27"
BORDER = "#253247"
CYAN = "#59DAEF"
GREEN = "#C9FF6C"
RED = "#FF818E"
MUTED = "#8899AD"

STYLE = """
QMainWindow, QWidget { background: #070B12; color: #E8F1FB; font-family: 'Segoe UI'; font-size: 13px; }
QFrame#Card { background: #111A27; border: 1px solid #253247; border-radius: 12px; }
QLabel#Title { font-size: 27px; font-weight: 700; color: #EAF8FF; }
QLabel#Heading { font-size: 18px; font-weight: 700; color: #EAF8FF; }
QLabel#Muted { color: #8899AD; }
QLabel#Number { color: #C9FF6C; font-size: 25px; font-weight: 700; }
QPushButton { background: #18263A; border: 1px solid #2B4059; border-radius: 8px;
              padding: 10px 14px; color: #E6F6FF; font-weight: 600; text-align: center; }
QPushButton:hover { background: #233A50; border-color: #59DAEF; }
QPushButton:disabled { color: #647589; border-color: #1A2532; }
QPushButton#Primary { background: #C9FF6C; color: #0D1706; border-color: #C9FF6C; }
QPushButton#Primary:hover { background: #DFFF9F; }
QPushButton#Nav { text-align: left; padding: 13px 17px; background: transparent; border: none; }
QPushButton#Nav:checked { color: #C9FF6C; background: #172633; border-left: 3px solid #C9FF6C; }
QPlainTextEdit, QLineEdit, QTableWidget { background: #0B1420; border: 1px solid #253247;
                           border-radius: 8px; color: #E8F1FB; padding: 7px; }
QHeaderView::section { background: #172335; padding: 9px; border: none; color: #A8C1D7; }
QProgressBar { border: 1px solid #253247; background: #09121D; border-radius: 5px; height: 10px; }
QProgressBar::chunk { background: #C9FF6C; border-radius: 5px; }
QCheckBox { color: #D4E5F3; padding: 8px; }
"""


def label(text: str, tag: str | None = None) -> QLabel:
    widget = QLabel(text)
    widget.setWordWrap(True)
    if tag:
        widget.setObjectName(tag)
    return widget


def card(title: str) -> tuple[QFrame, QVBoxLayout]:
    frame = QFrame()
    frame.setObjectName("Card")
    inner = QVBoxLayout(frame)
    inner.setContentsMargins(17, 15, 17, 15)
    inner.setSpacing(10)
    inner.addWidget(label(title.upper(), "Muted"))
    return frame, inner


def summary(samples: list[Sample]) -> dict:
    usable = [s for s in samples if s.link == "connected"]
    signal = [s.signal_pct for s in usable if s.signal_pct is not None]
    tcp = [s.probes.get("external_tcp") for s in usable]
    checked = [p for p in tcp if p is not None and p.status in ("ok", "fail")]
    return {"count": len(samples), "connected": len(usable),
            "signal_avg": round(statistics.mean(signal), 1) if signal else None,
            "tcp_success": round(100 * sum(p.status == "ok" for p in checked) / len(checked), 1)
            if checked else None, "tested": len(checked)}


class MainWindow(QMainWindow):
    def __init__(self, db_path: Path):
        super().__init__()
        self.db = Database(db_path)
        self.monitor: Monitor | None = None
        self.last_sample: Sample | None = None
        self.last_assessment: Assessment | None = None
        self.baseline_id: int | None = None
        self.baseline_started_at: str | None = None
        self.setWindowTitle("TRACEBACK WiFi | Network Failure Investigation")
        self.resize(1300, 820)
        self.setMinimumSize(980, 650)
        self.setStyleSheet(STYLE)
        self._build()
        self.refresh_incidents()
        self.refresh_history()
        if sys.platform != "win32":
            self.banner.setText("WINDOWS REQUIRED • Native WLAN collection unavailable on this OS")
            self.start_btn.setEnabled(False)
        else:
            self.start_monitor()

    def _build(self) -> None:
        shell = QWidget()
        self.setCentralWidget(shell)
        root = QHBoxLayout(shell)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        sidebar = QFrame()
        sidebar.setFixedWidth(235)
        sidebar.setStyleSheet("QFrame { background: #0E1623; border-right: 1px solid #253247; }")
        nav = QVBoxLayout(sidebar)
        nav.setContentsMargins(15, 28, 15, 20)
        nav.setSpacing(8)
        brand = label("◉  TRACEBACK", "Heading")
        brand.setStyleSheet("font-size: 22px; color: #C9FF6C; font-weight: bold;")
        nav.addWidget(brand)
        nav.addWidget(label("WiFi  /  INCIDENT LAB", "Muted"))
        nav.addSpacing(30)
        self.nav_buttons: list[QPushButton] = []
        self.stack = QStackedWidget()
        pages = [("⌁   LIVE OVERVIEW", self._overview()),
                 ("◈   INCIDENTS", self._incidents()),
                 ("◇   INVESTIGATION", self._investigation()),
                 ("▤   SETTINGS / EXPORT", self._settings())]
        for idx, (text, page) in enumerate(pages):
            button = QPushButton(text)
            button.setObjectName("Nav")
            button.setCheckable(True)
            button.clicked.connect(lambda checked=False, i=idx: self._navigate(i))
            self.nav_buttons.append(button)
            nav.addWidget(button)
            self.stack.addWidget(page)
        nav.addStretch()
        nav.addWidget(label("LOCAL-FIRST  •  NO CREDENTIAL COLLECTION", "Muted"))
        nav.addWidget(label("v0.1.0 • 5s sampling", "Muted"))
        root.addWidget(sidebar)

        body = QWidget()
        body_layout = QVBoxLayout(body)
        body_layout.setContentsMargins(28, 24, 28, 18)
        body_layout.setSpacing(14)
        top = QHBoxLayout()
        heading = label("NETWORK FORENSICS CONSOLE", "Title")
        top.addWidget(heading)
        top.addStretch()
        self.banner = label("●  LIVE HARDWARE MONITORING", "Muted")
        top.addWidget(self.banner)
        body_layout.addLayout(top)
        body_layout.addWidget(self.stack, 1)
        self.footer = label("Ready • Awaiting Windows Wi-Fi samples", "Muted")
        body_layout.addWidget(self.footer)
        root.addWidget(body, 1)
        self._navigate(0)

    def _navigate(self, index: int) -> None:
        self.stack.setCurrentIndex(index)
        for i, button in enumerate(self.nav_buttons):
            button.setChecked(i == index)
        if index == 1:
            self.refresh_incidents()
        if index == 3:
            self.refresh_history()

    def _overview(self) -> QWidget:
        page = QWidget()
        lay = QVBoxLayout(page)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(16)
        intro = label("Observe association state, network reachability and pre-failure evidence.", "Muted")
        lay.addWidget(intro)
        grid = QGridLayout()
        grid.setSpacing(15)
        self.value_labels = {}
        for index, (title, key) in enumerate((("WI-FI LINK", "link"), ("ACTIVE SSID", "ssid"),
                                              ("SIGNAL QUALITY", "signal"), ("INCIDENTS", "incidents"))):
            frame, content = card(title)
            val = label("—", "Number")
            val.setTextInteractionFlags(Qt.TextSelectableByMouse)
            self.value_labels[key] = val
            content.addWidget(val)
            content.addWidget(label("Live sample; no estimated values", "Muted"))
            grid.addWidget(frame, index // 2, index % 2)
        lay.addLayout(grid)
        mid = QHBoxLayout()
        mid.setSpacing(15)
        graph_frame, graph = card("Wireless signal • measured samples")
        axis = pg.DateAxisItem(orientation="bottom")
        self.plot = pg.PlotWidget(axisItems={"bottom": axis}, background=PANEL)
        self.plot.setYRange(0, 100)
        self.plot.setLabel("left", "Signal", units="%")
        self.plot.showGrid(x=True, y=True, alpha=0.12)
        self.plot.setMinimumHeight(215)
        self.curve = self.plot.plot([], [], pen=pg.mkPen(GREEN, width=2),
                                    symbol="o", symbolSize=4, symbolBrush=CYAN)
        graph.addWidget(self.plot)
        mid.addWidget(graph_frame, 2)
        diag_frame, diag = card("Latest active diagnostic probes")
        self.probe_labels = {}
        for key, title in (("gateway_icmp", "DEFAULT ROUTE ICMP"),
                           ("external_tcp", "EXTERNAL TCP"), ("dns", "DNS RESOLUTION")):
            diag.addWidget(label(title, "Muted"))
            v = label("Not measured")
            v.setStyleSheet(f"color: {CYAN}; font-size: 14px;")
            self.probe_labels[key] = v
            diag.addWidget(v)
        diag.addStretch()
        mid.addWidget(diag_frame, 1)
        lay.addLayout(mid, 1)
        self.adapter_label = label("Waiting for adapter details…", "Muted")
        lay.addWidget(self.adapter_label)
        return page

    def _incidents(self) -> QWidget:
        page = QWidget()
        lay = QVBoxLayout(page)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(14)
        lay.addWidget(label("FAILURE BLACK BOX", "Heading"))
        lay.addWidget(label("Only sustained link loss or external TCP/DNS probe failure opens an incident. "
                            "Sampling can miss outages shorter than the polling interval.", "Muted"))
        self.incident_table = QTableWidget(0, 6)
        self.incident_table.setHorizontalHeaderLabels(["ID", "START (UTC)", "END (UTC)", "FINGERPRINT", "REPEATS", "ASSESSMENT"])
        self.incident_table.horizontalHeader().setStretchLastSection(True)
        self.incident_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.incident_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.incident_table.itemSelectionChanged.connect(self._incident_selected)
        lay.addWidget(self.incident_table, 2)
        lay.addWidget(label("INCIDENT EVIDENCE", "Heading"))
        self.incident_detail = QPlainTextEdit()
        self.incident_detail.setReadOnly(True)
        self.incident_detail.setPlaceholderText("Select an incident to review recorded evidence and limitations.")
        lay.addWidget(self.incident_detail, 1)
        return page

    def _investigation(self) -> QWidget:
        page = QWidget()
        lay = QVBoxLayout(page)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(14)
        lay.addWidget(label("EVIDENCE / COMPETING CAUSES", "Heading"))
        lay.addWidget(label("The rules describe candidate causes, not validated diagnosis or AI probability.", "Muted"))
        self.reason_detail = QPlainTextEdit()
        self.reason_detail.setReadOnly(True)
        self.reason_detail.setPlainText("Waiting for a sample from the Windows Wi-Fi adapter…")
        lay.addWidget(self.reason_detail, 1)
        lay.addWidget(label("FIX CHALLENGE — CONTROLLED BEFORE / AFTER", "Heading"))
        lay.addWidget(label("Capture 3–5 recent samples, make a manual reversible change, "
                            "then capture at least 3 NEW samples. Improvement is correlation, not proof of cause.", "Muted"))
        actions = QHBoxLayout()
        self.baseline_btn = QPushButton("1  CAPTURE BASELINE")
        self.baseline_btn.setObjectName("Primary")
        self.baseline_btn.clicked.connect(self.capture_baseline)
        self.after_btn = QPushButton("2  MEASURE AFTER CHANGE")
        self.after_btn.clicked.connect(self.capture_after)
        self.after_btn.setEnabled(False)
        actions.addWidget(self.baseline_btn)
        actions.addWidget(self.after_btn)
        actions.addStretch()
        lay.addLayout(actions)
        self.fix_note = QLineEdit()
        self.fix_note.setPlaceholderText("Optional: describe the manually applied change (e.g., moved near router)")
        lay.addWidget(self.fix_note)
        self.challenge_result = QPlainTextEdit()
        self.challenge_result.setReadOnly(True)
        self.challenge_result.setMaximumHeight(130)
        self.challenge_result.setPlainText("No comparison captured yet.")
        lay.addWidget(self.challenge_result)
        return page

    def _settings(self) -> QWidget:
        page = QWidget()
        lay = QVBoxLayout(page)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(15)
        lay.addWidget(label("CONTROL / DATA OWNERSHIP", "Heading"))
        lay.addWidget(label("Locally stored samples may contain network SSIDs and BSSIDs. "
                            "No saved Wi-Fi passwords, traffic payloads, or credentials are accessed.", "Muted"))
        self.external_box = QCheckBox("Allow external diagnostics: 1.1.1.1:443 TCP + example.com DNS")
        self.external_box.setChecked(True)
        self.external_box.toggled.connect(self._toggle_external)
        lay.addWidget(self.external_box)
        row = QHBoxLayout()
        self.start_btn = QPushButton("START MONITORING")
        self.start_btn.setObjectName("Primary")
        self.start_btn.clicked.connect(self.start_monitor)
        self.stop_btn = QPushButton("STOP MONITORING")
        self.stop_btn.clicked.connect(self.stop_monitor)
        row.addWidget(self.start_btn)
        row.addWidget(self.stop_btn)
        row.addStretch()
        lay.addLayout(row)
        exports = QHBoxLayout()
        export_btn = QPushButton("EXPORT LOCAL REPORT (JSON)")
        export_btn.clicked.connect(self.export_data)
        exports.addWidget(export_btn)
        exports.addStretch()
        lay.addLayout(exports)
        self.history_label = label("", "Muted")
        lay.addWidget(self.history_label)
        lay.addWidget(label("Interpretation limits: default-route gateway may belong to VPN/Ethernet; "
                            "ICMP can be filtered; DNS can be cached or blocked; the single TCP endpoint "
                            "can be unreachable independently of normal browsing. "
                            "This is an investigative tool, not an automated network repair product.", "Muted"))
        lay.addStretch()
        return page

    def start_monitor(self) -> None:
        if sys.platform != "win32":
            return
        if self.monitor and self.monitor.isRunning():
            return
        self.monitor = Monitor(self.db)
        self.monitor.collector.external_probes = self.external_box.isChecked()
        self.monitor.observed.connect(self.on_observed)
        self.monitor.incident_changed.connect(lambda change: self.refresh_incidents())
        self.monitor.failed.connect(lambda message: self.footer.setText(message))
        self.monitor.start()
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.banner.setText("●  MONITORING • 5 SEC INTERVAL")

    def stop_monitor(self) -> None:
        if self.monitor and self.monitor.isRunning():
            self.monitor.stop()
            if not self.monitor.wait(9000):
                self.footer.setText("A probe is still finishing. Close is delayed until it exits.")
                return
        self.start_btn.setEnabled(sys.platform == "win32")
        self.stop_btn.setEnabled(False)
        self.banner.setText("○  MONITOR PAUSED")

    def _toggle_external(self, enabled: bool) -> None:
        if self.monitor:
            self.monitor.collector.external_probes = enabled

    def on_observed(self, sample: Sample, assessment: Assessment) -> None:
        self.last_sample, self.last_assessment = sample, assessment
        self.value_labels["link"].setText(sample.link.upper().replace("_", " "))
        self.value_labels["ssid"].setText(sample.ssid or "NOT AVAILABLE")
        self.value_labels["signal"].setText(f"{sample.signal_pct}%" if sample.signal_pct is not None else "—")
        self.adapter_label.setText(f"ADAPTER  {sample.adapter or 'unavailable'}    •    BSSID  {sample.bssid or '—'}"
                                   f"    •    CHANNEL  {sample.channel if sample.channel is not None else '—'}"
                                   f"    •    SECURITY  {sample.security or '—'}"
                                   f"    •    DEFAULT ROUTE  {sample.gateway or '—'}")
        for key, v in self.probe_labels.items():
            p = sample.probes.get(key)
            v.setText((f"{p.status.upper()}  •  {p.latency_ms} ms" if p.latency_ms is not None
                       else f"{p.status.upper()}  •  {p.detail}") if p else "Not measured")
        evidence = "\n".join(f"  • {e}" for e in assessment.evidence)
        limits = "\n".join(f"  • {x}" for x in assessment.limits)
        candidates = competing_causes(sample)
        differentials = "\n\n".join(
            f"{i}. {h.title}\n"
            f"  Supporting: {'; '.join(h.supports) or 'none observed'}\n"
            f"  Contradicting: {'; '.join(h.contradicts) or 'none observed'}\n"
            f"  Missing: {'; '.join(h.unknown) or 'none stated'}\n"
            f"  Discriminating test: {h.next_test}"
            for i, h in enumerate(candidates, 1))
        self.reason_detail.setPlainText(
            f"CURRENT OBSERVATION  /  {sample.timestamp}\n\n"
            f"Finding: {assessment.label}\nEvidence strength: {assessment.confidence}\n\n"
            f"EVIDENCE\n{evidence}\n\nKNOWN LIMITS\n{limits}\n\n"
            f"NEXT TEST\n{assessment.recommendation}\n\n"
            f"COMPETING CAUSES (NOT CONFIRMED)\n{differentials}\n")
        self.footer.setText(f"Sample at {sample.timestamp}  •  {assessment.label}"
                            + (f"  •  {sample.collection_error}" if sample.collection_error else ""))
        self._plot_history()
        self.refresh_incidents()

    def _plot_history(self) -> None:
        samples = self.db.recent_samples(120)
        points = [(datetime.fromisoformat(s.timestamp).timestamp(), s.signal_pct)
                  for s in samples if s.signal_pct is not None]
        self.curve.setData([x for x, y in points], [y for x, y in points])
        self.plot.enableAutoRange(axis="x", enable=True)

    def refresh_incidents(self) -> None:
        incidents = self.db.incidents()
        self._incident_rows = incidents
        self.value_labels["incidents"].setText(str(len(incidents)))
        self.incident_table.setRowCount(len(incidents))
        for row_idx, inc in enumerate(incidents):
            for col_idx, value in enumerate((inc["id"], inc["started_at"], inc["ended_at"] or "ACTIVE",
                                             inc["fingerprint"], self.db.repeat_count(inc["fingerprint"]), inc["assessment"]["label"])):
                self.incident_table.setItem(row_idx, col_idx, QTableWidgetItem(str(value)))
        self.incident_table.resizeColumnsToContents()

    def _incident_selected(self) -> None:
        row = self.incident_table.currentRow()
        if not 0 <= row < len(getattr(self, "_incident_rows", [])):
            return
        inc = self._incident_rows[row]
        a = inc["assessment"]
        lines = [f"INCIDENT #{inc['id']}  |  {inc['fingerprint']}",
                 f"Started: {inc['started_at']}  |  End: {inc['ended_at'] or 'still active'}",
                 f"Assessment: {a['label']} ({a['confidence']})", "", "Evidence:"]
        lines += ["  - " + x for x in a["evidence"]]
        lines += ["", "Limitations:"] + ["  - " + x for x in a["limits"]]
        lines += ["", "Recommended diagnostic: " + a["recommendation"]]
        lines += ["", "RECORDED PRE-INCIDENT SAMPLE CONTEXT (poll snapshots):"]
        for snapshot in self.db.incident_context(inc["sample_id"]):
            p = snapshot.probes.get("external_tcp")
            lines.append(f"  {snapshot.timestamp} • link={snapshot.link} • "
                         f"signal={snapshot.signal_pct if snapshot.signal_pct is not None else '—'}% • "
                         f"external_tcp={p.status if p else 'unknown'}")
        lines += ["", f"Matching historical incident count: {self.db.repeat_count(inc['fingerprint'])}",
                  "Repeated fingerprint means similar probe evidence, NOT proven identical cause."]
        self.incident_detail.setPlainText("\n".join(lines))

    def _fresh_samples(self) -> list[Sample]:
        samples = self.db.recent_samples(10)
        now = datetime.now(timezone.utc)
        return [s for s in samples if (now - datetime.fromisoformat(s.timestamp)).total_seconds() <= 90][-5:]

    def capture_baseline(self) -> None:
        samples = self._fresh_samples()
        if len(samples) < 3:
            QMessageBox.information(self, "Baseline", "At least 3 actual recent samples are needed.")
            return
        self.baseline_id = self.db.save_challenge(samples)
        self.baseline_started_at = utc_now()
        self.after_btn.setEnabled(True)
        self.challenge_result.setPlainText(
            f"Baseline captured: {len(samples)} real observations.\n"
            "Make a manual reversible change. Then collect at least 3 new samples (about 15s).")

    def capture_after(self) -> None:
        if self.baseline_id is None or self.baseline_started_at is None:
            return
        candidates = self.db.recent_samples(20, after=self.baseline_started_at)[-5:]
        if len(candidates) < 3:
            QMessageBox.information(self, "After-change capture",
                                    "Need at least 3 NEW observations following baseline.")
            return
        before_json = next((x["before_json"] for x in self.db.challenges()
                            if x["id"] == self.baseline_id), None)
        if not before_json:
            return
        before = [Sample.from_dict(x) for x in json.loads(before_json)]
        after = candidates
        b, a = summary(before), summary(after)
        self.db.finish_challenge(self.baseline_id, after, self.fix_note.text())
        def val(x: object, unit: str = "") -> str:
            return "unavailable" if x is None else f"{x}{unit}"
        result = (f"ACTUAL SAMPLE COMPARISON • baseline n={b['count']} / after n={a['count']}\n"
                  f"Average signal: {val(b['signal_avg'],'%')}  →  {val(a['signal_avg'],'%')}\n"
                  f"External TCP success: {val(b['tcp_success'],'%')} ({b['tested']} checks) "
                  f" → {val(a['tcp_success'],'%')} ({a['tested']} checks)\n"
                  "Interpret cautiously: no causal conclusion, no statistical significance claim.")
        self.challenge_result.setPlainText(result)
        self.after_btn.setEnabled(False)
        self.baseline_id = None
        self.baseline_started_at = None

    def refresh_history(self) -> None:
        if hasattr(self, "history_label"):
            self.history_label.setText(f"Storage location: {self.db.path}\n"
                                       f"Samples retained locally (default: 7 days), incident evidence preserved.")

    def export_data(self) -> None:
        filename, _ = QFileDialog.getSaveFileName(self, "Save local evidence report",
                                                   "traceback-wifi-report.json", "JSON Files (*.json)")
        if not filename:
            return
        try:
            data = {"exported_at_utc": utc_now(), "app": "TRACEBACK WiFi 0.1.0",
                    "limits": "5s sampled; probes are endpoint-specific; not proof of root cause",
                    "samples": [s.to_dict() for s in self.db.recent_samples(10000)],
                    "incidents": self.db.incidents(10000), "challenges": self.db.challenges(500)}
            Path(filename).write_text(json.dumps(data, indent=2), encoding="utf-8")
            QMessageBox.information(self, "Export complete", "Local JSON report saved.")
        except OSError as exc:
            QMessageBox.critical(self, "Export failed", str(exc))

    def closeEvent(self, event) -> None:
        if self.monitor and self.monitor.isRunning():
            self.monitor.stop()
            if not self.monitor.wait(9000):
                event.ignore()
                QMessageBox.warning(self, "Finishing probe", "A network probe is still completing. Retry close.")
                return
        event.accept()


def run_gui(db_path: Path) -> int:
    app = QApplication.instance() or QApplication(sys.argv)
    app.setFont(QFont("Segoe UI", 10))
    window = MainWindow(db_path)
    window.show()
    return app.exec()
