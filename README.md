# TRACEBACK WiFi

**Evidence-driven Windows Wi-Fi failure investigator — native desktop software, not a website or a mock dashboard.**

![status](https://img.shields.io/badge/status-Windows%20hardware%20validation%20pending-orange) ![python](https://img.shields.io/badge/python-3.11%2B-blue) ![license](https://img.shields.io/badge/license-MIT-green)

## What is implemented (v0.1)

- **Native Windows WLAN API (read-only):** Enumerate actual Wi-Fi adapters, connection state, SSID, BSSID, signal percentage, wireless channel (if available), authentication family (if available). No scraped mock data. May require Windows location permission.
- **Diagnostic probes:** Windows default-route gateway ICMP, external IPv4 TCP connect to `1.1.1.1:443`, and DNS `nslookup example.com`. Time bounded; off-network probes may be disabled. A blocked endpoint or gateway ICMP does **not** equal total internet failure.
- **Failure black box:** Fixed-interval (~5 sec plus the time to run probes) samples go into SQLite. Two consecutive Wi-Fi-link failures or external TCP/DNS test failures open incidents; two healthy checks close them. Brief failures may be missed.
- **Fingerprint + recurrence:** Stable SHA-256-derived signature and repeat counts for *class of observation*, not unique device or root cause. Repeated fingerprint means similar measurements, not the same underlying fault.
- **Investigations:** Multiple testable candidate causes (supporting, contradicting and missing evidence, and discriminating tests). Clear differentiated heuristic assessments (Wi-Fi link loss, DNS-path suspicion, external TCP-specific reachability, multiple probes failed, insufficient evidence), supporting observations and known limitations. No fake confidence scores.
- **Fix challenge:** Capture 3+ genuine baseline samples, manually make a reversible change, capture 3+ fresh samples; compare average signal quality and measured external TCP success rates. **Not** a causal experiment or proof of repair.
- **Local history:** SQLite WAL database under `%LOCALAPPDATA%\TRACEBACK-WiFi`, user-initiated JSON export, logs. No passwords or traffic payloads collected.
- **Dark Qt GUI:** Four navigable pages; live chart via pyqtgraph; incidents table, analysis and guided comparisons.

**NOT IMPLEMENTED:** automatic repair, machine-learning model, Windows native event-log correlation, nearby-network scanning, validated causal inference, installer wizard, packet capture, cloud accounts, or commercial certification. Do not describe v0.1 as these things.

## Setup on Windows 10 / Windows 11

Install [Python 3.11+](https://www.python.org/downloads/windows/) (64-bit recommended) and enable the Windows WLAN AutoConfig service.

From an ordinary PowerShell window in the unpacked project folder:

```powershell
py -3 -m venv .venv
.venv\Scripts\python.exe -m pip install -e .
.venv\Scripts\python.exe -m traceback_wifi
```

**Simplest start:** double-click `scripts\run_windows.bat` (creates local venv and installs dependencies on first launch).

One-shot read-only JSON check (even without the GUI):

```powershell
.venv\Scripts\python.exe -m traceback_wifi --once
.venv\Scripts\python.exe -m traceback_wifi --once --no-external
```

`--once` exits with code 2 if Wi-Fi cannot be observed. Do not use elevated/admin rights unless your environment requires them. If the UI says the adapter data is unavailable, check **Windows Settings → Privacy & security → Location**, WLAN AutoConfig, and the adapter driver. System admins can restrict WLAN access.

## Package as Windows `.exe`

Double-click `scripts\build_windows.bat`. This installs development dependencies, runs tests, and creates:

```
dist\TRACEBACK-WiFi\TRACEBACK-WiFi.exe
```

Copy the **whole** generated folder, not only the EXE. A fully packaged Windows application can only be built and validated on Windows; the provided source zip is not itself a compiled `.exe`.

## Build / test

```powershell
.venv\Scripts\python.exe -m pip install -e ".[dev]"
.venv\Scripts\python.exe -m pytest -q
```

Run the documented [Windows manual acceptance checks](tests/WINDOWS_QA.md) on hardware with a wireless adapter. Deterministic unit tests use **explicit fakes in test code only**, never in the running app.

## Key limits and privacy

- Fixed 5-second interval happens **after** sequential probes complete, so the effective cadence can be longer. This is **not** packet-level monitoring.
- The default route is system-wide; if a VPN or Ethernet is active its gateway may **not** be your Wi-Fi router. Avoid attributing its ICMP result to Wi-Fi alone.
- Windows restricts certain WLAN fields unless location access is granted. Native WLAN API returns errors rather than bypassing permissions.
- BSSID is a hardware address; keep exported reports private unless you consciously scrub them.
- `nslookup` might be influenced by DNS settings; endpoint probes can be blocked. A positive/negative probe is endpoint-specific.
- v0.1 classifies based on the **current/latest** observation captured when an incident opens. It does not yet reconstruct event-causal timelines from the Windows Event Log.
- Users are responsible for deciding whether and how to change any settings. There is no automatic disruption of networking.

## Project layout

```
src/traceback_wifi/
  wlan.py        native Windows WLAN APIs
  collector.py   actual network diagnostics
  models.py      immutable observation records
  reasoning.py   evidence rules / incident engine / fingerprints
  hypotheses.py  differentiated candidate mechanisms and follow-up tests
  database.py    SQLite samples, incidents and before/after challenges
  service.py     polling worker thread
  gui.py         desktop Qt dashboard
  cli.py         startup and JSON diagnostic
scripts/         Windows runner / EXE packager
tests/           unit tests and hardware acceptance plan
```

## Originality

TRACEBACK WiFi is an implementation of a particular combined investigative workflow, not a verified world-first invention. Many individual features are established in existing software. Trademark, competitor and patent clearance are NOT established.

## License

MIT — see LICENSE. You are responsible for checking license compliance of your dependencies when distributing binaries.
"# FITTRAKE-2.0" 
