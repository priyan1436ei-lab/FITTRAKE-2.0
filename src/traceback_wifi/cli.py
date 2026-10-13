"""GUI and headless one-shot diagnostic entry point."""
from __future__ import annotations

import argparse
import json
import logging
import os
from pathlib import Path

from . import __version__


def default_data_dir() -> Path:
    if os.name == "nt":
        root = Path(os.getenv("LOCALAPPDATA") or (Path.home() / "AppData" / "Local"))
        return root / "TRACEBACK-WiFi"
    return Path.home() / ".local" / "share" / "traceback-wifi"


def main() -> int:
    parser = argparse.ArgumentParser(description="TRACEBACK WiFi: Windows network evidence console")
    parser.add_argument("--once", action="store_true", help="Run one read-only observation and output JSON")
    parser.add_argument("--no-external", action="store_true", help="Disable external TCP and DNS probes")
    parser.add_argument("--data-dir", type=Path, default=default_data_dir())
    parser.add_argument("--version", action="version", version=__version__)
    args = parser.parse_args()
    args.data_dir.mkdir(parents=True, exist_ok=True)
    logging.basicConfig(filename=args.data_dir / "traceback-wifi.log", level=logging.INFO,
                        format="%(asctime)s %(levelname)s %(name)s %(message)s")
    if args.once:
        from .collector import LiveCollector
        from .reasoning import assess
        sample = LiveCollector(external_probes=not args.no_external).collect()
        print(json.dumps({"sample": sample.to_dict(), "assessment": assess(sample).to_dict()},
                         indent=2, ensure_ascii=False))
        return 0 if sample.link != "unknown" else 2
    from .gui import run_gui
    return run_gui(args.data_dir / "evidence.sqlite3")
