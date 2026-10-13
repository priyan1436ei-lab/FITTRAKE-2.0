# Manual acceptance tests — run on a REAL Windows 10/11 Wi-Fi adapter

Record Windows version, Wi-Fi adapter driver version, WLAN AutoConfig service status and whether Location for desktop apps is enabled. Redact SSID/BSSID before sharing logs.

1. **Connected:** Connect to an authorized network, run `python -m traceback_wifi --once`; verify that `link`, SSID, BSSID, signal, channel and authentication (where available) agree with Windows Wi-Fi settings / `netsh wlan show interfaces`. Do not accept fabricated values.
2. **Disconnected:** Disable Wi-Fi association without uninstalling adapter. Verify `disconnected` and skipped probes. Reconnect. After two samples, incident opens; after two healthy samples, closes. Note: this takes longer than exactly 10 seconds because probes add latency.
3. **No adapter:** Disable or remove the WLAN adapter. Verify `no_adapter` (or an explicit API error). No fabricated SSID/graph data should appear.
4. **Location denied:** Revoke WLAN location permission where applicable. Verify explicit access error or redacted fields and sensible recovery instructions; no crash.
5. **DNS issue:** On a *permitted test machine* configure or block DNS so nslookup fails while external TCP succeeds, verify `dns_suspected`. Restore settings manually.
6. **TCP target blocked:** Block test to 1.1.1.1:443 while DNS still resolves. Verify `tcp_reachability` and limitation text; do **not** report 'internet down'. Restore settings.
7. **VPN/Ethernet:** Connect VPN or Ethernet. Verify UI continues to call gateway "default route" and does not claim it is necessarily the Wi-Fi router.
8. **No external:** Uncheck external diagnostics; verify probes are `skipped`, signal is still measured, and no false TCP incidents open from missing probes.
9. **Challenge:** Wait for 5 samples; capture baseline, do a harmless manual change, wait for 3+ new samples; compare actual results and verify stored challenge. Attempt immediate after capture and ensure it is blocked.
10. **Export:** Save JSON. Check `samples`, `incidents`, `challenges` are present and contain observations; never contain Wi-Fi credentials.
11. **Packaging:** Build on Windows with `scripts\build_windows.bat`, then launch the EXE on a supported clean Windows PC. Copy complete distribution folder. Check PySide6 DLLs and native WLAN access.
12. **Reliability:** Leave app running 1+ hour and alternate connected/disconnected; verify no runaway memory / locked SQLite DB / unhandled exception; check logfile.

These checks are NOT automatically completed by Linux/unit tests.
