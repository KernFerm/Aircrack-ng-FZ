# Changelog

## 1.0.3 — 2026-09-26

- Corrected all fixed-width integer formatting reported by GitHub CodeQL.
- Replaced non-portable `uint32_t`/`uint64_t` format assumptions with `PRIu32`/`PRIu64`.
- Removed shell-command construction from the Windows host-test runner.
- Restricted device-fixture generation to fixed repository paths.
- Achieved an authenticated Snyk Code result of zero issues at low-or-higher severity.
- Rebuilt and validated the FAP for target f7, API 87.1.
- Added the ACF1 bounded UART protocol and External Aircrack-ng Flipper view.
- Added a Raspberry Pi/Linux bridge that launches genuine `airodump-ng` and reports capture-derived counters.
- Added external UART baud, Wi-Fi channel, protocol, and application-version settings.
- Added Raspberry Pi wiring, monitor-mode, manual launch, and systemd setup documentation.
