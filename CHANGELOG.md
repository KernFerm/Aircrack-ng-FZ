# Changelog

## 1.0.6 — 2026-09-27

- Added a scrollable Settings > About page with version, native-mode, Linux/Raspberry Pi, safety, and license guidance.
- Made reports transactional and synchronized so a failed save cannot replace a valid report.
- Required successful CSV synchronization and added bounded 1 MiB current/previous log rotation.
- Initialized UART before its worker and added bridge heartbeat timeout/reconnection handling.
- Propagated bounded capture-directory, reader, process-exit, stderr, and shutdown failures to the Flipper.
- Prevented stale-reader reuse with collision-resistant capture names and explicit prior-session cleanup.
- Strengthened PCAPNG section, interface, snap-length, and packet-length validation.
- Strengthened IVS2 flag and payload validation and prevented binary SSIDs from reaching formatted UI text.
- Corrected invalid LF RFID protocol results and saturated accumulated radio-event statistics.
- Expanded parser and Linux companion failure-path regression tests.

## 1.0.5 — 2026-09-26

- Added a bounded ACF1 UART transport for an external Raspberry Pi/Linux backend.
- Added a Flipper controller screen for genuine passive `airodump-ng` capture.
- Added real capture-derived packet, byte, frame-type, and EAPOL counters.
- Added configurable external UART baud rate and authorized Wi-Fi channel.
- Added safe USART/expansion acquisition and release, including failed-start cleanup.
- Added a Linux companion daemon, systemd example, wiring instructions, and monitor-mode setup guide.
- Added host tests for the external protocol and Linux capture classifier.
- Rebuilt for target f7/API 87.1 and rescanned with zero Snyk Code findings.

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
