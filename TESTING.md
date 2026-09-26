# Testing

## Automated parser suite

Run:

```powershell
python tests/run_tests.py
```

The host-native C tests compile `acf_parser.c`, `acf_external_protocol.c`, and the host-only `parser_test.c.host` harness with MSVC `/W4 /WX` (or `cc -Wall -Wextra -Werror` elsewhere) and validate:

- known-answer PCAP beacon/SSID/BSSID, short control-frame, ordinary EAPOL, and QoS/HT-control EAPOL classification;
- known-answer PCAPNG section/interface/enhanced-packet parsing;
- known-answer IVS2 BSSID/ESSID record parsing;
- malformed record lengths and truncated input;
- cancellation before record processing;
- 50,000-record/2 MB input with a measured maximum read request of 512 bytes;
- upstream Aircrack-ng `test/wpa.cap`, copied unchanged to `tests/fixtures/wpa.cap`, with real packet and EAPOL results.
- exact ACF1 INFO/STATUS parsing, fragmented UART delivery, oversized-line rejection, malformed fields, and 64-bit overflow rejection.

Result on 2026-09-26: all parser tests passed.

The companion's host tests run with `python tests/test_bridge.py` and validate real 802.11/Radiotap frame classification, EAPOL recognition, unsupported-link rejection, and bounded protocol tokens. Result on 2026-09-26: 4/4 passed. `python -m py_compile companion/aircrack_fz_bridge.py` also passed.

## Firmware build validation

```powershell
python -m ufbt clean
python -m ufbt
```

Validated against official SDK 1.4.3, target f7, API 87.1. Compiler and linker diagnostics are treated as errors by the SDK build. The artifact is `dist/aircrack_ng_fz.fap`.

Current release artifact: 41,356 bytes; SHA-256 `2B18E51D3705863F430900BEB777688F77B893B8D25F0E96F9123325C3CAC986`.

A source-only temporary tree containing only `application.fam` and the six production C/header files was cache-cleaned and fully recompiled on 2026-09-25. All three production C files compiled, linked, passed APPCHK, and generated a genuine FAP, confirming that ignored/generated files are not build inputs.

## On-device results

Tests performed on an attached stock Flipper Zero running official firmware 1.4.3:

- The internal CC1101 opened at an actual calibrated frequency of 433.919 MHz and displayed changing hardware RSSI values. Back released the mode cleanly, and a second open/close cycle succeeded.
- The 315.00 MHz setting opened at the CC1101's calibrated 314.999 MHz with a measured -91.5 dBm sample. No threshold crossing occurred, so events remained 0 and the timestamp correctly remained unavailable.
- The 868.35 MHz setting opened successfully and measured -94.5 dBm. No threshold crossing occurred, so events remained 0 and the timestamp correctly remained unavailable.
- The 915.00 MHz setting opened at the CC1101's calibrated 914.999 MHz. Three distinct real threshold crossings incremented events from 0 through 3 and populated/updated `Last` with RTC timestamps.
- NFC no-tag operation remained in `Scanning`, did not invent a detection, returned with Back, and did not crash.
- LF RFID no-tag operation remained in `Scanning`, did not invent a detection, returned with Back, and did not crash.
- The upstream `wpa.cap` fixture was copied unchanged to the SD card and parsed on-device: PCAP, DLT 119, 13 packets, 3,004 captured bytes, management/data/control 1/6/6, 2 protected frames, 4 EAPOL frames, 0 IVS2/WPA records, with SSID and BSSID populated from the capture.
- Aircrack-ng upstream `test1.pcap` was parsed unchanged on-device through the `.pcap` menu: PCAP, DLT 127, 192 packets, 25,081 captured bytes, management/data/control 147/45/0, 0 protected frames, 45 EAPOL frames, and captured SSID/BSSID values.
- A PCAPNG lossless re-container of the 13-packet upstream `wpa.cap` was parsed on-device: PCAPNG, DLT 119, 13 packets, 3,004 captured bytes, management/data/control 1/6/6, 2 protected frames, 4 EAPOL frames, and the same captured SSID/BSSID values.
- An IVS2 conversion containing the upstream capture's genuine SSID/BSSID metadata was parsed on-device: IVS2, 1 IVS2 record, 0 WPA records, SSID `test`, captured BSSID, and no packet/EAPOL values claimed.
- A deliberately malformed `.cap` input was selected on-device and rejected with `Malformed`; no analysis result was produced.
- Hardware CSV logging was enabled and verified by reading the resulting SD-card file over the official USB storage tool. Ten consecutive records contained the calibrated frequency `433919830`, changing hardware RSSI values from -87.5 to -79.5 dBm, and a threshold event transition from 0 to 1. Identifier fields remained empty because Sub-GHz RSSI activity supplies no identifier.
- Report generation was triggered on-device and the resulting app-scoped `/data/report.txt` was read back from `/ext/apps_data/aircrack_ng_fz/report.txt`. It contained a real RTC generation time, 4 accumulated radio events, truthful zero/Unknown capture fields for the post-reinstall session, and no handshake claim.
- With the app already running and the microSD removed, Report generation failed closed with `Report failed / Check SD card and free space`; the app remained responsive and did not claim a write succeeded.
- With hardware logging enabled and the microSD removed, live Sub-GHz measurement remained responsive while the UI displayed `LOG ERROR: check SD`; no unsaved CSV record was presented as successful.
- After SD reinsertion and remount, the error cleared and logging resumed automatically. USB readback showed the CSV had grown to 8,142 bytes with new RTC timestamps, calibrated `433919830` Hz values, changing RSSI, and real event transitions after recovery.
- The worker-thread Resource Self-Test completed 25/25 real start/stop cycles for each of Sub-GHz, NFC, and LF RFID (75 hardware acquisition/release operations total) without a crash.
- A second Resource Self-Test was cancelled at 1/25. The worker stopped, released the active backend, and displayed `All resources were released` without a crash.
- A temporary 12,353,949-byte PCAP stress file containing 50,000 repeated genuine upstream packet records was started on-device and cancelled with Back. The worker returned `Cancelled`, closed the file, and produced no partial analysis result.
- The same 50,000-record stress file was then allowed to complete on-device: PCAP/DLT 119, 50,000 packets, 11,553,925 captured bytes, management/data/control 3,847/23,077/23,076, protected 7,692, EAPOL 15,385, SSID `test`, and the captured BSSID. Free heap was identical before/after at 112,272 bytes, global minimum free heap was 40,944 bytes, and the 3,072-byte worker stack retained a 1,884-byte high-water margin (maximum use 1,188 bytes).
- A 30-byte truncation of the genuine upstream PCAP was parsed on-device and rejected as `Malformed`; no partial analysis result was produced.
- After both lifecycle tests, the stock Sub-GHz, NFC, and 125 kHz RFID applications opened and scanned normally with no busy state, freeze, or crash, confirming resource cleanup across application boundaries.
- The final candidate FAP passed target/API validation and was installed over USB on 2026-09-26.

These results validate resource acquisition, idle/no-tag behavior, genuine Sub-GHz measurement, and the tested cleanup paths. They do not validate NFC or LF tag identification because no authorized tags were available. They also predate the external Linux/Pi controller and therefore do not validate its physical UART or monitor-mode path.

The installed FAP was scanned after the on-device fixture tests: it contains none of the fixture filenames or paths. Production C/header sources contain no TODO, FIXME, placeholder, pseudocode, simulation, example-result, transmit, replay, emulation, cloning, brute-force, deauthentication, injection, or private-header implementation path. The only `injection` source match is explanatory compatibility text stating that it is unavailable.

## Remaining on-device acceptance

These tests require a physical, authorized Flipper Zero and cannot be truthfully replaced by simulation:

1. Verify no transmission with a spectrum receiver; the source and imports contain no TX call.
2. NFC: scan authorized ISO14443-A/B, ISO15693, and FeliCa samples where available; verify only detected protocols appear and removal/re-entry remains responsive.
3. LF RFID: read authorized tags of multiple supported protocols; compare decoded identifier bytes with the stock RFID app.
4. Remove the SD card during saved-file parsing; verify a closed error and no crash. Repeat report, logging, and parsing with a full/read-only card. SD removal during report generation and live logging has already passed as recorded above.
5. With a Raspberry Pi and authorized monitor-mode adapter, verify the ACF1 handshake, real Aircrack-ng/interface display, start/stop behavior, increasing capture-derived counters, saved PCAP path, disconnect recovery, and clean UART/expansion release. This is pending because the hardware is not yet available.

No claim of complete physical tag/protocol coverage should be made until the remaining checklist is executed on authorized hardware and the results are recorded here.

## Snyk status

- Dependency/repository analysis: not applicable; Snyk detected no supported target manifest.
- Authenticated Snyk Code analysis on 2026-09-26 initially reported eight low-severity findings in host-only test tooling: two shell-command construction paths and six unrestricted fixture paths. No production C/FAP finding, medium finding, or high finding was reported.
- The test runner now invokes a compiler from fixed standard Visual Studio locations without a shell, and the fixture generator now uses fixed repository-contained input/output paths.
- The authenticated rescan with `snyk code test --severity-threshold=low --remote-repo-url=https://github.com/KernFerm/Aircrack-ng-FZ` completed with `Total issues: 0` and exit code 0. No finding was ignored or suppressed.

## CodeQL formatting remediation

GitHub CodeQL reported 15 high-severity `cpp/wrong-type-format-argument` alerts in `aircrack_ng_fz.c`. The affected fixed-width `uint32_t`/`uint64_t` values now use the matching `<inttypes.h>` `PRIu32`/`PRIu64` macros; promoted byte arguments are explicitly cast for `%X`. The corrected production sources passed the warning-clean host suite and a cache-clean APPCHK build. GitHub will update the alert state after these changes are pushed and its code-scanning workflow reruns.
