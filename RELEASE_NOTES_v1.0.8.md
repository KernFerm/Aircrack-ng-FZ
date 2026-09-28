# Aircrack-ng FZ v1.0.8

Aircrack-ng FZ provides real offline wireless-capture inspection, receive-only Flipper radio measurements, and an optional controller for genuine Aircrack-ng running on external Linux Wi-Fi hardware.

## Native Flipper features

### Offline capture inspection

- Streams authorized `.cap`, `.pcap`, `.pcapng`, and `.ivs`/IVS2 files from microSD.
- Parses real capture headers and reports format, data-link type, packet count, byte count, 802.11 management/data/control counts, protected frames, EAPOL frames, IVS2/WPA records, and the first valid SSID/BSSID.
- Rejects malformed, truncated, unsupported, or mismatched input without inventing a result.
- Treats EAPOL as a measured frame count, not proof that a complete WPA handshake exists.
- Supports safe worker cancellation and bounded memory use.

### Receive-only device analyzers

- Sub-GHz displays calibrated CC1101 frequency, live RSSI, threshold-crossing events, timestamps, and signal history at 315.00, 433.92, 868.35, or 915.00 MHz.
- Optional CSV logging records genuine measurements and rotates at 1 MiB, retaining only current and previous generations.
- NFC identifies technologies and protocols reported by the official Flipper NFC worker.
- LF RFID displays the protocol and decoded identifier bytes returned by the official RFID worker.
- Saved `.nfc`, `.rfid`, and `.sub` files open read-only through official format loaders.
- The resource self-test performs 25 real start/stop cycles per radio backend and verifies cleanup.

Sub-GHz activity is not Wi-Fi traffic, and NFC/LF RFID observations are never presented as Aircrack results.

## Genuine Aircrack-ng on Raspberry Pi/Linux

External mode runs real `airodump-ng` on a Raspberry Pi, Linux laptop, desktop, mini PC, or VM with a compatible monitor-mode Wi-Fi adapter. The Flipper is the 3.3 V UART controller and live status display.

The bridge uses a preconfigured monitor interface and bounded protocol. The Flipper can start or stop an authorized passive capture and display genuine packet, byte, frame-type, and EAPOL counters from the growing capture. Captures remain on the Linux system. UART text is never executed through a shell.

The stock Flipper has no Wi-Fi radio. This release does not claim native Wi-Fi capture, WPA key recovery, packet injection, replay, deauthentication, or jamming.

## Using the application

1. For offline analysis, copy a capture to microSD, select **Offline Aircrack Analysis**, choose its format, and select the file.
2. For Sub-GHz, select frequency/logging in **Settings**, then open **Sub-GHz Analyzer**.
3. For NFC or LF RFID, open the corresponding analyzer and present an authorized tag.
4. For external Wi-Fi capture, follow `EXTERNAL_WIFI.md`, connect crossed 3.3 V UART TX/RX plus GND, match the baud/channel, then open **External Aircrack-ng**.
5. Use **Reports** to transactionally save measured/parser results. A failed write preserves the previous valid report.

## Install

Requires official Flipper firmware 1.4.3 or later and a microSD card. Download `aircrack_ng_fz.fap`, copy it to `/ext/apps/Tools/`, then open **Apps → Tools → Aircrack-ng FZ**.

## v1.0.8 verification

- Native parser and UART protocol regression tests passed.
- External companion regression tests: 9 passed.
- Authenticated Snyk Code scan: 0 issues at low-or-higher severity.
- uFBT APPCHK: target f7/API 87.1, no unresolved symbols.
- FAP size: 44,316 bytes.
- SHA-256: `8A752311670EE204FCEB4499422C19911AA1A84AD8EB40335E5B34FFAFB157CC`

Use only files, radios, networks, and credentials you own or are explicitly authorized to test. Aircrack-ng FZ is GNU GPL v3 and preserves compatible upstream GPL attribution.
