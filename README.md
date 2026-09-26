# Aircrack-ng FZ

Aircrack-ng FZ inspects Aircrack-compatible capture files and analyzes the receive hardware built into a stock Flipper Zero. Version 1.0.5 includes an external Linux/Raspberry Pi mode: genuine Aircrack-ng runs on the Linux computer with a compatible monitor-mode Wi-Fi adapter, and the Flipper is its UART controller and live status display. The stock Flipper still does **not** contain Wi-Fi hardware.

Current release: **v1.0.5**.

## Install the FAP

You need a Flipper Zero with a working microSD card. The supplied release build targets official firmware 1.4.3, target f7, API 87.1. A firmware build with an incompatible API may require the app to be rebuilt.

### Install with qFlipper

1. Download `aircrack_ng_fz.fap` from the latest GitHub release or from this repository's `dist` folder.
2. Connect the Flipper Zero by USB and open qFlipper.
3. Open the microSD card file browser.
4. Open `apps`, then `Tools`.
5. Copy `aircrack_ng_fz.fap` into `/ext/apps/Tools/`.
6. Safely disconnect the device.
7. On the Flipper, open **Apps → Tools → Aircrack-ng FZ**.

The filename ends in `.fap` (Flipper Application Package), not `.fab`.

### Install directly from a microSD card

Put the microSD card in a computer, copy `aircrack_ng_fz.fap` to `apps/Tools/`, safely eject the card, and return it to the Flipper Zero. The app then appears under **Apps → Tools**.

## Use the application

### Offline Aircrack analysis

1. Copy an authorized `.cap`, `.pcap`, `.pcapng`, or `.ivs`/IVS2 file anywhere on the Flipper's microSD card.
2. Open **Offline Aircrack Analysis** and select the menu entry matching the file extension.
3. Use the file browser to select the capture.
4. Wait for the result screen. Press **Back** while analyzing to request safe cancellation.

The result contains only values actually parsed from the selected file: format, data-link type, packet and byte counts, 802.11 management/data/control counts, protected frames, EAPOL frames, IVS2/WPA records, and the first valid SSID/BSSID found. An EAPOL count is not claimed to be a complete or valid WPA handshake. Malformed or unsupported input is rejected without producing an analysis result.

### Live Sub-GHz analyzer

1. Select **Settings** to choose 315.00, 433.92, 868.35, or 915.00 MHz and optionally enable CSV logging.
2. Open **Sub-GHz Analyzer**.
3. The screen shows the CC1101's calibrated receive frequency, live RSSI, threshold-crossing event count, last-event timestamp, and signal history.
4. Press **Back** to stop and release the radio.

This is a receive-only activity analyzer. An event is an RSSI threshold crossing, not a decoded Sub-GHz packet and not Wi-Fi traffic. When logging is enabled, genuine measurements are written to `/ext/apps_data/aircrack_ng_fz/radio_log.csv`. `LOG ERROR: check SD` means the app could not write the current record and will retry.

### NFC and LF RFID analyzers

- Open **NFC Analyzer** and present an authorized 13.56 MHz tag to identify a detected technology/protocol.
- Open **LF RFID Analyzer** and present an authorized 125 kHz tag to display the protocol and decoded identifier bytes reported by the official Flipper worker.
- `Scanning` means no supported tag has been detected. The app does not invent a result when no tag is present.
- Press **Back** before opening another radio application so the current backend is released.

### External Aircrack-ng on Raspberry Pi/Linux

This mode uses the real `airodump-ng` executable on the companion computer; it does not imitate packets or generate results. Install and configure the companion first by following [EXTERNAL_WIFI.md](EXTERNAL_WIFI.md).

1. Connect the Flipper and Pi with crossed 3.3 V UART TX/RX and a common ground.
2. Start the bridge on the Pi with an already-created monitor-mode interface.
3. In **Settings**, select the same UART baud and the authorized Wi-Fi channel.
4. Open **External Aircrack-ng**. The screen must report the Pi's actual Aircrack-ng version and interface.
5. Press **OK** to start/stop a real `airodump-ng` capture. The displayed packet, frame-type, byte, and EAPOL counters come from the growing capture file. Captures remain on the Pi at the path reported by the bridge.
6. Press **Back** to stop capture, close UART, and restore the Flipper expansion service.

The complete unmodified Aircrack-ng command-line suite remains available directly on the Pi. The Flipper UI currently controls passive capture; it does not expose arbitrary shell commands or disruptive packet-injection/deauthentication operations.

### Saved files, reports, and diagnostics

- **Saved Files** opens existing `.nfc`, `.rfid`, and `.sub` files read-only through the official format loaders.
- **Reports** writes measured/parser session results to `/ext/apps_data/aircrack_ng_fz/report.txt`.
- **Session Statistics** shows counters for the current app session. They reset when the app closes; saved reports and CSV logs remain.
- **Resource Self-Test** performs 25 real start/stop cycles for each radio backend. It can be cancelled with **Back** and does not transmit.

## What the app does not do

Aircrack-ng FZ does not transmit or capture Wi-Fi over the Flipper's native radios. Its external bridge performs passive capture through genuine Aircrack-ng on separate Linux hardware; it does not expose packet injection, replay, deauthentication, or jamming. The Flipper-side offline parser does not validate WPA handshakes or recover keys. Sub-GHz, NFC, and LF RFID observations are never presented as Wi-Fi results.

Only inspect files, tags, and credentials that you own or are authorized to test. See [FEATURE_MATRIX.md](FEATURE_MATRIX.md), [BACKEND_COMPATIBILITY.md](BACKEND_COMPATIBILITY.md), [SECURITY.md](SECURITY.md), and [TESTING.md](TESTING.md) for exact support and validation boundaries.

## Build from source

Requirements: Python 3, `ufbt` 0.2.6 or newer, and official firmware/SDK 1.4.3 (API 87.1) or a compatible SDK.

```powershell
python -m pip install --upgrade ufbt
python -m ufbt update --channel release
python -m ufbt
```

The build creates `dist/aircrack_ng_fz.fap`. To build inside a full official firmware checkout, place the project at `applications_user/aircrack_ng_fz` and run:

```sh
./fbt fap_aircrack_ng_fz
```

## License

This repository is free software distributed under the **GNU General Public License, version 3 (`GPL-3.0`)**. Aircrack-ng-derived material retains its compatible upstream `GPL-2.0-or-later` attribution. See [LICENSE](LICENSE), [NOTICE](NOTICE), and [UPSTREAM_VERSION.md](UPSTREAM_VERSION.md).
