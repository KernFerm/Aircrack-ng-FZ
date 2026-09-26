# Porting analysis

## Upstream architecture reviewed

- `aircrack-ng`: capture/IVS ingestion, AP/station bookkeeping, WEP statistical attacks, WPA/WPA2 key derivation and MIC verification, wordlist loops, session handling, and CPU acceleration.
- `airodump-ng`: monitor-interface capture, radiotap/Prism/PPI normalization, 802.11 frame classification, AP/station state, capture/CSV/IVS writers, channel control, and terminal UI.
- `airdecap-ng`: PCAP input, 802.11/WEP/WPA decryption, Ethernet conversion, and PCAP output.
- `airmon-ng`: shell/platform orchestration for driver monitor mode. It has no portable radio core.
- `aireplay-ng`: driver-backed injection, capture, replay timing, and attack state machines.
- `include/aircrack-ng/support/pcap_local.h`: PCAP link types and IVS2 file and record definitions adapted by this port.
- `lib/osdep`: OS/driver abstraction for monitor-mode read/write, injection, and channel control.
- `test` and `test/cryptounittest`: capture fixtures, integration scripts, PBKDF/HMAC/CMAC and PMK known-answer tests, malformed-input regressions, and utility tests.

## Port decision

Portable and useful on stock hardware:

- streaming PCAP global/record validation;
- PCAPNG section/interface/enhanced-packet validation;
- IVS2 record validation;
- bounded 802.11 header classification and EAPOL EtherType identification;
- read-only SSID/BSSID extraction from actual offline beacon/probe-response frames;
- common capture counters and cancellation architecture.

Portable in theory but deliberately not included in this memory-constrained first port:

- WEP statistical key recovery;
- WPA/WPA2 PBKDF2/MIC cracking and wordlist processing;
- decryption/output rewriting;
- large AP/station tables and session databases.

Those operations need more RAM, sustained CPU, larger crypto integration, and extensive known-answer validation. The app does not expose inert menu entries or pretend they succeeded.

Not portable to stock Flipper Zero:

- monitor mode and live 802.11 capture;
- channel hopping and Wi-Fi RSSI;
- frame injection, deauthentication, replay, fake AP, and packet forging;
- `airmon-ng` driver management;
- Linux/BSD/macOS/Windows `osdep` implementations.

## Adaptation details

`acf_parser.c` preserves Aircrack-ng's PCAP link-type values, IVS2 magic/version, flag meanings, and packed on-disk semantics without importing host ABI structs. Every multibyte field is decoded explicitly, avoiding alignment and host-endian assumptions. Records are streamed through an abstract reader. Packet storage is capped at a 512-byte inspection prefix; record lengths are bounded at 16 MiB and checked against snap length, original length, block length, current position, and total file size.

The hardware additions in `acf_radio.c` are not upstream Aircrack-ng backends. They are separate Flipper-specific modes using public firmware 1.4.3 APIs:

- `subghz_devices_*` with internal CC1101, receive-only OOK preset, hardware frequency validation, RSSI-threshold activity events, and deterministic idle/sleep/deinit;
- `nfc_alloc`, `nfc_scanner_*`, and official protocol naming;
- `lfrfid_worker_*` and `protocol_dict_*` for stock 125 kHz detection and decoding.

## Resource and threading model

Offline and saved-file work runs on a 3072-byte worker stack. The GUI only changes views and renders completed results. A volatile cancellation flag is checked for every record/block. Back requests cancellation, and teardown joins the worker before freeing storage or GUI state.

NFC and LF use SDK-owned worker/event execution. Sub-GHz follows firmware 1.4.3's `rx_carrier` sequence and samples hardware RSSI; hysteretic threshold crossings produce activity timestamps and a fixed 64-byte history. Logging runs on a separate bounded worker, never the GUI thread. No unbounded capture, packet, AP, station, wordlist, or log buffer exists.
