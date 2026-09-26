# Feature matrix

| Feature | Status | Evidence/boundary |
|---|---|---|
| Classic PCAP/CAP | Supported | LE/BE microsecond and nanosecond magic; v2.4; 802.11, Prism, Radiotap, PPI link types |
| PCAPNG | Supported subset | Section Header, Interface Description, Enhanced Packet blocks; per-section endianness; up to 8 interfaces |
| Aircrack IVS2 | Supported | Version 1 record validation, BSSID/ESSID metadata, WPA-record counts |
| 802.11 frame summary | Supported offline only | Management/control/data/protected counts from supplied bytes |
| SSID/BSSID | Supported offline only | First valid beacon/probe-response values; never synthesized |
| EAPOL identification | Supported offline only | LLC/SNAP EtherType `0x888e`; not claimed as a complete/valid handshake |
| WPA handshake validation | Not implemented | Would require replay-counter/message/MIC validation |
| WEP/WPA key recovery | Not implemented | No unvalidated crypto or recovery claims |
| Capture decryption | Not implemented | No keys are accepted or produced |
| Wordlists | Not implemented | Avoids presenting unusable CPU/memory-heavy cracking |
| Live Wi-Fi/monitor mode/injection | Impossible on stock hardware | No general-purpose 802.11 chipset |
| Live Sub-GHz | Supported | Internal CC1101 RX, real RSSI, hysteretic activity crossings, hardware frequency, time, history; no TX |
| Live NFC | Supported detection | Actual stock NFC scan and protocol identification; scanner API does not expose raw frames or UID |
| Saved NFC | Supported | Official `nfc_device_load`; protocol, device name, legitimate saved UID in hex |
| Live LF RFID | Supported | Actual stock LF worker; protocol and decoder data bytes |
| Saved LF RFID | Supported | Official dictionary file loader and decoder |
| Saved Sub-GHz | Supported | Official FlipperFormat header/frequency/protocol validation; read-only |
| Logging | Supported | Optional CSV of actual hardware values/events; off by default |
| Reports | Supported | Timestamped local summary, no inferred results |
| Cancellation | Supported | Per-record/block cooperative cancellation and joined worker |
| Resource lifecycle test | Supported | Cancellable worker performs 25 real acquire/release cycles for Sub-GHz, NFC, and LF RFID |

Malformed input returns a visible error. Unsupported formats/link types are not guessed. Unavailable measurements remain absent.
