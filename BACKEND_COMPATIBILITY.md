# Backend compatibility

| Backend | Hardware/API | Frequency | Values exposed | Explicitly unavailable |
|---|---|---:|---|---|
| Offline Aircrack | SD storage + bounded parser | From file only | Format, link type, frame counts, bytes, EAPOL count, first real SSID/BSSID, IVS2 metadata | Live Wi-Fi, key recovery, decryption |
| External Aircrack-ng | Linux/Raspberry Pi, genuine Aircrack-ng, monitor-mode Wi-Fi adapter, 3.3 V UART | Authorized channel 1-13 | Backend version/interface, process state, capture path, real packets/bytes/frame types/EAPOL from growing PCAP | Stock-Flipper Wi-Fi, arbitrary shell commands, injection/deauthentication/jamming controls |
| Sub-GHz | Internal CC1101 via `subghz_devices` | User selection; checked by device API | Tuned frequency, real RSSI, threshold-crossing activity, timestamps, history | Wi-Fi concepts, TX, replay, jamming, protocol claims from RSSI alone |
| NFC | Stock ST25R3916 via `nfc_scanner` | 13.56 MHz | Detection and identified NFC protocol | Generic raw RF/frame capture, live UID in scanner mode, auth bypass |
| LF RFID | Stock LF frontend via `lfrfid_worker` | 125 kHz | Detection, decoded protocol and identifier bytes | Authentication bypass, brute force, writing, emulation, cloning |
| Saved files | Official `nfc_device`, LF dictionary, FlipperFormat loaders | Recorded metadata only | Legitimately stored protocol, identifier, frequency, version | Replay/transmission and invented missing fields |

Sub-GHz receive frequencies offered by default are 315.00, 433.92, 868.35, and 915.00 MHz. The device API rejects frequencies outside hardware support. This application contains no TX call, so firmware regional transmit policy cannot be bypassed.

All Flipper symbols were compiled and linked against the official firmware 1.4.3 external SDK (target f7, API 87.1). No private firmware header or symbol is used. The external bridge requires Aircrack-ng, `iw`, Python 3, and pyserial on Linux. Physical Pi/UART/adapter validation is pending hardware availability.
