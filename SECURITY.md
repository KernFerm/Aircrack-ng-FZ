# Security

## Scope and safe-use policy

Use only with files, radios, networks, and physical credentials you own or are authorized to inspect. The native Flipper functions are read-only with respect to RF. The external Linux bridge starts passive `airodump-ng` capture only; it has no replay, clone, injection, authentication bypass, brute-force, deauthentication, or jamming command.

## Native review

- Lengths are decoded from bytes, not cast to packed host structs.
- Additions and seeks are checked for 32-bit overflow and against actual file size.
- PCAP snap length, captured/original lengths, PCAPNG block alignment/trailers/interfaces, IVS2 payload lengths, SSID tag lengths, and 802.11 header offsets are validated before use.
- Capture input is streamed; only a 512-byte packet prefix is retained. Capture records above 16 MiB are rejected.
- SSIDs, protocol strings, identifiers, reports, and log lines have fixed bounds and explicit terminators.
- Saved NFC/RFID/Sub-GHz formats are loaded through public firmware parsers where available.
- Worker lifetime is joined before app state is freed. Cancellation is checked between records. Hardware callbacks do not retain borrowed SDK event pointers.
- Every successful radio acquisition has a stop/free path. Sub-GHz is stopped, idled, slept, charging suppression is reversed, and the device registry is deinitialized; NFC scanner/HAL and LF mode/thread/dictionary are released.
- UI and logging consumers copy one mutex-protected radio snapshot, so callbacks cannot expose partially updated protocol, identifier, timestamp, RSSI, or history fields.
- Storage open failure, SD removal/read failure, malformed/truncated input, unsupported format/link type, allocation failure reported by constructors, cancellation, and short report/log writes fail closed. Live CSV failures are displayed and retried rather than counted as saved. There is no simulated fallback.
- The external decoder bounds every UART line, requires exact ACF1 token counts, rejects malformed and overflowing integers, and copies reported strings into fixed-size fields.
- The Linux bridge accepts only four fixed protocol commands. Interface names, serial devices, baud rates, and channels are allowlisted; subprocesses use argument arrays without a shell. Captures use bridge-generated UTC names.
- The Flipper disables the firmware expansion listener before acquiring USART, serializes transmit access, stops asynchronous RX before freeing the worker/stream, releases USART, and restores expansion on exit.

## Known limitations

The Sub-GHz RSSI-threshold counter is an activity statistic, not a decoded packet counter. The NFC scanner reports protocol presence but not generic raw frames or a live UID. PCAPNG support intentionally rejects unsupported link types and does not parse Simple Packet Blocks. The external bridge requires root or equivalent capture permissions and trusts the locally configured Aircrack-ng/`iw` executables and monitor interface. UART has no cryptographic authentication and must be a direct physical connection. These limits are exposed in the UI/docs rather than guessed around.

## Snyk review

Authenticated Snyk Code analysis on 2026-09-26 initially reported eight low-severity test-tool findings and no production C/FAP, medium, or high findings. Shell-based MSVC discovery was replaced with a fixed-location, argument-vector invocation, and the fixture generator was restricted to fixed repository-contained paths. After the external C/UART and Python companion were added, another authenticated rescan at low-or-higher severity completed with zero issues. No finding was ignored or suppressed.

GitHub CodeQL's 15 high-severity wrong-format-type alerts were remediated by using `<inttypes.h>` fixed-width format macros for `uint32_t` and `uint64_t` values and correct promoted types for hexadecimal byte output. The cache-clean host and official SDK builds pass. Remote alerts close only after the corrected commit is pushed and GitHub reruns code scanning.

## Vulnerability reporting

Report memory-safety, parser, or resource-lifetime issues to the repository owner without attaching sensitive captures, access credentials, or secrets. Do not publish live credential data in an issue.
