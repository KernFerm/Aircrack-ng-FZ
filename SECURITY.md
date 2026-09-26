# Security

## Scope and safe-use policy

Use only with files and physical credentials you own or are authorized to inspect. The application is read-only with respect to RF: it has no transmit, replay, clone, write, injection, authentication bypass, brute-force, deauthentication, or jamming path.

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

## Known limitations

The Sub-GHz RSSI-threshold counter is an activity statistic, not a decoded packet counter. The NFC scanner reports protocol presence but not generic raw frames or a live UID. PCAPNG support intentionally rejects unsupported link types and does not parse Simple Packet Blocks. These limits are exposed in the UI/docs rather than guessed around.

## Snyk review

On 2026-09-25, `snyk test --all-projects --json` reported that no supported dependency manifest exists in this native external-app repository. `snyk code test --json` was attempted but the installed CLI requires account authentication, which was not available and was not bypassed. No finding was suppressed. Native review therefore consists of the bounded-parser review above, host compilation with all warnings as errors, malformed-input tests, and the official SDK's compiler/linker/import checks.

## Vulnerability reporting

Report memory-safety, parser, or resource-lifetime issues to the repository owner without attaching sensitive captures, access credentials, or secrets. Do not publish live credential data in an issue.
