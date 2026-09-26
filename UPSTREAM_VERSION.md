# Upstream version record

| Field | Value |
|---|---|
| Repository | `https://github.com/aircrack-ng/aircrack-ng` |
| Commit | `2f393aefda9c8f1b1f2486c14d43d5708fe625e9` |
| Commit date | 2026-09-08T21:52:19-04:00 |
| Version source | `configure.ac` |
| Version | 1.7 development line (`version_major=1`, `version_minor=7`, `version_micro=0`) |
| Clone command | `git clone --depth 1 https://github.com/aircrack-ng/aircrack-ng.git upstream-aircrack-ng` |
| Upstream license | GNU GPL v2 or later, with the upstream OpenSSL linking exception where applicable |
| Firmware baseline | Official Flipper firmware 1.4.3 |
| SDK baseline | uFBT 0.2.6, release SDK 1.4.3, target f7, API 87.1 |

The unmodified upstream checkout is an analysis input, not an FAP build input. Desktop code depends on operating-system network interfaces, monitor-mode drivers, sockets, processes, terminal UI, SQLite/OpenSSL/libpcap, and memory budgets unavailable to an external Flipper app. The FAP carries only a small, audited parser adaptation; the upstream clone is intentionally not vendored into the application source directory.

