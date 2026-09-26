# Changelog

## 1.0.3 — 2026-09-26

- Corrected all fixed-width integer formatting reported by GitHub CodeQL.
- Replaced non-portable `uint32_t`/`uint64_t` format assumptions with `PRIu32`/`PRIu64`.
- Removed shell-command construction from the Windows host-test runner.
- Restricted device-fixture generation to fixed repository paths.
- Achieved an authenticated Snyk Code result of zero issues at low-or-higher severity.
- Rebuilt and validated the FAP for target f7, API 87.1.
