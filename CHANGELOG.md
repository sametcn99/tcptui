# Changelog

All notable changes to this project are documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [1.0.0] - 2026-10-13

### Added
- Category-based filter language: field expressions with comparison and
  regex operators, wildcards, byte units, `and`/`or`/`not` and parentheses
  (`process:chrome and tx>1MB`); live match count and inline errors while
  typing; filter history; quick presets on keys 1-8.
- Multi-key sort order editor (`o`); the chain persists in the config.
- Bandwidth chart (`B`): rolling per-interval Tx/Rx deltas with total and
  per-endpoint series.
- Alert rules (`A`): field expressions fire on newly appearing endpoints.
- Coloring rules (`A`, Colors tab): Wireshark-style row styles.
- Age column with first-seen timestamps carried through snapshot diffs.
- Top processes by endpoint count and by transferred bytes in statistics.
- Search term highlighting inside matching cells.
- Shift+arrow range marking for batch close/kill.
- GeoIP country column (feature `geoip`): MaxMind GeoLite2-Country
  database resolved per remote address with flags; soft-hidden without a
  database.
- Named view profiles (`P`): filter + sort + visibility as one keystroke.
- In-app settings screen (`M`) persisted to `%APPDATA%/tcptui/config.toml`.
- Process detail popup: Authenticode signature status (WinVerifyTrust) and
  the hosting user account.
- Experimental ETW mode (`--etw`): real connect/disconnect events from the
  Microsoft-Windows-Kernel-Network provider; true ages and transient
  connection logging; requires an elevated terminal and falls back to
  polling on any failure.
- Optional VirusTotal lookups (feature `virustotal`, `V` key) with an API
  key in config.toml.
- `tcpvcon`: `-j/--json` output.
- Themes: dark, light, gruvbox, nord, solarized-dark, solarized-light.
- GitHub Actions CI (fmt, clippy, tests, release build) and tag-triggered
  release workflow publishing zipped binaries with checksums.
- Scoop manifest under `packaging/scoop/`.
- MIT license.

### Fixed
- Running on the legacy Windows console (conhost): kitty keyboard
  enhancements are only enabled when supported, and fatal startup errors
  now keep the console open so double-clicked launches show the message.

## [0.4.0] - 2026-10-13
- Authenticode signature status and experimental ETW mode.

## [0.3.0] - 2026-10-13
- GeoIP country column, view profiles, settings screen.

## [0.2.0] - 2026-10-13
- Advanced filtering/sorting, bandwidth chart, alert and coloring rules.

## [0.1.0] - 2026-10-13
- Initial release: full endpoint table (TCP/UDP, IPv4/IPv6) with process,
  service and PID resolution; TCPView-style change highlighting; reverse
  DNS; search/filter/sort; close connection; end process; whois; export
  (CSV/TSV/JSON/TXT); clipboard; EStats byte counters; `tcpvcon` CLI.
