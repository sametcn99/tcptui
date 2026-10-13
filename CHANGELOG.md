# Changelog

All notable changes to this project are documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added
- Pause/resume live updates (`p`): while paused the title bar shows a
  `PAUSED` indicator, incoming snapshots are dropped before the diff runs
  so the table, colors, statistics and bandwidth chart hold still for
  inspection; ETW connect timestamps keep buffering so ages stay accurate
  after resuming; `F5` is inert while paused.
- Help popup rendered as a two-column grid: entries balanced across two
  aligned key columns with section headers kept in place, row-based
  scrolling (`j/k`, `PgUp/PgDn`) and a hint on the bottom border.

### Fixed
- Column headers were invisible in the main table: the header row was
  built as a single cell, clipping every title into the 2-character
  gutter. Headers are now one cell per column, aligned with the grid and
  still showing sort indicator arrows.
- Mouse click geometry was off by the header line: header clicks now hit
  the row inside the top border (sorting works again, Shift+click still
  appends a sort key) and body clicks select the correct row.
- Pending alerts covered the shortcut-hint line in the footer until
  acknowledged. The footer now grows to three lines while alerts are
  pending: the alert message (truncated to the terminal width) gets its
  own line and hints/statistics stay visible.

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
