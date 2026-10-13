# tcptui

A terminal UI clone of [Sysinternals TCPView](https://learn.microsoft.com/en-us/sysinternals/downloads/tcpview) for Windows, written in Rust with [Ratatui](https://ratatui.rs).

It shows every TCP and UDP endpoint on the system (IPv4 and IPv6) together with the owning process, service and PID, updates live, and lets you close connections, end processes, run whois lookups, chart bandwidth, define alert and coloring rules, search with a structured filter language, sort by any column chain, and export — all from the terminal.

```
 tcptui  sort:Process ↑ resolve:off                                          1000ms
┌ 423 endpoint(s) ─────────────────────────────────────────────────────────────┐
│M  Process          PID    Proto Local Address        L-Port State      Age   │
│*  chrome.exe       39496  TCP   192.168.1.111         14720 ESTABLISHED 12s  │
│   Code.exe         35668  TCP   127.0.0.1              6907 LISTEN      3h   │
│   svchost.exe      1420   UDP   0.0.0.0                5353               1d  │
└──────────────────────────────────────────────────────────────────────────────┘
 ?:help  /:filter  1-8:presets  o:sort  B:chart  A:rules  c:close  K:kill  q:quit
 total 423 · tcp 288 (est 91 lsn 62 tw 5) · udp 135 · shown 423
```

## The package

| Binary | Description |
|---|---|
| `tcptui` | Interactive terminal UI |
| `tcpvcon` | Command-line companion, mirroring the tool that ships with TCPView |

## Feature overview

**Monitoring**
- All TCP/UDP endpoints, IPv4 + IPv6, with owning process, PID, hosted service, user account and Authenticode signature status
- TCPView-style change highlighting: new endpoints **green**, deleted **red**, state-changed **yellow**
- Age column (first-seen timestamps); with the experimental ETW mode these are true connect times
- Adjustable refresh rate (250 ms – 60 s, default 1 s), manual refresh (`F5`),
  pause/resume live updates (`p`) to freeze the table for inspection
- Statistics popup (`i`) with totals and top processes by count and by traffic
- Optional GeoIP country column with flags (see below)
- Experimental ETW mode (`--etw`): real connect/disconnect events, transient connection logging
- Bandwidth chart (`B`): rolling per-interval Tx/Rx deltas from the EStats counters, total system or selected endpoint (Tab)

**Filtering and search**
- Structured filter language: fields (`process path pid proto state laddr raddr addr lport rport port service tx rx change loopback connected`), operators (`= == != > >= < <= : =~ !~`), wildcards, byte units, `and`/`or`/`not` with parentheses
- Live match count and inline parse errors while typing; filter history (Up/Down); quick presets on keys `1`–`8`
- Incremental search (`Ctrl+F`) with highlighting and match jumping (`n`/`N`)
- Rules (`A`): alert expressions fired on new endpoints (⚠ indicator, event log) and Wireshark-style coloring rules

**Sorting and views**
- Multi-key sort order editor (`o`); `s` cycles, `S` reverses, header clicks sort (Shift+click appends)
- Grouped tree view by process (`G`); watch mode (`F6`); column setup (`C`); named view profiles (`P`); settings screen (`M`)
- Everything persists in `%APPDATA%\tcptui\config.toml`

**Actions**
- Close Connection (`c`) via `SetTcpEntry` — the same API TCPView uses; batch close/kill over marked rows (`Space`, Shift+arrows)
- End Process (`K`), whois (`w`, RFC 3912 referrals), VirusTotal lookup (`V`, optional feature)
- Copy to clipboard (`Ctrl+C` row — or TSV of all marked rows; `Ctrl+Shift+C` table; JSON via the right-click menu)
- Right-click context menu on rows; drag header edges to resize columns; Shift+wheel scrolls horizontally
- `tcptui --dump-frame <file> [--frame-size 120x30]` renders one live frame as text (screenshots, no terminal)
- View profiles can be exported/imported as `[[profile]]` TOML files (P popup)
- Process details include a system-traffic sparkline
- Export to CSV / TSV / JSON / text (`e`)

## Key map

| Key | Action |
|---|---|
| `?` | Help |
| `/` · `1`-`8` | Filter prompt · presets (tcp, udp, established, listen, loopback, non-loopback, new, clear) |
| `Ctrl+F` · `n`/`N` | Search · next/previous match |
| `s` · `S` · `o` | Cycle sort column · reverse · sort order editor |
| `B` · `A` | Bandwidth chart · rules (alerts/colors) |
| `P` · `M` · `C` | View profiles · settings · column setup |
| `t` · `u` · `U` · `L` · `r` | TCP · UDP · unconnected · loopback · resolve toggles |
| `G` · `F5` · `F6` | Group view · refresh now · watch process |
| `p` | Pause / resume live updates (freeze the table for inspection) |
| `Ctrl+P` | Command palette (fuzzy search over every action) |
| `c` · `K` · `w` · `V` · `e` | Close connection · end process · whois · VirusTotal · export |
| `Space` · Shift+arrows | Mark rows · mark a range |
| `i` · `g` · `x` | Statistics · event log · clear marks/alerts/filter |
| `q` / `Esc` | Quit / close popup |

## Filter language

```
process=chrome            exact match (case-insensitive; * and ? wildcards)
process:chrome            substring contains
process~=^chrome          regex (=~ or ~=; !~ negates)
state=established         TCP state; prefix matching (state=close matches CLOSE_WAIT)
pid>1000 tx>10MB          numeric comparisons with byte units (kb/mb/gb)
laddr=192.168.*           wildcard address filters; addr matches either side
port=443                  either local or remote port
loopback=false            boolean fields (loopback, connected)
change=new                change marker (new/changed/deleted/unchanged)
a and (b or not c)        boolean logic; && || ! also work
service="google chrome"   quoted strings allow spaces
chrome 127.0.0.1:443      bare text still searches every field
```

## Building

Requirements: Rust stable (MSVC target) and the Visual Studio C++ Build Tools with a Windows SDK.

```
cargo build --release                     # default features (geoip)
cargo build --release --features virustotal   # + VirusTotal lookups
cargo build --release --no-default-features   # minimal build without geoip
cargo test --all-features
cargo clippy --all-targets -- -D warnings
cargo fmt --all --check
```

## Optional integrations

- **GeoIP**: place a [GeoLite2-Country](https://dev.maxmind.com/geoip/docs/databases/city-and-country) `.mmdb` database next to the executable (or configure `[geoip] path`); the Country column appears automatically. The database is not bundled (MaxMind EULA requires attribution and a free account).
- **ETW (experimental)**: run from an elevated terminal with `--etw` (or set `[etw] enabled`) for event-driven connect/disconnect tracking. Any failure falls back to polling.
- **VirusTotal**: build with `--features virustotal`, put your free API key in `[virustotal] api_key` in config.toml, then press `V` on an endpoint.

## Running

- Plain `tcptui` monitors without any special rights.
- **Close Connection** and **End Process** usually require an elevated shell for other users' processes; the title bar shows `ADMIN` when elevated. Windows Terminal is recommended; conhost works.
- Closing IPv6 connections is not supported: Windows only exposes a setter for the IPv4 TCP table.

## Distribution

CI builds on every push and publishes zipped binaries with SHA-256 checksums for every `v*` tag. A Scoop manifest lives in `packaging/scoop/`; for winget, submit the manifest to `microsoft/winget-pkgs` referencing the release zip.

## Architecture notes

- `src/model.rs` — data types, snapshot diffing, statistics
- `src/filter.rs` — the structured filter language (tokenizer/parser/matcher)
- `src/net.rs`, `src/proc.rs`, `src/services.rs` — socket enumeration, process table, SCM services
- `src/dns.rs`, `src/geoip.rs` — background reverse DNS and optional GeoIP resolution
- `src/actions.rs`, `src/etw.rs`, `src/vt.rs` — Windows actions (close/kill/whois/signature), experimental ETW session, optional VirusTotal client
- `src/app.rs` — application state, collector thread, rules, profiles, chart series
- `src/events.rs` / `src/ui/` — terminal input and rendering (event → state → render)
- Threading is classic `std::thread` + `mpsc`; no async runtime

## License

[MIT](LICENSE)
