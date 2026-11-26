# tcptui

A native Rust terminal monitor for TCP and UDP endpoints on Windows, Linux, and macOS. Inspired by [Sysinternals TCPView](https://learn.microsoft.com/en-us/sysinternals/downloads/tcpview) and built with [Ratatui](https://ratatui.rs).

Use `tcptui` to inspect connections in a live table or `tcpvcon` to filter and export them from scripts. Both show IPv4 and IPv6 endpoints and the PID and process name when the operating system makes that information available.

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

## Platform support

| Feature | Windows x64 | Linux x64 and ARM64 | macOS 15+ Intel and Apple Silicon |
|---|---|---|---|
| TCP/UDP and process details | IP Helper and Win32 | inet_diag, `/proc`, and systemd service names where available | libproc for processes you can inspect |
| TCP traffic counters | IPv4 EStats in an elevated terminal | IPv4 and IPv6 `TCP_INFO` | IPv4 and IPv6 byte counts where `nettop` reports a matching socket |
| Close an established TCP connection | IPv4, elevated | IPv4 and IPv6, with `CAP_NET_ADMIN` in the current network namespace | — |
| TCP connection event log | Snapshot changes and optional ETW | Snapshot changes and optional eBPF | Snapshot changes |
| Executable signature check | Authenticode | — | Apple Code Signing Services |
| End a process | With permission to terminate the process | With permission to signal the process | With permission to signal the process |

Run the viewer normally for day-to-day monitoring. Linux shows endpoints in the current network namespace and can display sockets even when it cannot read their owners. On macOS, visible endpoints depend on which processes the current user can inspect. Missing byte counters stay blank.

## Feature overview

**Monitoring**
- IPv4 and IPv6 TCP/UDP endpoints with process details and platform-specific metadata
- TCPView-style change highlighting: new endpoints **green**, deleted **red**, state-changed **yellow**
- Age column based on first observation and, when available, a matched trace event
- Adjustable refresh rate (250 ms – 60 s, default 1 s), manual refresh (`F5`),
  pause/resume live updates (`p`) to freeze the table for inspection
- Statistics popup (`i`) with totals and top processes by count and by traffic
- Optional GeoIP country column with flags (see below)
- Optional TCP tracing (`--trace`) for short-lived connections on Windows and Linux
- Bandwidth chart (`B`): rolling Tx/Rx deltas across measured TCP sockets or for the selected endpoint (Tab)

**Filtering and search**
- Structured filter language: fields (`process path pid proto state laddr raddr addr lport rport port service tx rx change loopback connected`), operators (`= == != > >= < <= : =~ !~`), wildcards, byte units, `and`/`or`/`not` with parentheses
- Live match count and inline parse errors while typing; filter history (Up/Down); quick presets on keys `1`–`8`
- Incremental search (`Ctrl+F`) with highlighting and match jumping (`n`/`N`)
- Rules (`A`): alert expressions fired on new endpoints (⚠ indicator, event log) and Wireshark-style coloring rules

**Sorting and views**
- Multi-key sort order editor (`o`); `s` cycles, `S` reverses, header clicks sort (Shift+click appends)
- Grouped tree view by process (`G`); watch mode (`F6`); column setup (`C`); named view profiles (`P`); settings screen (`M`)
- View settings and profiles persist in the platform configuration file

**Actions**
- Close Connection (`c`) on Windows and Linux, and batch actions over marked rows (`Space`, Shift+arrows)
- End Process (`K`), whois (`w`, RFC 3912 referrals), VirusTotal lookup (`V`, optional feature)
- Copy to clipboard (`Ctrl+C` row — or TSV of all marked rows; `Ctrl+Shift+C` table; JSON via the right-click menu)
- Right-click context menu on rows; drag header edges to resize columns; Shift+wheel scrolls horizontally
- `tcptui --dump-frame <file> [--frame-size 120x30]` renders one live frame as text (screenshots, no terminal)
- View profiles can be exported/imported as `[[profile]]` TOML files (P popup)
- Process details include a sparkline for traffic measured across visible system sockets
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

## Configuration

| Platform | Path |
|---|---|
| Windows | `%APPDATA%\tcptui\config.toml` |
| Linux | `$XDG_CONFIG_HOME/tcptui/config.toml` when set to an absolute path, otherwise `~/.config/tcptui/config.toml` |
| macOS | `~/Library/Application Support/tcptui/config.toml` |

`[estats] enabled` controls TCP counters on all systems. Windows still accepts `--etw` and `[etw] enabled`. Use `--trace` to request ETW on Windows or eBPF on Linux. Tracing failures are shown in the event log while polling continues. Linux eBPF needs a kernel with BTF and permission to load tracing programs. It observes TCP state transitions in the current network namespace. A transient connection can have an unknown PID.

## Building

Use Rust stable on the target system.

- **Windows** requires the MSVC C++ Build Tools and a Windows SDK.
- **Linux** requires a C toolchain. For VirusTotal install the OpenSSL development headers and `pkg-config`. For `linux-trace` install Clang with a BPF backend and libbpf headers. On Debian/Ubuntu the optional packages are `clang libclang-dev libbpf-dev libssl-dev pkg-config`.
- **macOS** requires Xcode Command Line Tools. With a full Xcode installation, use `export BINDGEN_EXTRA_CLANG_ARGS="-isysroot $(xcrun --sdk macosx --show-sdk-path)"` if bindgen needs the SDK location.

```sh
cargo build --locked --release
cargo build --locked --release --all-features
cargo build --locked --release --no-default-features
cargo test --locked --all-features
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo fmt --all --check
```

`--all-features` enables GeoIP and VirusTotal, and includes eBPF tracing on Linux. The default build includes GeoIP. Place a [GeoLite2-Country](https://dev.maxmind.com/geoip/docs/databases/city-and-country) database next to the binary or set `[geoip] path`. To use VirusTotal, set `[virustotal] api_key` and press `V`.

## Installation and distribution

Find the assets and `sha256sums.txt` under [GitHub Releases](https://github.com/sametcn99/tcptui/releases). Each binary archive includes `tcptui` and `tcpvcon`. Choose the download for your OS and CPU architecture.

| Platform | Install |
|---|---|
| Windows x64 | Extract the ZIP or use `scoop install https://github.com/sametcn99/tcptui/releases/latest/download/scoop-tcptui.json`. Winget submission templates are in `packaging/winget/`. |
| Debian/Ubuntu | Download the `.deb` for `amd64` or `arm64` and run `sudo apt install ./tcptui_*.deb` from its directory. |
| Fedora | Download the `.rpm` for `x86_64` or `aarch64` and run `sudo dnf install ./tcptui-*.rpm`. |
| Arch Linux x64 | Download `tcptui-bin-aur.tar.gz`, extract it in a dedicated directory, and run `makepkg -si` there. The bundle contains the AUR recipe. |
| macOS 15+ | Extract the macOS archive or install the `tcptui.rb` formula from a trusted Homebrew tap. The release supplies the formula with both architecture checksums. |

For a Cargo installation from the repository, use `cargo install --locked --git https://github.com/sametcn99/tcptui.git`. Run `tcptui` to open the TUI or `tcpvcon -a -n` to list endpoints without DNS lookups.

A `v*` tag matching `Cargo.toml` publishes only after the native build and test matrix passes. Homebrew and AUR publication use the generated formula and recipe bundle. These channels are managed separately from GitHub Releases.

## Architecture

- `src/net/` enumerates sockets and reads per-connection counters. `src/proc.rs` enriches PIDs and `src/services.rs` adds service metadata.
- `src/trace/` runs Linux tracing, `src/etw.rs` runs Windows tracing, and both feed the application's event log.
- `src/model.rs` and `src/filter.rs` share the endpoint model, diffing, statistics, and filter expressions between the TUI and CLI.
- `src/app.rs`, the input handlers, and the Ratatui views share snapshots through `std::thread` and `mpsc`.

## License

[MIT](LICENSE)
