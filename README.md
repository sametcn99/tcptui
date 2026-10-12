# tcptui

A terminal UI clone of [Sysinternals TCPView](https://learn.microsoft.com/en-us/sysinternals/downloads/tcpview) for Windows, written in Rust with [Ratatui](https://ratatui.rs).

It shows every TCP and UDP endpoint on the system (IPv4 and IPv6) together with the owning process, service and PID, updates live, and lets you close connections, end processes, run whois lookups, search, filter, sort and export — all from the terminal.

```
 tcptui  sort:Process ↑ resolve:off                                          1000ms
┌ 423 endpoint(s) ──────────────────────────────────────────────────────────────┐
│M  Process          PID    Proto Local Address        L-Port State           │
│*  chrome.exe       39496  TCP   192.168.1.111         14720 ESTABLISHED      │
│   Code.exe         35668  TCP   127.0.0.1              6907 LISTEN           │
│   svchost.exe      1420   UDP   0.0.0.0                5353                  │
└──────────────────────────────────────────────────────────────────────────────┘
 ?:help  /:filter  Ctrl+F:search  s:sort  c:close  K:kill  w:whois  e:export
 total 423 · tcp 288 (est 91 lsn 62 tw 5) · udp 135 · shown 423
```

## The package

| Binary | Description |
|---|---|
| `tcptui` | Interactive terminal UI |
| `tcpvcon` | Command-line companion, mirroring the tool that ships with TCPView |

## Features

**Display**
- All TCP/UDP endpoints, IPv4 + IPv6, with owning process, PID and hosted service name
- TCPView-style change highlighting: new endpoints **green**, deleted **red**, state-changed **yellow**
- Reverse DNS resolution toggle with a TTL cache (resolved in the background)
- Adjustable refresh rate (250 ms – 60 s, default 1 s), manual refresh (`F5`)
- Statistics bar (total / established / listening / time-wait / close-wait / UDP) and a statistics popup
- Full mouse support: wheel scrolling, click-to-select, header-click sorting, double-click details
- Dark and light color themes

**Navigation and analysis**
- Incremental filter (`/`) with plain text or regular expressions (`re:` prefix)
- Search (`Ctrl+F`) with match jumping (`n` / `N`)
- Multi-column sorting (`s`, `S`, mouse header clicks; Shift+click adds a sort key)
- Grouped tree view by process (`G`), expand/collapse groups
- Watch mode to follow a single process (`F6`)
- Show/hide TCP, UDP, unconnected endpoints (`U`) and loopback (`L`)
- Column setup: visibility, order, widths (`C`), persisted across runs
- Timestamped event log of opened/closed connections and user actions (`g`)

**Actions**
- Close Connection (`c`) — terminates ESTABLISHED connections via `SetTcpEntry`, the same API TCPView uses; supports batch closing of marked rows
- End Process (`K`) — with confirmation; supports marked rows
- Whois (`w`) — follows RFC 3912 referrals and shows the result in a popup
- Copy to clipboard (`Ctrl+C` row, `Ctrl+Shift+C` table)
- Export to CSV / TSV / JSON / text (`e`), either visible rows or all endpoints
- Process detail popup (`Enter`): full executable path, command line, user account, CPU/RAM, hosted services and all endpoints of the process

**Advanced**
- Per-connection Tx/Rx byte counters via TCP extended statistics (`GetPerTcpConnectionEStats`, IPv4 only; silently hidden when unavailable)

**Command line (`tcptui`)**

```
tcptui [--interval <MS>] [--no-resolve] [--filter <TEXT>] [--tcp|--udp] [--theme dark|light]
```

**Command line (`tcpvcon`)** — identical flags to Sysinternals' tcpvcon:

```
tcpvcon [-a] [-c] [-n] [process name or PID]

  -a   Show all endpoints (default: established TCP connections only)
  -c   Print output as CSV
  -n   Don't resolve addresses
```

## Building

Requirements:

- Rust (stable, `x86_64-pc-windows-msvc`) — <https://rustup.rs>
- Visual Studio C++ Build Tools (for the MSVC linker) and a Windows SDK

```
cargo build --release
```

The resulting `target/release/tcptui.exe` and `target/release/tcpvcon.exe` are self-contained; copy them anywhere on `PATH`.

Run the test suite and lints with:

```
cargo test
cargo clippy --all-targets -- -D warnings
cargo fmt --check
```

## Running

- Plain `tcptui` monitors without any special rights.
- **Close Connection** and **End Process** usually require an elevated shell for processes owned by other users; the title bar shows an `ADMIN` indicator when tcptui itself is elevated.
- Windows Terminal is recommended (full UTF-8 and color support). The classic `conhost` console works but renders fewer niceties.
- Closing IPv6 connections is not supported: Windows only exposes a setter for the IPv4 TCP table.

## Configuration

Settings persist in `%APPDATA%\tcptui\config.toml` and are rewritten on exit:

```toml
[view]
refresh_interval_ms = 1000
resolve_addresses = false
show_tcp = true
show_udp = true
show_unconnected = true
show_loopback = true
theme = "dark"

[columns]
order = ["mark", "process", "pid", "protocol", "local_address", "local_port",
         "remote_address", "remote_port", "state", "service", "path", "tx", "rx"]
hidden = []
[columns.width]
process = 16

[estats]
enabled = true
```

## Architecture notes

- `src/model.rs` — data types, snapshot diffing (the green/red/yellow logic), statistics; fully unit-tested
- `src/net.rs` — socket enumeration (`netstat2`) and EStats counters
- `src/proc.rs`, `src/services.rs` — process metadata (`sysinfo`) and SCM service mapping
- `src/dns.rs` — background reverse-DNS worker with TTL cache
- `src/actions.rs` — `SetTcpEntry`, whois client, elevation/user-account helpers
- `src/app.rs` — application state, filtering/sorting/grouping, background collector thread
- `src/events.rs` / `src/ui/` — terminal input and rendering (Elm-style: event → state → render)
- Threading is classic `std::thread` + `mpsc` channels; no async runtime required

## License

TBD
