// ============================================================================
// tcptui GitHub Pages Interactive Documentation Engine
// ============================================================================

const INSTALL_COMMANDS = {
  scoop: 'scoop install https://github.com/sametcn99/tcptui/releases/download/v1.3.0/scoop-tcptui.json',
  cargo: 'cargo install --git https://github.com/sametcn99/tcptui.git --all-features',
  binary: 'Invoke-WebRequest https://github.com/sametcn99/tcptui/releases/download/v1.3.0/tcptui-v1.3.0-windows-x86_64.zip -OutFile tcptui.zip; Expand-Archive tcptui.zip',
  source: 'git clone https://github.com/sametcn99/tcptui.git && cd tcptui && cargo build --release --all-features'
};

// ============================================================================
// 1. TUI Simulator Screens (Authentic 120-col Ratatui Renders)
// ============================================================================
const TUI_SCREENS = {
  endpoints: {
    statusLeft: ' sort:Process ↑ resolve:on ',
    statusRight: '1000ms ADMIN',
    footerTop: ' ?:help  /:filter  1-8:presets  o:sort  B:chart  A:rules  c:close  K:kill  e:export  q:quit',
    footerBottom: ' total 423 · tcp 288 (est 91 lsn 62 tw 5 cw 2) · udp 135 · shown 14',
    html: `<span class="tui-dim">┌ 423 endpoint(s) ──────────────────────────────────────────────────────────────────────────────────────────────────────┐</span>
<span class="tui-dim">│</span><span class="tui-col-header">M  Process          PID    Proto Local Address          L-Port Remote Address         R-Port State         Tx       Rx      Age  Country</span><span class="tui-dim">│</span>
<span class="tui-dim">│</span><span class="tui-row-selected">*  chrome.exe       39496  TCP   192.168.1.111           54720 142.250.187.206           443 ESTABLISHED   1.4 MiB  8.9 MiB 12s  🇺🇸 US  </span><span class="tui-dim">│</span>
<span class="tui-dim">│</span><span class="tui-row-new">+  chrome.exe       39496  TCP   192.168.1.111           54788 104.18.32.47              443 ESTABLISHED   42.1 KiB 318 KiB  2s  🇺🇸 US  </span><span class="tui-dim">│</span>
<span class="tui-dim">│</span>   Code.exe         35668  TCP   127.0.0.1                6907 0.0.0.0                     0 LISTEN        0 B      0 B      3h  —      <span class="tui-dim">│</span>
<span class="tui-dim">│</span><span class="tui-row-marked">*  Code.exe         35668  TCP   192.168.1.111           51892 140.82.121.4              443 ESTABLISHED   890 KiB  2.1 MiB 44m  🇺🇸 US  </span><span class="tui-dim">│</span>
<span class="tui-dim">│</span>   cargo.exe        41204  TCP   192.168.1.111           55012 151.101.1.69              443 ESTABLISHED   128 KiB  14.2 MiB 8s  🇳🇱 NL  <span class="tui-dim">│</span>
<span class="tui-dim">│</span><span class="tui-row-changed">~  discord.exe      22816  TCP   192.168.1.111           50144 162.159.135.232           443 TIME_WAIT     3.1 MiB  9.4 MiB 28m  🇺🇸 US  </span><span class="tui-dim">│</span>
<span class="tui-dim">│</span>   lsass.exe          912  TCP   0.0.0.0                 49664 0.0.0.0                     0 LISTEN        0 B      0 B      2d  —      <span class="tui-dim">│</span>
<span class="tui-dim">│</span>   postgres.exe      8840  TCP   127.0.0.1                5432 127.0.0.1               53110 ESTABLISHED   6.4 MiB  1.9 MiB  4h  —      <span class="tui-dim">│</span>
<span class="tui-dim">│</span>   spotify.exe      18400  TCP   192.168.1.111           52901 35.186.224.25             443 ESTABLISHED   512 KiB  24.6 MiB 1h  🇩🇪 DE  <span class="tui-dim">│</span>
<span class="tui-dim">│</span>   svchost.exe       1420  UDP   0.0.0.0                  5353 *                           *               14.2 KiB 39.0 KiB 2d  —      <span class="tui-dim">│</span>
<span class="tui-dim">│</span>   svchost.exe       2188  TCP   192.168.1.111           54119 20.199.120.85             443 ESTABLISHED   92.0 KiB 410 KiB 19m  🇮🇪 IE  <span class="tui-dim">│</span>
<span class="tui-dim">│</span><span class="tui-row-deleted">-  curl.exe         44910  TCP   192.168.1.111           55104 93.184.216.34             443 CLOSE_WAIT    1.8 KiB  64.0 KiB 1s  🇺🇸 US  </span><span class="tui-dim">│</span>
<span class="tui-dim">│</span>   wezterm-gui.exe  11024  TCP   127.0.0.1               48120 127.0.0.1               48121 ESTABLISHED   420 KiB  420 KiB  5h  —      <span class="tui-dim">│</span>
<span class="tui-dim">│</span>   WireGuard.exe     6104  UDP   0.0.0.0                 51820 *                           *               88.4 MiB 312 MiB  2d  —      <span class="tui-dim">│</span>
<span class="tui-dim">└───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┘</span>`
  },
  chart: {
    statusLeft: ' sort:Process ↑ resolve:on ',
    statusRight: '1000ms ADMIN',
    footerTop: ' Tab:switch series (total / selected endpoint)   Esc/B/q:close',
    footerBottom: ' total 423 · tcp 288 (est 91 lsn 62 tw 5 cw 2) · udp 135 · shown 423',
    html: `<span class="tui-dim">┌ Bandwidth — Total System (60 samples · 1000ms interval · Tab switches to chrome.exe:54720) ───────────────────────────┐</span>
<span class="tui-dim">│</span> <span class="tui-accent">Tx (Sent)</span>      cur: <span class="tui-col-header">384.2 KiB/s</span>   peak: <span class="tui-col-header">1.42 MiB/s</span>   total: <span class="tui-col-header">104.8 MiB</span>                                           <span class="tui-dim">│</span>
<span class="tui-dim">│</span> 1.4M │                      ▄█▆▂                                        ▃▇█▄                                          <span class="tui-dim">│</span>
<span class="tui-dim">│</span> 1.0M │                     ▆████▄                                      ▅████▆▂                                        <span class="tui-dim">│</span>
<span class="tui-dim">│</span> 700K │       ▂▄▃          ███████▆▂          ▂▃▅▃                     ████████▅▃                 ▂▄▅▃                 <span class="tui-dim">│</span>
<span class="tui-dim">│</span> 350K │  ▁▂▃▄████▆▃▂▁▁▂▃▄▅██████████▅▄▃▂▁▁▂▃▄██████▅▄▃▂▁▁▁▂▃▄▅▆▄▃▂▁▁▂▄███████████▆▅▄▃▂▁▁▁▂▃▄▅▆████████▆▅▄▃▂▃▄▅▄▃     <span class="tui-dim">│</span>
<span class="tui-dim">│</span>   0B └──────────────────────────────────────────────────────────────────────────────────────────────────────────────  <span class="tui-dim">│</span>
<span class="tui-dim">│</span>                                                                                                                       <span class="tui-dim">│</span>
<span class="tui-dim">│</span> <span class="tui-row-new">Rx (Received)</span>  cur: <span class="tui-row-new">2.18 MiB/s</span>    peak: <span class="tui-row-new">6.84 MiB/s</span>   total: <span class="tui-row-new">482.3 MiB</span>                                           <span class="tui-dim">│</span>
<span class="tui-dim">│</span> 6.8M │                                                                  ▄███▆                                         <span class="tui-dim">│</span>
<span class="tui-dim">│</span> 5.1M │                     ▃██▇▃                                       ███████▃                                       <span class="tui-dim">│</span>
<span class="tui-dim">│</span> 3.4M │                    ▆█████▆▂          ▂▅▇▆▃                     █████████▆▃               ▃▆██▅▂                <span class="tui-dim">│</span>
<span class="tui-dim">│</span> 1.7M │  ▂▃▅▇████▆▄▃▂▁▂▃▄▆█████████▆▄▃▂▁▁▂▃▅███████▅▄▃▂▁▁▂▃▄▅▇▆▅▄▃▂▂▃▅████████████▇▅▄▃▂▁▁▂▃▅▆██████████▇▆▅▄▃▄▆▇▆▅    <span class="tui-dim">│</span>
<span class="tui-dim">│</span>   0B └──────────────────────────────────────────────────────────────────────────────────────────────────────────────  <span class="tui-dim">│</span>
<span class="tui-dim">└─ [Tab] Toggle Total / Endpoint (chrome.exe 192.168.1.111:54720 -> 142.250.187.206:443) ── [Esc/q] Close ──────────────┘</span>`
  },
  grouped: {
    statusLeft: ' GROUPED sort:Process ↑ resolve:on ',
    statusRight: '1000ms ADMIN',
    footerTop: ' Enter:expand/collapse  K:kill process  w:whois  V:virustotal  G:flat view  q:quit',
    footerBottom: ' total 423 · tcp 288 (est 91 lsn 62 tw 5 cw 2) · udp 135 · 24 process groups',
    html: `<span class="tui-dim">┌ Grouped by Process (24 groups · 423 endpoints) ───────────────────────────────────────────────────────────────────────┐</span>
<span class="tui-dim">│</span><span class="tui-col-header">M  Process / Endpoint                   PID    Proto Local Address          L-Port Remote Address         R-Port State </span><span class="tui-dim">│</span>
<span class="tui-dim">│</span><span class="tui-row-selected">▼  chrome.exe (14 endpoints · 8 est · Tx 4.2 MiB · Rx 38.4 MiB)                                                        </span><span class="tui-dim">│</span>
<span class="tui-dim">│</span>   ├─ chrome.exe                        39496  TCP   192.168.1.111           54720 142.250.187.206           443 ESTAB <span class="tui-dim">│</span>
<span class="tui-dim">│</span><span class="tui-row-new">   ├─ chrome.exe                        39496  TCP   192.168.1.111           54788 104.18.32.47              443 ESTAB </span><span class="tui-dim">│</span>
<span class="tui-dim">│</span>   ├─ chrome.exe                        39496  TCP   192.168.1.111           54790 172.217.169.110           443 ESTAB <span class="tui-dim">│</span>
<span class="tui-dim">│</span>   └─ chrome.exe                        39496  UDP   0.0.0.0                  5353 *                           *       <span class="tui-dim">│</span>
<span class="tui-dim">│</span><span class="tui-accent">▼  Code.exe (9 endpoints · 4 est · 3 lsn · Tx 1.1 MiB · Rx 3.7 MiB)</span>                                                   <span class="tui-dim">│</span>
<span class="tui-dim">│</span>   ├─ Code.exe                          35668  TCP   127.0.0.1                6907 0.0.0.0                     0 LISTEN<span class="tui-dim">│</span>
<span class="tui-dim">│</span>   └─ Code.exe                          35668  TCP   192.168.1.111           51892 140.82.121.4              443 ESTAB <span class="tui-dim">│</span>
<span class="tui-dim">│</span>▶  cargo.exe (4 endpoints · 4 est · Tx 128 KiB · Rx 14.2 MiB)                                                          <span class="tui-dim">│</span>
<span class="tui-dim">│</span>▶  discord.exe (6 endpoints · 3 est · 1 tw · Tx 3.1 MiB · Rx 9.4 MiB)                                                  <span class="tui-dim">│</span>
<span class="tui-dim">│</span>▶  postgres.exe (11 endpoints · 9 est · 2 lsn · Tx 6.4 MiB · Rx 1.9 MiB)                                               <span class="tui-dim">│</span>
<span class="tui-dim">│</span>▶  svchost.exe (38 endpoints · 12 est · 15 lsn · 11 udp — Services: Dnscache, W32Time, NlaSvc, LanmanWorkstation)      <span class="tui-dim">│</span>
<span class="tui-dim">│</span>▶  WireGuard.exe (2 endpoints · 2 udp · Tx 88.4 MiB · Rx 312.0 MiB)                                                    <span class="tui-dim">│</span>
<span class="tui-dim">└───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┘</span>`
  },
  palette: {
    statusLeft: ' sort:Process ↑ resolve:on ',
    statusRight: '1000ms ADMIN',
    footerTop: ' Up/Down:select command   Enter:execute   Esc:cancel',
    footerBottom: ' Command Palette (22 actions available · fuzzy subsequence match)',
    html: `<span class="tui-dim">┌ 423 endpoint(s) ──────────────────────────────────────────────────────────────────────────────────────────────────────┐</span>
<span class="tui-dim">│M  Process          PID    Proto Local Address          L-Port Remote Address         R-Port State         Age  Country│</span>
<span class="tui-dim">│*  chrome.exe       39496  TCP   192.168.1.111           54720 142.250.187.206           443 ESTABLISHED   12s  🇺🇸 US  │</span>
<span class="tui-dim">│         ┌ Command Palette (Ctrl+P) ────────────────────────────────────────────────────────────────────────┐          │</span>
<span class="tui-dim">│         │</span> <span class="tui-accent">&gt;</span> <span class="tui-col-header">r</span><span class="tui-dim">_</span>                                                                          <span class="tui-dim">(8 / 22 matched)</span> <span class="tui-dim">│          │</span>
<span class="tui-dim">│         ├──────────────────────────────────────────────────────────────────────────────────────────────────┤          │</span>
<span class="tui-dim">│         │</span> <span class="tui-row-selected">▸ rules: alerts and colors                                                                  [A] </span> <span class="tui-dim">│          │</span>
<span class="tui-dim">│         │</span>   bandwidth chart                                                                           [B]  <span class="tui-dim">│          │</span>
<span class="tui-dim">│         │</span>   view profiles                                                                             [P]  <span class="tui-dim">│          │</span>
<span class="tui-dim">│         │</span>   export table                                                                              [e]  <span class="tui-dim">│          │</span>
<span class="tui-dim">│         │</span>   sort order editor                                                                         [o]  <span class="tui-dim">│          │</span>
<span class="tui-dim">│         │</span>   refresh now                                                                              [F5]  <span class="tui-dim">│          │</span>
<span class="tui-dim">│         │</span>   toggle grouped view                                                                       [G]  <span class="tui-dim">│          │</span>
<span class="tui-dim">│         │</span>   toggle hostname resolution                                                                [r]  <span class="tui-dim">│          │</span>
<span class="tui-dim">│         │</span>   whois remote address                                                                      [w]  <span class="tui-dim">│          │</span>
<span class="tui-dim">│         └─ ↑/↓ navigate · Enter run · Esc close ───────────────────────────────────────────────────────────┘          │</span>
<span class="tui-dim">└───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┘</span>`
  },
  rules: {
    statusLeft: ' ⚠2 sort:Process ↑ resolve:on ',
    statusRight: '1000ms ADMIN',
    footerTop: ' ⚠ 2 alert(s) — ALERT \'rport=4444 or rport=1337\' matched TCP 192.168.1.111:55201 -> 198.51.100.42:4444 (x clears)',
    footerBottom: ' Tab:switch Alerts/Colors   a:add rule   Space:toggle   d:delete   Esc/q:close',
    html: `<span class="tui-dim">┌ Rules Engine — [Alerts (3)]  Colors (4) ──────────────────────────────────────────────────────────────────────────────┐</span>
<span class="tui-dim">│</span> <span class="tui-col-header">Alert Rules (Fire when a newly discovered endpoint matches the filter expression)</span>                                     <span class="tui-dim">│</span>
<span class="tui-dim">│</span>                                                                                                                       <span class="tui-dim">│</span>
<span class="tui-dim">│</span> <span class="tui-row-selected">▸ [x] rport=4444 or rport=1337 or rport=31337                              (fires ⚠ banner + event log + bell)</span>       <span class="tui-dim">│</span>
<span class="tui-dim">│</span>   [x] proto=tcp and state=listen and laddr=0.0.0.0                         (new wildcard listener opened)             <span class="tui-dim">│</span>
<span class="tui-dim">│</span>   [ ] process~=^(powershell|cmd|wscript|mshta) and connected=true          (shell outbound network activity)          <span class="tui-dim">│</span>
<span class="tui-dim">│</span>                                                                                                                       <span class="tui-dim">│</span>
<span class="tui-dim">├───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤</span>
<span class="tui-dim">│</span> <span class="tui-col-header">Wireshark-Style Coloring Rules (Evaluated in order · First matching rule styles the row)</span>                              <span class="tui-dim">│</span>
<span class="tui-dim">│</span>                                                                                                                       <span class="tui-dim">│</span>
<span class="tui-dim">│</span>   <span class="tui-row-new">[x] state=listen                                      fg:cyan      bg:none      bold:yes  underline:no</span>              <span class="tui-dim">│</span>
<span class="tui-dim">│</span>   <span class="tui-row-changed">[x] tx>10MB or rx>10MB                                fg:yellow    bg:none      bold:yes  underline:no</span>              <span class="tui-dim">│</span>
<span class="tui-dim">│</span>   <span class="tui-row-marked">[x] proto=udp and not loopback                        fg:magenta   bg:none      bold:no   underline:no</span>              <span class="tui-dim">│</span>
<span class="tui-dim">│</span>   <span class="tui-row-deleted">[x] state=close_wait or state=time_wait               fg:red       bg:none      bold:no   underline:no</span>              <span class="tui-dim">│</span>
<span class="tui-dim">│</span>                                                                                                                       <span class="tui-dim">│</span>
<span class="tui-dim">└─ [Tab] Switch Tab · [a] Add Rule · [Space] Enable/Disable · [J/K] Reorder · [d] Delete · [Esc] Close ─────────────────┘</span>`
  },
  stats: {
    statusLeft: ' ETW sort:Process ↑ resolve:on ',
    statusRight: '1000ms ADMIN',
    footerTop: ' Enter/i/Esc:close popup   w:whois remote   V:VirusTotal lookup',
    footerBottom: ' ETW Kernel-Network session active · true connect timestamps & transient event logging enabled',
    html: `<span class="tui-dim">┌ Process &amp; System Telemetry (Enter / i) ───────────────────────────────────────────────────────────────────────────────┐</span>
<span class="tui-dim">│</span> <span class="tui-col-header">Selected Endpoint &amp; Owning Process Details</span>                                                                            <span class="tui-dim">│</span>
<span class="tui-dim">│</span>   Process Name : <span class="tui-accent">chrome.exe</span> (PID 39496)                  User Account : <span class="tui-col-header">WORKSTATION\\samet</span>                             <span class="tui-dim">│</span>
<span class="tui-dim">│</span>   Executable   : C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe                                                <span class="tui-dim">│</span>
<span class="tui-dim">│</span>   Authenticode : <span class="tui-row-new">✔ Signed (Valid — WinVerifyTrust verified)</span>     Hosted Svc   : —                                      <span class="tui-dim">│</span>
<span class="tui-dim">│</span>   Endpoint     : TCP 192.168.1.111:54720 → 142.250.187.206:443 (ESTABLISHED · 🇺🇸 United States · Age 12s)            <span class="tui-dim">│</span>
<span class="tui-dim">│</span>   Traffic (2m) : <span class="tui-accent">▁▂▃▄▆█▇▅▃▂▄▆█▇▄▃▂▁▂▄▆▇█▆▄▃▂▃▅▆▄▃▂▁▂▃▅▇█▆▄▂</span>  (Tx: 1.4 MiB / Rx: 8.9 MiB)                             <span class="tui-dim">│</span>
<span class="tui-dim">├───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤</span>
<span class="tui-dim">│</span> <span class="tui-col-header">Top Processes by Endpoint Count</span>                      <span class="tui-col-header">Top Processes by Total Transferred Bytes (EStats)</span>                <span class="tui-dim">│</span>
<span class="tui-dim">│</span>   1. svchost.exe            38 endpoints               1. WireGuard.exe          400.4 MiB (Tx 88.4M / Rx 312.0M)     <span class="tui-dim">│</span>
<span class="tui-dim">│</span>   2. chrome.exe             14 endpoints               2. chrome.exe              42.6 MiB (Tx  4.2M / Rx  38.4M)     <span class="tui-dim">│</span>
<span class="tui-dim">│</span>   3. postgres.exe           11 endpoints               3. spotify.exe             25.1 MiB (Tx  512K / Rx  24.6M)     <span class="tui-dim">│</span>
<span class="tui-dim">│</span>   4. Code.exe                9 endpoints               4. cargo.exe               14.3 MiB (Tx  128K / Rx  14.2M)     <span class="tui-dim">│</span>
<span class="tui-dim">│</span>   5. discord.exe             6 endpoints               5. discord.exe             12.5 MiB (Tx  3.1M / Rx   9.4M)     <span class="tui-dim">│</span>
<span class="tui-dim">└─ [Esc / q / i] Close ─────────────────────────────────────────────────────────────────────────────────────────────────┘</span>`
  },
  help: {
    statusLeft: ' sort:Process ↑ resolve:on ',
    statusRight: '1000ms ADMIN',
    footerTop: ' j/k or Up/Down:scroll help   PgUp/PgDn:page   Esc/?/q:close',
    footerBottom: ' Two-column balanced keymap reference',
    html: `<span class="tui-dim">┌ Help — Keyboard &amp; Mouse Shortcuts ────────────────────────────────────────────────────────────────────────────────────┐</span>
<span class="tui-dim">│</span> <span class="tui-col-header">Navigation &amp; Selection</span>                                  <span class="tui-col-header">Filtering, Search &amp; Presets</span>                                   <span class="tui-dim">│</span>
<span class="tui-dim">│</span>   <span class="tui-accent">↑/↓, j/k</span>          Move selection up / down              <span class="tui-accent">/</span>                 Open structured filter prompt             <span class="tui-dim">│</span>
<span class="tui-dim">│</span>   <span class="tui-accent">PgUp / PgDn</span>       Move one page up / down               <span class="tui-accent">1 - 8</span>             Presets (tcp/udp/est/lsn/loop/!loop/new)  <span class="tui-dim">│</span>
<span class="tui-dim">│</span>   <span class="tui-accent">Home / End, g/G</span>   Jump to first / last row              <span class="tui-accent">Ctrl+F, n / N</span>     Incremental search · next / prev match    <span class="tui-dim">│</span>
<span class="tui-dim">│</span>   <span class="tui-accent">Space</span>             Toggle mark on current row            <span class="tui-accent">x</span>                 Clear marks, pending alerts &amp; filter      <span class="tui-dim">│</span>
<span class="tui-dim">│</span>   <span class="tui-accent">Shift + ↑/↓</span>       Range-mark multiple rows                                                                          <span class="tui-dim">│</span>
<span class="tui-dim">│</span>                                                                                                                       <span class="tui-dim">│</span>
<span class="tui-dim">│</span> <span class="tui-col-header">Views, Sorting &amp; Popups</span>                                 <span class="tui-col-header">Actions &amp; Mouse Support</span>                                       <span class="tui-dim">│</span>
<span class="tui-dim">│</span>   <span class="tui-accent">s / S / o</span>         Cycle sort · reverse · sort editor    <span class="tui-accent">c / K</span>             Close TCP connection · Kill process       <span class="tui-dim">│</span>
<span class="tui-dim">│</span>   <span class="tui-accent">G / F6 / p</span>        Grouped tree · Watch PID · Pause      <span class="tui-accent">w / V / e</span>         Whois lookup · VirusTotal · Export        <span class="tui-dim">│</span>
<span class="tui-dim">│</span>   <span class="tui-accent">B / A / P / M / C</span> Chart · Rules · Profiles · Settings   <span class="tui-accent">Ctrl+C / Shift+C</span>  Copy row (or marked TSV) / full table     <span class="tui-dim">│</span>
<span class="tui-dim">│</span>   <span class="tui-accent">Ctrl+P</span>            Fuzzy command palette (22 commands)   <span class="tui-accent">Right-Click</span>       Context menu on any endpoint row          <span class="tui-dim">│</span>
<span class="tui-dim">│</span>   <span class="tui-accent">i / g / F5</span>        Statistics · Event log · Refresh      <span class="tui-accent">Shift+Wheel/Drag</span>  Horizontal scroll · Resize column edges   <span class="tui-dim">│</span>
<span class="tui-dim">└─ j/k scroll · Esc/q close ────────────────────────────────────────────────────────────────────────────────────────────┘</span>`
  }
};

// ============================================================================
// 2. Sample Endpoint Dataset for the Live Filter Playground
// ============================================================================
const PLAYGROUND_ENDPOINTS = [
  { process: 'chrome.exe', path: 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe', pid: 39496, proto: 'TCP', laddr: '192.168.1.111', lport: 54720, raddr: '142.250.187.206', rport: 443, state: 'ESTABLISHED', service: '', tx: 1468006, rx: 9332326, change: 'unchanged', loopback: false, connected: true, country: '🇺🇸 US' },
  { process: 'chrome.exe', path: 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe', pid: 39496, proto: 'TCP', laddr: '192.168.1.111', lport: 54788, raddr: '104.18.32.47', rport: 443, state: 'ESTABLISHED', service: '', tx: 43110, rx: 325632, change: 'new', loopback: false, connected: true, country: '🇺🇸 US' },
  { process: 'Code.exe', path: 'C:\\Users\\samet\\AppData\\Local\\Programs\\Microsoft VS Code\\Code.exe', pid: 35668, proto: 'TCP', laddr: '127.0.0.1', lport: 6907, raddr: '0.0.0.0', rport: 0, state: 'LISTEN', service: '', tx: 0, rx: 0, change: 'unchanged', loopback: true, connected: false, country: '—' },
  { process: 'Code.exe', path: 'C:\\Users\\samet\\AppData\\Local\\Programs\\Microsoft VS Code\\Code.exe', pid: 35668, proto: 'TCP', laddr: '192.168.1.111', lport: 51892, raddr: '140.82.121.4', rport: 443, state: 'ESTABLISHED', service: '', tx: 911360, rx: 2202009, change: 'unchanged', loopback: false, connected: true, country: '🇺🇸 US' },
  { process: 'cargo.exe', path: 'C:\\Users\\samet\\.cargo\\bin\\cargo.exe', pid: 41204, proto: 'TCP', laddr: '192.168.1.111', lport: 55012, raddr: '151.101.1.69', rport: 443, state: 'ESTABLISHED', service: '', tx: 131072, rx: 14889779, change: 'new', loopback: false, connected: true, country: '🇳🇱 NL' },
  { process: 'discord.exe', path: 'C:\\Users\\samet\\AppData\\Local\\Discord\\app-1.0.9162\\Discord.exe', pid: 22816, proto: 'TCP', laddr: '192.168.1.111', lport: 50144, raddr: '162.159.135.232', rport: 443, state: 'TIME_WAIT', service: '', tx: 3250585, rx: 9856614, change: 'changed', loopback: false, connected: false, country: '🇺🇸 US' },
  { process: 'postgres.exe', path: 'C:\\Program Files\\PostgreSQL\\16\\bin\\postgres.exe', pid: 8840, proto: 'TCP', laddr: '127.0.0.1', lport: 5432, raddr: '127.0.0.1', rport: 53110, state: 'ESTABLISHED', service: 'postgresql-x64-16', tx: 6710886, rx: 1992294, change: 'unchanged', loopback: true, connected: true, country: '—' },
  { process: 'postgres.exe', path: 'C:\\Program Files\\PostgreSQL\\16\\bin\\postgres.exe', pid: 8840, proto: 'TCP', laddr: '127.0.0.1', lport: 5432, raddr: '0.0.0.0', rport: 0, state: 'LISTEN', service: 'postgresql-x64-16', tx: 0, rx: 0, change: 'unchanged', loopback: true, connected: false, country: '—' },
  { process: 'spotify.exe', path: 'C:\\Users\\samet\\AppData\\Roaming\\Spotify\\Spotify.exe', pid: 18400, proto: 'TCP', laddr: '192.168.1.111', lport: 52901, raddr: '35.186.224.25', rport: 443, state: 'ESTABLISHED', service: '', tx: 524288, rx: 25794969, change: 'unchanged', loopback: false, connected: true, country: '🇩🇪 DE' },
  { process: 'svchost.exe', path: 'C:\\Windows\\System32\\svchost.exe', pid: 1420, proto: 'UDP', laddr: '0.0.0.0', lport: 5353, raddr: '*', rport: 0, state: '', service: 'Dnscache', tx: 14540, rx: 39936, change: 'unchanged', loopback: false, connected: false, country: '—' },
  { process: 'svchost.exe', path: 'C:\\Windows\\System32\\svchost.exe', pid: 2188, proto: 'TCP', laddr: '192.168.1.111', lport: 54119, raddr: '20.199.120.85', rport: 443, state: 'ESTABLISHED', service: 'WinHttpAutoProxySvc', tx: 94208, rx: 419840, change: 'unchanged', loopback: false, connected: true, country: '🇮🇪 IE' },
  { process: 'lsass.exe', path: 'C:\\Windows\\System32\\lsass.exe', pid: 912, proto: 'TCP', laddr: '0.0.0.0', lport: 49664, raddr: '0.0.0.0', rport: 0, state: 'LISTEN', service: 'SamSs', tx: 0, rx: 0, change: 'unchanged', loopback: false, connected: false, country: '—' },
  { process: 'curl.exe', path: 'C:\\Windows\\System32\\curl.exe', pid: 44910, proto: 'TCP', laddr: '192.168.1.111', lport: 55104, raddr: '93.184.216.34', rport: 443, state: 'CLOSE_WAIT', service: '', tx: 1843, rx: 65536, change: 'deleted', loopback: false, connected: false, country: '🇺🇸 US' },
  { process: 'wezterm-gui.exe', path: 'C:\\Program Files\\WezTerm\\wezterm-gui.exe', pid: 11024, proto: 'TCP', laddr: '127.0.0.1', lport: 48120, raddr: '127.0.0.1', rport: 48121, state: 'ESTABLISHED', service: '', tx: 430080, rx: 430080, change: 'unchanged', loopback: true, connected: true, country: '—' },
  { process: 'WireGuard.exe', path: 'C:\\Program Files\\WireGuard\\wireguard.exe', pid: 6104, proto: 'UDP', laddr: '0.0.0.0', lport: 51820, raddr: '*', rport: 0, state: '', service: 'WireGuardTunnel$wg0', tx: 92694118, rx: 327155712, change: 'unchanged', loopback: false, connected: false, country: '—' },
  { process: 'node.exe', path: 'C:\\Program Files\\nodejs\\node.exe', pid: 29800, proto: 'TCP', laddr: '127.0.0.1', lport: 3000, raddr: '0.0.0.0', rport: 0, state: 'LISTEN', service: '', tx: 0, rx: 0, change: 'new', loopback: true, connected: false, country: '—' }
];

function formatBytes(bytes) {
  if (!bytes || bytes === 0) return '0 B';
  if (bytes >= 1024 * 1024) return (bytes / (1024 * 1024)).toFixed(1) + ' MiB';
  if (bytes >= 1024) return (bytes / 1024).toFixed(1) + ' KiB';
  return bytes + ' B';
}

function parseByteSize(valStr) {
  const m = String(valStr).trim().match(/^(\d+(?:\.\d+)?)\s*(b|kb|kib|mb|mib|gb|gib)?$/i);
  if (!m) return null;
  const n = parseFloat(m[1]);
  const unit = (m[2] || 'b').toLowerCase();
  const mult = {
    b: 1,
    kb: 1024, kib: 1024,
    mb: 1024 * 1024, mib: 1024 * 1024,
    gb: 1024 * 1024 * 1024, gib: 1024 * 1024 * 1024
  }[unit] || 1;
  return Math.round(n * mult);
}

function wildcardToRegExp(pattern) {
  const escaped = pattern.replace(/[.+^${}()|[\]\\]/g, '\\$&')
    .replace(/\*/g, '.*')
    .replace(/\?/g, '.');
  return new RegExp('^' + escaped + '$', 'i');
}

// Evaluate a single clause `field op val` or bare word against a row
function evalClause(clause, row) {
  const trimmed = clause.trim();
  if (!trimmed) return true;

  const opMatch = trimmed.match(/^([a-zA-Z_]+)\s*(==|=~|!~|!=|>=|<=|=|>|<|:)\s*(.+)$/);
  if (!opMatch) {
    // Bare substring search across all fields
    const hay = `${row.process} ${row.path} ${row.pid} ${row.proto} ${row.laddr}:${row.lport} ${row.raddr}:${row.rport} ${row.state} ${row.service}`.toLowerCase();
    return hay.includes(trimmed.replace(/^["']|["']$/g, '').toLowerCase());
  }

  const rawField = opMatch[1].toLowerCase();
  const op = opMatch[2];
  let rawVal = opMatch[3].trim().replace(/^["']|["']$/g, '');

  const fieldMap = {
    process: 'process', proc: 'process', name: 'process',
    path: 'path', exe: 'path',
    pid: 'pid',
    proto: 'proto', protocol: 'proto',
    state: 'state',
    laddr: 'laddr', local_addr: 'laddr',
    raddr: 'raddr', remote_addr: 'raddr',
    addr: 'addr', address: 'addr',
    lport: 'lport', local_port: 'lport',
    rport: 'rport', remote_port: 'rport',
    port: 'port',
    service: 'service', svc: 'service',
    tx: 'tx', sent: 'tx',
    rx: 'rx', received: 'rx',
    change: 'change',
    loopback: 'loopback',
    connected: 'connected'
  };

  const field = fieldMap[rawField];
  if (!field) {
    throw new Error(`unknown field '${rawField}'`);
  }

  // Handle addr / port composite fields
  if (field === 'addr') {
    return evalSingleValue(row.laddr, op, rawVal, false) || evalSingleValue(row.raddr, op, rawVal, false);
  }
  if (field === 'port') {
    return evalSingleValue(row.lport, op, rawVal, true) || evalSingleValue(row.rport, op, rawVal, true);
  }

  const isNumeric = ['pid', 'lport', 'rport', 'tx', 'rx'].includes(field);
  const isBool = ['loopback', 'connected'].includes(field);
  const rowVal = row[field];

  if (isBool) {
    const bVal = ['true', '1', 'yes', 'on'].includes(rawVal.toLowerCase());
    if (op === '=' || op === '==') return rowVal === bVal;
    if (op === '!=') return rowVal !== bVal;
    throw new Error(`boolean field '${field}' only supports = or !=`);
  }

  if (field === 'state' && (op === '=' || op === '==')) {
    return row.state.toLowerCase().startsWith(rawVal.toLowerCase());
  }

  return evalSingleValue(rowVal, op, rawVal, isNumeric);
}

function evalSingleValue(rowVal, op, rawVal, isNumeric) {
  if (op === '=~') {
    const re = new RegExp(rawVal, 'i');
    return re.test(String(rowVal));
  }
  if (op === '!~') {
    const re = new RegExp(rawVal, 'i');
    return !re.test(String(rowVal));
  }
  if (op === ':') {
    return String(rowVal).toLowerCase().includes(rawVal.toLowerCase());
  }

  if (isNumeric) {
    const target = parseByteSize(rawVal);
    if (target === null) throw new Error(`expected numeric/byte value, got '${rawVal}'`);
    const actual = Number(rowVal) || 0;
    if (op === '=' || op === '==') return actual === target;
    if (op === '!=') return actual !== target;
    if (op === '>') return actual > target;
    if (op === '>=') return actual >= target;
    if (op === '<') return actual < target;
    if (op === '<=') return actual <= target;
  }

  const sActual = String(rowVal).toLowerCase();
  const sTarget = rawVal.toLowerCase();
  if (op === '=' || op === '==') {
    if (sTarget.includes('*') || sTarget.includes('?')) {
      return wildcardToRegExp(sTarget).test(sActual);
    }
    return sActual === sTarget;
  }
  if (op === '!=') {
    if (sTarget.includes('*') || sTarget.includes('?')) {
      return !wildcardToRegExp(sTarget).test(sActual);
    }
    return sActual !== sTarget;
  }
  return sActual.includes(sTarget);
}

// Tokenizer & recursive-descent boolean parser for filter expressions
function tokenizeFilter(input) {
  const tokens = [];
  let i = 0;
  while (i < input.length) {
    if (/\s/.test(input[i])) { i++; continue; }
    if (input[i] === '(' || input[i] === ')') {
      tokens.push({ type: 'PAREN', val: input[i] });
      i++;
      continue;
    }
    if (input.slice(i, i + 2) === '&&') { tokens.push({ type: 'AND' }); i += 2; continue; }
    if (input.slice(i, i + 2) === '||') { tokens.push({ type: 'OR' }); i += 2; continue; }
    if (input[i] === '!' && input[i + 1] !== '=' && input[i + 1] !== '~') {
      tokens.push({ type: 'NOT' }); i++; continue;
    }

    // Read a term (can include quoted strings)
    let term = '';
    while (i < input.length && !/\s/.test(input[i]) && input[i] !== '(' && input[i] !== ')') {
      if (input[i] === '"' || input[i] === "'") {
        const q = input[i++];
        term += q;
        while (i < input.length && input[i] !== q) term += input[i++];
        if (i < input.length) term += input[i++];
      } else {
        term += input[i++];
      }
    }
    const lower = term.toLowerCase();
    if (lower === 'and') tokens.push({ type: 'AND' });
    else if (lower === 'or') tokens.push({ type: 'OR' });
    else if (lower === 'not') tokens.push({ type: 'NOT' });
    else tokens.push({ type: 'TERM', val: term });
  }
  return tokens;
}

function evaluateFilterExpression(query, row) {
  const q = query.trim();
  if (!q) return true;
  if (q.startsWith('re:')) {
    const re = new RegExp(q.slice(3), 'i');
    const hay = `${row.process} ${row.path} ${row.pid} ${row.proto} ${row.laddr}:${row.lport} ${row.raddr}:${row.rport} ${row.state} ${row.service}`;
    return re.test(hay);
  }

  const tokens = tokenizeFilter(q);
  let pos = 0;

  function parseOr() {
    let left = parseAnd();
    while (pos < tokens.length && tokens[pos].type === 'OR') {
      pos++;
      const right = parseAnd();
      left = left || right;
    }
    return left;
  }

  function parseAnd() {
    let left = parseNot();
    while (pos < tokens.length && (tokens[pos].type === 'AND' || (tokens[pos].type !== 'OR' && tokens[pos].val !== ')'))) {
      if (tokens[pos].type === 'AND') pos++;
      if (pos >= tokens.length || tokens[pos].val === ')') break;
      const right = parseNot();
      left = left && right;
    }
    return left;
  }

  function parseNot() {
    if (pos < tokens.length && tokens[pos].type === 'NOT') {
      pos++;
      return !parseNot();
    }
    return parsePrimary();
  }

  function parsePrimary() {
    if (pos >= tokens.length) throw new Error('unexpected end of expression');
    const tok = tokens[pos];
    if (tok.type === 'PAREN' && tok.val === '(') {
      pos++;
      const val = parseOr();
      if (pos >= tokens.length || tokens[pos].val !== ')') {
        throw new Error('unclosed parenthesis "("');
      }
      pos++;
      return val;
    }
    if (tok.type === 'TERM') {
      pos++;
      return evalClause(tok.val, row);
    }
    throw new Error(`unexpected token`);
  }

  const result = parseOr();
  if (pos < tokens.length) throw new Error('unexpected trailing token');
  return result;
}

// ============================================================================
// 3. tcpvcon Companion CLI Output Samples
// ============================================================================
const TCPVCON_SAMPLES = {
  table: `$ tcpvcon -a -n
Process            PID    Proto Local Address                  L-Port Remote Address                 R-Port State
------------------ ------ ----- ------------------------------ ------ ------------------------------ ------ -------------
Code.exe           35668  TCP   127.0.0.1                      6907   0.0.0.0                        0      LISTEN
Code.exe           35668  TCP   192.168.1.111                  51892  140.82.121.4                   443    ESTABLISHED
WireGuard.exe      6104   UDP   0.0.0.0                        51820                                        
cargo.exe          41204  TCP   192.168.1.111                  55012  151.101.1.69                   443    ESTABLISHED
chrome.exe         39496  TCP   192.168.1.111                  54720  142.250.187.206                443    ESTABLISHED
postgres.exe       8840   TCP   127.0.0.1                      5432   127.0.0.1                      53110  ESTABLISHED`,

  csv: `$ tcpvcon -a -c -n chrome
Process,PID,Protocol,Local Address,Local Port,Remote Address,Remote Port,State
chrome.exe,39496,TCP,192.168.1.111,54720,142.250.187.206,443,ESTABLISHED
chrome.exe,39496,TCP,192.168.1.111,54788,104.18.32.47,443,ESTABLISHED`,

  json: `$ tcpvcon -a -j -n --filter "state=established and not loopback"
[
  {
    "Local Address": "192.168.1.111",
    "Local Port": "54720",
    "PID": "39496",
    "Process": "chrome.exe",
    "Protocol": "TCP",
    "Remote Address": "142.250.187.206",
    "Remote Port": "443",
    "State": "ESTABLISHED"
  },
  {
    "Local Address": "192.168.1.111",
    "Local Port": "51892",
    "PID": "35668",
    "Process": "Code.exe",
    "Protocol": "TCP",
    "Remote Address": "140.82.121.4",
    "Remote Port": "443",
    "State": "ESTABLISHED"
  }
]`
};

// ============================================================================
// 4. Bilingual Dictionary (EN / TR)
// ============================================================================
const I18N = {
  en: {
    nav_showcase: 'TUI Showcase',
    nav_features: 'Features',
    nav_filter: 'Filter Playground',
    nav_cli: 'CLI & tcpvcon',
    nav_keymap: 'Keymap',
    nav_config: 'Config Builder',
    nav_arch: 'Architecture',
    hero_badge_1: 'v1.3.0 Latest Release',
    hero_badge_2: 'Rust 2024 · Ratatui 0.30',
    hero_badge_3: 'Windows x86_64 Native',
    hero_title_1: 'Sysinternals TCPView,',
    hero_title_2: 'Reimagined for the Terminal.',
    hero_subtitle: 'Inspect every IPv4 & IPv6 TCP/UDP socket on Windows in real time. Built in Rust with Ratatui — featuring a structured filter language, live EStats bandwidth charts, ETW kernel tracking, Wireshark-style coloring rules, GeoIP flags, Authenticode verification, and instant connection termination.',
    cta_download: 'Download v1.3.0 (Windows x64)',
    cta_playground: 'Try Filter Playground',
    cta_source: 'View Source on GitHub',
    features_eyebrow: 'CAPABILITIES & DEEP DIVE',
    features_title: 'Everything TCPView does — plus power-user workflows.',
    features_desc: 'Designed for systems engineers, security analysts, and developers who live in the terminal.',
    filter_eyebrow: 'INTERACTIVE STRUCTURED QUERY ENGINE',
    filter_title: 'Live Filter Language Playground',
    filter_desc: 'Type any tcptui filter expression below or click a preset chip to test the query parser live against a simulated Windows socket table.',
    cli_eyebrow: 'DUAL BINARIES INCLUDED',
    cli_title: 'tcptui Interactive TUI & tcpvcon CLI Companion',
    cli_desc: 'Ships with both the interactive terminal UI (tcptui.exe) and a script-friendly command-line companion (tcpvcon.exe) supporting CSV, JSON, and structured filters.',
    keymap_eyebrow: 'KEYBOARD-FIRST & MOUSE-AWARE',
    keymap_title: 'Complete Keymap & Mouse Controls',
    keymap_desc: 'Every action is reachable in one keystroke or via the fuzzy Command Palette (Ctrl+P). Full mouse support included.',
    config_eyebrow: 'PERSISTENT CONFIGURATION',
    config_title: 'Interactive config.toml Generator',
    config_desc: 'Customize your default view, refresh interval, theme, GeoIP database, ETW kernel tracking, and rules — persisted automatically at %APPDATA%\\tcptui\\config.toml.',
    arch_eyebrow: 'INTERNALS & ENGINEERING',
    arch_title: 'Zero-Async Architecture & Release Timeline',
    arch_desc: 'Clean separation between socket enumeration, snapshot diffing, DNS/GeoIP background workers, and deterministic Ratatui rendering.'
  },
  tr: {
    nav_showcase: 'Canlı TUI',
    nav_features: 'Özellikler',
    nav_filter: 'Filtre Laboratuvarı',
    nav_cli: 'CLI & tcpvcon',
    nav_keymap: 'Kısayollar',
    nav_config: 'Yapılandırma',
    nav_arch: 'Mimari',
    hero_badge_1: 'v1.3.0 Son Sürüm',
    hero_badge_2: 'Rust 2024 · Ratatui 0.30',
    hero_badge_3: 'Windows x86_64 Yerel',
    hero_title_1: 'Sysinternals TCPView,',
    hero_title_2: 'Modern Terminal İçin Yeniden Tasarlandı.',
    hero_subtitle: 'Windows üzerindeki tüm IPv4 ve IPv6 TCP/UDP uç noktalarını gerçek zamanlı izleyin. Rust ve Ratatui ile geliştirildi — yapılandırılmış filtre dili, canlı EStats bant genişliği grafikleri, ETW çekirdek takibi, Wireshark tarzı renklendirme kuralları, GeoIP bayrakları, Authenticode imza doğrulaması ve anında bağlantı sonlandırma.',
    cta_download: 'v1.3.0 İndir (Windows x64)',
    cta_playground: 'Filtre Dili Laboratuvarı',
    cta_source: 'GitHub Üzerinde İncele',
    features_eyebrow: 'ÖZELLİKLER & TEKNİK DETAYLAR',
    features_title: 'TCPView’un yaptığı her şey — ve çok daha fazlası.',
    features_desc: 'Terminalde çalışan sistem mühendisleri, güvenlik analistleri ve geliştiriciler için tasarlandı.',
    filter_eyebrow: 'ETKİLEŞİMLİ SORGULAMA MOTORU',
    filter_title: 'Canlı Filtre Dili Laboratuvarı',
    filter_desc: 'Aşağıya herhangi bir tcptui filtre ifadesi yazın veya hazır butonlara tıklayarak sorgu ayrıştırıcısını canlı Windows soket tablosu üzerinde test edin.',
    cli_eyebrow: 'İKİ AYRI ÇALIŞTIRILABİLİR İKİLİ (BINARY)',
    cli_title: 'tcptui Etkileşimli TUI & tcpvcon CLI Aracı',
    cli_desc: 'Hem etkileşimli terminal arayüzü (tcptui.exe) hem de otomasyon ve betikler için CSV, JSON ve gelişmiş filtre destekli komut satırı aracı (tcpvcon.exe) birlikte gelir.',
    keymap_eyebrow: 'KLAVYE ODAKLI & FARE DESTEKLİ',
    keymap_title: 'Tüm Klavye Kısayolları ve Fare Kontrolleri',
    keymap_desc: 'Her işlev tek tuşla veya bulanık aramalı Komut Paleti (Ctrl+P) ile erişilebilir. Sütun boyutlandırma ve sağ tık menüsü dahil tam fare desteği.',
    config_eyebrow: 'KALICI YAPILANDIRMA',
    config_title: 'Etkileşimli config.toml Oluşturucu',
    config_desc: 'Varsayılan görünüm, yenileme hızı, tema, GeoIP veritabanı, ETW çekirdek izleme ve uyarı kurallarını özelleştirin — %APPDATA%\\tcptui\\config.toml dosyasında saklanır.',
    arch_eyebrow: 'İÇ MİMARİ & SÜRÜM GEÇMİŞİ',
    arch_title: 'Sıfır-Async Mimari & Sürüm Zaman Çizelgesi',
    arch_desc: 'Soket tarama, anlık görüntü farkı (diff), arka plan DNS/GeoIP iş parçacıkları ve deterministik Ratatui çizimi arasında temiz modüler ayrım.'
  }
};

// ============================================================================
// 5. DOM Initialization & Event Binding
// ============================================================================
document.addEventListener('DOMContentLoaded', () => {
  // --- A. Install Tabs & Copy ---
  let currentInstallKey = 'scoop';
  const installCmdCode = document.getElementById('install-cmd-text');
  const installTabs = document.querySelectorAll('.install-tab');
  const installCopyBtn = document.getElementById('install-copy-btn');

  installTabs.forEach(tab => {
    tab.addEventListener('click', () => {
      installTabs.forEach(t => t.classList.remove('active'));
      tab.classList.add('active');
      currentInstallKey = tab.dataset.install;
      installCmdCode.textContent = INSTALL_COMMANDS[currentInstallKey];
    });
  });

  if (installCopyBtn) {
    installCopyBtn.addEventListener('click', () => {
      navigator.clipboard.writeText(INSTALL_COMMANDS[currentInstallKey]);
      const prev = installCopyBtn.textContent;
      installCopyBtn.textContent = 'Copied ✓';
      setTimeout(() => { installCopyBtn.textContent = prev; }, 1600);
    });
  }

  // --- B. Interactive TUI Showcase ---
  const tuiWindow = document.getElementById('tui-window');
  const tuiPre = document.getElementById('tui-pre');
  const tuiStatusLeft = document.getElementById('tui-status-left');
  const tuiStatusRight = document.getElementById('tui-status-right');
  const tuiFooterTop = document.getElementById('tui-footer-top');
  const tuiFooterBottom = document.getElementById('tui-footer-bottom');
  const tuiViewBtns = document.querySelectorAll('.tui-view-btn');
  const tuiThemeSelect = document.getElementById('tui-theme-select');

  function renderTuiScreen(viewKey) {
    const screen = TUI_SCREENS[viewKey] || TUI_SCREENS.endpoints;
    tuiPre.innerHTML = screen.html;
    tuiStatusLeft.textContent = screen.statusLeft;
    tuiStatusRight.textContent = screen.statusRight;
    tuiFooterTop.textContent = screen.footerTop;
    tuiFooterBottom.textContent = screen.footerBottom;
    tuiViewBtns.forEach(btn => {
      btn.classList.toggle('active', btn.dataset.view === viewKey);
    });
  }

  tuiViewBtns.forEach(btn => {
    btn.addEventListener('click', () => renderTuiScreen(btn.dataset.view));
  });

  if (tuiThemeSelect) {
    tuiThemeSelect.addEventListener('change', (e) => {
      tuiWindow.setAttribute('data-tui-theme', e.target.value);
    });
  }

  renderTuiScreen('endpoints');

  // --- C. Live Filter Playground ---
  const filterInput = document.getElementById('playground-filter-input');
  const filterBadge = document.getElementById('playground-status-badge');
  const filterTableBody = document.getElementById('playground-tbody');
  const presetChips = document.querySelectorAll('.preset-chip');

  function updateFilterPlayground() {
    const query = filterInput.value;
    let matched = [];
    try {
      matched = PLAYGROUND_ENDPOINTS.filter(row => evaluateFilterExpression(query, row));
      filterBadge.className = 'filter-status-badge valid';
      filterBadge.textContent = `${matched.length} / ${PLAYGROUND_ENDPOINTS.length} matched`;
    } catch (err) {
      filterBadge.className = 'filter-status-badge error';
      filterBadge.textContent = `Syntax: ${err.message}`;
      return;
    }

    filterTableBody.innerHTML = matched.map(r => {
      const stateClass = r.state === 'ESTABLISHED' ? 'badge-est'
        : r.state === 'LISTEN' ? 'badge-lsn'
        : r.state ? 'badge-wait' : '';
      const rowChangeStyle = r.change === 'new' ? 'style="color: var(--accent-green);"'
        : r.change === 'changed' ? 'style="color: var(--accent-yellow);"'
        : r.change === 'deleted' ? 'style="color: var(--accent-red);"' : '';

      return `<tr ${rowChangeStyle}>
        <td><strong>${r.process}</strong></td>
        <td>${r.pid}</td>
        <td>${r.proto}</td>
        <td>${r.laddr}:${r.lport}</td>
        <td>${r.raddr}${r.rport ? ':' + r.rport : ''}</td>
        <td>${r.state ? `<span class="badge-state ${stateClass}">${r.state}</span>` : '—'}</td>
        <td>${r.service || '—'}</td>
        <td>${formatBytes(r.tx)}</td>
        <td>${formatBytes(r.rx)}</td>
        <td>${r.change}</td>
        <td>${r.country}</td>
      </tr>`;
    }).join('');
  }

  if (filterInput) {
    filterInput.addEventListener('input', updateFilterPlayground);
    presetChips.forEach(chip => {
      chip.addEventListener('click', () => {
        filterInput.value = chip.dataset.expr;
        updateFilterPlayground();
      });
    });
    updateFilterPlayground();
  }

  // --- D. tcpvcon Output Format Tabs ---
  const tcpvconTabs = document.querySelectorAll('[data-tcpvcon-tab]');
  const tcpvconPre = document.getElementById('tcpvcon-output-pre');
  tcpvconTabs.forEach(tab => {
    tab.addEventListener('click', () => {
      tcpvconTabs.forEach(t => t.classList.remove('active'));
      tab.classList.add('active');
      tcpvconPre.textContent = TCPVCON_SAMPLES[tab.dataset.tcpvconTab] || TCPVCON_SAMPLES.table;
    });
  });

  // --- E. Keymap Live Search ---
  const keymapSearch = document.getElementById('keymap-search-input');
  const keymapRows = document.querySelectorAll('#keymap-tbody tr');
  if (keymapSearch) {
    keymapSearch.addEventListener('input', () => {
      const needle = keymapSearch.value.trim().toLowerCase();
      keymapRows.forEach(tr => {
        const text = tr.textContent.toLowerCase();
        tr.style.display = text.includes(needle) ? '' : 'none';
      });
    });
  }

  // --- F. Interactive config.toml Builder ---
  const cfgInputs = document.querySelectorAll('.cfg-control');
  const cfgOutput = document.getElementById('config-toml-output');
  const cfgCopyBtn = document.getElementById('config-copy-btn');

  function updateConfigToml() {
    if (!cfgOutput) return;
    const interval = document.getElementById('cfg-interval').value || 1000;
    const theme = document.getElementById('cfg-theme').value || 'dark';
    const resolve = document.getElementById('cfg-resolve').checked;
    const loopback = document.getElementById('cfg-loopback').checked;
    const estats = document.getElementById('cfg-estats').checked;
    const etw = document.getElementById('cfg-etw').checked;
    const geoip = document.getElementById('cfg-geoip').checked;
    const bell = document.getElementById('cfg-bell').checked;

    const toml = `# %APPDATA%\\tcptui\\config.toml — Generated via tcptui Docs

[view]
refresh_interval_ms = ${interval}
resolve_addresses = ${resolve}
show_tcp = true
show_udp = true
show_unconnected = true
show_loopback = ${loopback}
theme = "${theme}"

[[view.sort]]
col = "process"
desc = false

[[view.sort]]
col = "protocol"
desc = false

[columns]
hidden = ["service", "path"]

[estats]
enabled = ${estats}

[geoip]
enabled = ${geoip}
path = "GeoLite2-Country.mmdb"

[etw]
enabled = ${etw}

[notifications]
bell = ${bell}

[[alerts]]
expression = "rport=4444 or rport=1337"
enabled = true

[[colors]]
expression = "state=listen"
enabled = true
fg = "cyan"
bold = true

[[colors]]
expression = "tx>10MB or rx>10MB"
enabled = true
fg = "yellow"
bold = true

[[profiles]]
name = "External Active HTTPS"
filter = "proto=tcp and port=443 and state=established and not loopback"
show_tcp = true
show_udp = false
show_unconnected = false
show_loopback = false
grouped = false`;

    cfgOutput.textContent = toml;
  }

  cfgInputs.forEach(el => el.addEventListener('input', updateConfigToml));
  cfgInputs.forEach(el => el.addEventListener('change', updateConfigToml));
  updateConfigToml();

  if (cfgCopyBtn) {
    cfgCopyBtn.addEventListener('click', () => {
      navigator.clipboard.writeText(cfgOutput.textContent);
      const prev = cfgCopyBtn.textContent;
      cfgCopyBtn.textContent = 'Copied TOML ✓';
      setTimeout(() => { cfgCopyBtn.textContent = prev; }, 1600);
    });
  }

  // --- G. Site Theme (Dark / Light) & Language Toggle (EN / TR) ---
  const siteThemeBtn = document.getElementById('site-theme-toggle');
  if (siteThemeBtn) {
    siteThemeBtn.addEventListener('click', () => {
      const html = document.documentElement;
      const next = html.getAttribute('data-site-theme') === 'light' ? 'dark' : 'light';
      html.setAttribute('data-site-theme', next);
      siteThemeBtn.textContent = next === 'light' ? '🌙 Dark' : '☀️ Light';
    });
  }

  let currentLang = 'en';
  const langToggleBtn = document.getElementById('lang-toggle-btn');
  if (langToggleBtn) {
    langToggleBtn.addEventListener('click', () => {
      currentLang = currentLang === 'en' ? 'tr' : 'en';
      langToggleBtn.textContent = currentLang === 'en' ? '🌐 TR' : '🌐 EN';
      const dict = I18N[currentLang];
      document.querySelectorAll('[data-i18n]').forEach(el => {
        const key = el.getAttribute('data-i18n');
        if (dict[key]) el.textContent = dict[key];
      });
    });
  }
});
