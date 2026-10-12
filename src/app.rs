//! Application state: modes, filtering, sorting, grouping, background
//! collector thread and every state transition the UI reflects.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::mpsc::{Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use chrono::{DateTime, Local};
use ratatui::style::Color;

use crate::config::Config;
use crate::dns::{self, DnsCache, SharedDnsCache};
use crate::model::{
    ConnectionRow, ProcessInfo, Protocol, RowChange, RowId, Snapshot, Stats, format_bytes,
    merge_snapshots,
};
use crate::net::EStatsReader;
use crate::proc::ProcTable;

// ---------------------------------------------------------------------------
// Columns
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum ColumnId {
    Mark,
    Process,
    Pid,
    Protocol,
    LocalAddress,
    LocalPort,
    RemoteAddress,
    RemotePort,
    State,
    Service,
    Path,
    Tx,
    Rx,
}

pub const DEFAULT_COLUMN_ORDER: &[ColumnId] = &[
    ColumnId::Mark,
    ColumnId::Process,
    ColumnId::Pid,
    ColumnId::Protocol,
    ColumnId::LocalAddress,
    ColumnId::LocalPort,
    ColumnId::RemoteAddress,
    ColumnId::RemotePort,
    ColumnId::State,
    ColumnId::Service,
    ColumnId::Path,
    ColumnId::Tx,
    ColumnId::Rx,
];

impl ColumnId {
    pub fn key(self) -> &'static str {
        match self {
            ColumnId::Mark => "mark",
            ColumnId::Process => "process",
            ColumnId::Pid => "pid",
            ColumnId::Protocol => "protocol",
            ColumnId::LocalAddress => "local_address",
            ColumnId::LocalPort => "local_port",
            ColumnId::RemoteAddress => "remote_address",
            ColumnId::RemotePort => "remote_port",
            ColumnId::State => "state",
            ColumnId::Service => "service",
            ColumnId::Path => "path",
            ColumnId::Tx => "tx",
            ColumnId::Rx => "rx",
        }
    }

    pub fn from_key(key: &str) -> Option<ColumnId> {
        DEFAULT_COLUMN_ORDER
            .iter()
            .copied()
            .find(|c| c.key() == key)
    }

    pub fn header(self) -> &'static str {
        match self {
            ColumnId::Mark => "M",
            ColumnId::Process => "Process",
            ColumnId::Pid => "PID",
            ColumnId::Protocol => "Proto",
            ColumnId::LocalAddress => "Local Address",
            ColumnId::LocalPort => "L-Port",
            ColumnId::RemoteAddress => "Remote Address",
            ColumnId::RemotePort => "R-Port",
            ColumnId::State => "State",
            ColumnId::Service => "Service",
            ColumnId::Path => "Process Path",
            ColumnId::Tx => "Tx",
            ColumnId::Rx => "Rx",
        }
    }

    pub fn default_width(self) -> u16 {
        match self {
            ColumnId::Mark => 1,
            ColumnId::Process => 16,
            ColumnId::Pid => 6,
            ColumnId::Protocol => 5,
            ColumnId::LocalAddress => 22,
            ColumnId::LocalPort => 6,
            ColumnId::RemoteAddress => 22,
            ColumnId::RemotePort => 6,
            ColumnId::State => 13,
            ColumnId::Service => 18,
            ColumnId::Path => 30,
            ColumnId::Tx => 9,
            ColumnId::Rx => 9,
        }
    }
}

// ---------------------------------------------------------------------------
// Sorting
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct SortKey {
    pub col: ColumnId,
    pub desc: bool,
}

/// Comparison value for a column: numeric columns compare numerically.
#[derive(PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum SortValue {
    Num(u64),
    Text(String),
}

pub fn cell_sort_value(row: &ConnectionRow, col: ColumnId) -> SortValue {
    match col {
        ColumnId::Pid => SortValue::Num(row.pid as u64),
        ColumnId::LocalPort => SortValue::Num(row.local_port as u64),
        ColumnId::RemotePort => SortValue::Num(row.remote_port.unwrap_or(0) as u64),
        ColumnId::Tx => SortValue::Num(row.tx_bytes.unwrap_or(0)),
        ColumnId::Rx => SortValue::Num(row.rx_bytes.unwrap_or(0)),
        ColumnId::Mark => SortValue::Num(0),
        other => SortValue::Text(cell_text(row, other, &DisplayCtx::default())),
    }
}

/// Sort rows by the given key chain (first key wins, later keys break ties).
pub fn sort_rows(rows: &mut [ConnectionRow], keys: &[SortKey]) {
    rows.sort_by(|a, b| {
        for key in keys {
            let ordering = cell_sort_value(a, key.col).cmp(&cell_sort_value(b, key.col));
            if ordering != std::cmp::Ordering::Equal {
                return if key.desc {
                    ordering.reverse()
                } else {
                    ordering
                };
            }
        }
        // Final tiebreaker: stable identity so rows do not flicker.
        a.id.local.port().cmp(&b.id.local.port()).then_with(|| {
            a.id.remote
                .map(|r| r.port())
                .cmp(&b.id.remote.map(|r| r.port()))
        })
    });
}

// ---------------------------------------------------------------------------
// Filtering
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub enum FilterKind {
    Plain(String),
    Regex(regex::Regex),
}

impl FilterKind {
    /// Parse filter text; a `re:` prefix switches to regular expressions.
    /// Plain text is case-insensitive; regexes are compiled with `(?i)`.
    pub fn parse(text: &str) -> Result<FilterKind, String> {
        if let Some(pattern) = text.strip_prefix("re:") {
            let re = regex::RegexBuilder::new(pattern)
                .case_insensitive(true)
                .build()
                .map_err(|e| format!("invalid regex: {e}"))?;
            Ok(FilterKind::Regex(re))
        } else {
            Ok(FilterKind::Plain(text.to_lowercase()))
        }
    }

    pub fn matches(&self, haystack: &str) -> bool {
        match self {
            FilterKind::Plain(p) => haystack.to_lowercase().contains(p),
            FilterKind::Regex(re) => re.is_match(haystack),
        }
    }

    pub fn describe(&self) -> String {
        match self {
            FilterKind::Plain(p) => p.clone(),
            FilterKind::Regex(re) => format!("re:{}", re.as_str()),
        }
    }
}

/// Everything a row render/sort/export needs from the environment.
pub struct DisplayCtx<'a> {
    pub processes: &'a HashMap<u32, ProcessInfo>,
    pub dns: Option<&'a DnsCache>,
    pub resolve: bool,
}

impl Default for DisplayCtx<'_> {
    fn default() -> Self {
        static EMPTY: std::sync::OnceLock<HashMap<u32, ProcessInfo>> = std::sync::OnceLock::new();
        Self {
            processes: EMPTY.get_or_init(HashMap::new),
            dns: None,
            resolve: false,
        }
    }
}

/// Text shown in a table/export cell for a column.
pub fn cell_text(row: &ConnectionRow, col: ColumnId, ctx: &DisplayCtx) -> String {
    let addr_text = |ip: &IpAddr| -> String {
        if ctx.resolve
            && let Some(cache) = ctx.dns
            && let Some(h) = cache.hostname(ip)
        {
            return h;
        }
        ip.to_string()
    };
    match col {
        ColumnId::Mark => String::new(),
        ColumnId::Process => row.process_display(),
        ColumnId::Pid => row.pid.to_string(),
        ColumnId::Protocol => row.protocol.to_string(),
        ColumnId::LocalAddress => addr_text(&row.local_addr),
        ColumnId::LocalPort => row.local_port.to_string(),
        ColumnId::RemoteAddress => match row.remote_addr {
            Some(ip) => addr_text(&ip),
            None => String::new(),
        },
        ColumnId::RemotePort => row.remote_port.map(|p| p.to_string()).unwrap_or_default(),
        ColumnId::State => row.state.map(|s| s.to_string()).unwrap_or_default(),
        ColumnId::Service => row.service_name.clone().unwrap_or_default(),
        ColumnId::Path => ctx
            .processes
            .get(&row.pid)
            .and_then(|p| p.exe.clone())
            .unwrap_or_default(),
        ColumnId::Tx => row.tx_bytes.map(format_bytes).unwrap_or_default(),
        ColumnId::Rx => row.rx_bytes.map(format_bytes).unwrap_or_default(),
    }
}

/// View toggles mirrored from config + runtime changes.
#[derive(Clone, Debug)]
pub struct ViewToggles {
    pub show_tcp: bool,
    pub show_udp: bool,
    pub show_unconnected: bool,
    pub show_loopback: bool,
    pub resolve: bool,
}

/// Apply toggles, watch mode and the active filter to a row set.
pub fn filter_rows(
    rows: &[ConnectionRow],
    toggles: &ViewToggles,
    watch_pid: Option<u32>,
    filter: Option<&FilterKind>,
    processes: &HashMap<u32, ProcessInfo>,
) -> Vec<ConnectionRow> {
    rows.iter()
        .filter(|r| {
            if r.change == RowChange::Deleted {
                return true; // ghosts stay visible for one cycle regardless
            }
            match r.protocol {
                Protocol::Tcp if !toggles.show_tcp => return false,
                Protocol::Udp if !toggles.show_udp => return false,
                _ => {}
            }
            if !toggles.show_unconnected && r.is_unconnected() {
                return false;
            }
            if !toggles.show_loopback && r.is_loopback() {
                return false;
            }
            if let Some(pid) = watch_pid
                && r.pid != pid
            {
                return false;
            }
            if let Some(f) = filter {
                let haystack = row_haystack(r, processes);
                if !f.matches(&haystack) {
                    return false;
                }
            }
            true
        })
        .cloned()
        .collect()
}

/// Text searched by both filter and search.
fn row_haystack(row: &ConnectionRow, processes: &HashMap<u32, ProcessInfo>) -> String {
    let mut parts: Vec<String> = vec![
        row.process_display(),
        row.pid.to_string(),
        row.protocol.to_string(),
        row.local_addr.to_string(),
        row.local_port.to_string(),
    ];
    if let (Some(a), Some(p)) = (row.remote_addr, row.remote_port) {
        parts.push(a.to_string());
        parts.push(p.to_string());
    }
    if let Some(s) = row.state {
        parts.push(s.to_string());
    }
    if let Some(s) = &row.service_name {
        parts.push(s.clone());
    }
    if let Some(exe) = processes.get(&row.pid).and_then(|p| p.exe.as_deref()) {
        parts.push(exe.to_string());
    }
    parts.join(" ")
}

// ---------------------------------------------------------------------------
// Themes
// ---------------------------------------------------------------------------

pub struct Theme {
    pub normal: Color,
    pub dim: Color,
    pub header: Color,
    pub new: Color,
    pub deleted: Color,
    pub changed: Color,
    pub selected_fg: Color,
    pub selected_bg: Color,
    pub marked: Color,
    pub bar: Color,
    pub accent: Color,
    pub popup_border: Color,
}

pub fn theme_by_name(name: &str) -> Theme {
    if name.eq_ignore_ascii_case("light") {
        Theme {
            normal: Color::Black,
            dim: Color::Rgb(110, 110, 110),
            header: Color::Black,
            new: Color::Rgb(0, 128, 0),
            deleted: Color::Rgb(200, 0, 0),
            changed: Color::Rgb(170, 120, 0),
            selected_fg: Color::White,
            selected_bg: Color::Rgb(60, 90, 160),
            marked: Color::Rgb(150, 0, 150),
            bar: Color::Blue,
            accent: Color::Blue,
            popup_border: Color::DarkGray,
        }
    } else {
        Theme {
            normal: Color::Gray,
            dim: Color::Rgb(130, 130, 130),
            header: Color::Cyan,
            new: Color::Green,
            deleted: Color::Red,
            changed: Color::Yellow,
            selected_fg: Color::Black,
            selected_bg: Color::Cyan,
            marked: Color::Magenta,
            bar: Color::Blue,
            accent: Color::Cyan,
            popup_border: Color::DarkGray,
        }
    }
}

// ---------------------------------------------------------------------------
// Modes and popups state
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Mode {
    Normal,
    Filtering,
    Searching,
    Confirm,
    ProcessDetail,
    Whois,
    Help,
    ColumnSetup,
    Export,
    Stats,
    Log,
}

/// Editable single-line text input (filter/search/...).
#[derive(Clone, Default)]
pub struct InputLine {
    pub value: String,
}

impl InputLine {
    pub fn push(&mut self, c: char) {
        self.value.push(c);
    }
    pub fn backspace(&mut self) {
        self.value.pop();
    }
    pub fn clear(&mut self) {
        self.value.clear();
    }
}

#[derive(Clone, Debug)]
pub enum ConfirmAction {
    Close(Vec<ConnectionRow>),
    Kill(Vec<(u32, String)>),
}

impl ConfirmAction {
    pub fn describe(&self) -> String {
        match self {
            ConfirmAction::Close(rows) => {
                let names: Vec<String> = rows
                    .iter()
                    .map(|r| {
                        format!(
                            "{} {}->{}",
                            r.process_display(),
                            r.local_display(),
                            r.remote_display()
                        )
                    })
                    .collect();
                format!("Close {} connection(s)?\n{}", rows.len(), names.join("\n"))
            }
            ConfirmAction::Kill(procs) => {
                let names: Vec<String> = procs
                    .iter()
                    .map(|(pid, name)| format!("{name} (PID {pid})"))
                    .collect();
                format!(
                    "End {} process(es)?\n{}\n\nAll their endpoints will be closed.",
                    procs.len(),
                    names.join("\n")
                )
            }
        }
    }
}

#[derive(Clone, Debug)]
pub struct WhoisState {
    pub addr: String,
    pub loading: bool,
    pub text: Option<String>,
    pub scroll: u16,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ExportSel {
    pub fmt: crate::export::ExportFormat,
    pub all: bool,
}

#[derive(Clone, Debug)]
pub struct EventEntry {
    pub at: DateTime<Local>,
    pub message: String,
}

/// One entry of the flattened view (flat or grouped).
#[derive(Clone, Debug)]
pub enum DisplayNode {
    Group {
        pid: u32,
        name: String,
        count: usize,
        expanded: bool,
    },
    Conn(usize), // index into App::visible
}

// ---------------------------------------------------------------------------
// Collector thread plumbing
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub enum CollectorCmd {
    RefreshNow,
    SetInterval(Duration),
    SetEstats(bool),
}

#[derive(Debug)]
pub enum AppMsg {
    Snapshot(Snapshot),
}

/// Spawn the background collector. It owns the process table and the
/// EStats reader, refreshing on the configured cadence or on demand.
pub fn spawn_collector(
    cmd_rx: Receiver<CollectorCmd>,
    tx: Sender<AppMsg>,
    initial_interval: Duration,
    estats_enabled: bool,
) {
    std::thread::spawn(move || {
        let mut interval = initial_interval;
        let mut sys = ProcTable::new();
        let mut estats = EStatsReader::new(estats_enabled);
        loop {
            match cmd_rx.recv_timeout(interval) {
                Ok(CollectorCmd::RefreshNow) => {}
                Ok(CollectorCmd::SetInterval(d)) => {
                    interval = d;
                    continue;
                }
                Ok(CollectorCmd::SetEstats(b)) => estats.set_enabled(b),
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
            }

            let mut rows = match crate::net::collect_sockets() {
                Ok(r) => r,
                Err(_) => continue, // transient API failure; retry next tick
            };

            sys.refresh();
            let pids: Vec<u32> = rows
                .iter()
                .map(|r| r.pid)
                .collect::<HashSet<_>>()
                .into_iter()
                .collect();
            let processes = sys.snapshot_for(&pids);
            let services = crate::services::map_pid_to_services();

            for row in &mut rows {
                row.process_name = processes.get(&row.pid).map(|p| p.name.clone());
                row.service_name = services.get(&row.pid).and_then(|list| {
                    list.first().map(|(_, display)| {
                        if display.is_empty() {
                            String::new()
                        } else {
                            display.clone()
                        }
                    })
                });
            }

            estats.poll(&mut rows);

            let snap = Snapshot {
                taken_at: Local::now(),
                rows,
                processes,
                services,
            };
            if tx.send(AppMsg::Snapshot(snap)).is_err() {
                break; // UI is gone
            }
        }
    });
}

// ---------------------------------------------------------------------------
// App
// ---------------------------------------------------------------------------

pub struct App {
    pub mode: Mode,
    pub should_quit: bool,

    // Data
    pub rows: Vec<ConnectionRow>,
    pub processes: HashMap<u32, ProcessInfo>,
    pub services: HashMap<u32, Vec<(String, String)>>,
    pub visible: Vec<ConnectionRow>,
    pub display: Vec<DisplayNode>,
    pub stats: Stats,

    // Channels
    pub collector_tx: Sender<CollectorCmd>,
    collector_rx: Receiver<AppMsg>,
    dns_tx: Sender<IpAddr>,
    whois_sx: Sender<Result<String, String>>,
    whois_rx: Receiver<Result<String, String>>,

    // View state
    pub toggles: ViewToggles,
    pub refresh_interval: Duration,
    pub filter: Option<FilterKind>,
    pub filter_input: InputLine,
    pub search: Option<FilterKind>,
    pub search_input: InputLine,
    pub sort: Vec<SortKey>,
    pub selected: usize,
    pub offset: usize,
    pub marked: HashSet<RowId>,
    pub watch_pid: Option<u32>,
    pub grouped: bool,
    pub expanded: HashSet<u32>,

    // Columns
    pub column_order: Vec<ColumnId>,
    pub column_hidden: HashSet<ColumnId>,
    pub column_width: HashMap<ColumnId, u16>,
    pub column_cursor: usize,

    // Popups
    pub confirm: Option<ConfirmAction>,
    pub detail_pid: Option<u32>,
    pub detail_lines: Vec<String>,
    pub detail_scroll: u16,
    pub whois: Option<WhoisState>,
    pub help_scroll: u16,
    pub log_scroll: usize,
    pub export_sel: ExportSel,

    // Misc
    pub theme: Theme,
    pub theme_name: String,
    pub admin: bool,
    pub event_log: Vec<EventEntry>,
    pub status: Option<(String, Instant)>,
    pub dns_cache: SharedDnsCache,
    pub estats_enabled: bool,
    pub last_snapshot_at: Option<DateTime<Local>>,
    pub started: Instant,
    pub snapshot_count: u64,

    /// Header cell screen positions filled in by the renderer for mouse
    /// hit-testing: (absolute x, width, column).
    pub header_cells: Vec<(u16, u16, ColumnId)>,
    /// Screen rect of the table body filled in by the renderer.
    pub table_area: ratatui::layout::Rect,
    /// Last mouse press for double-click detection: (time, x, y).
    pub last_click: Option<(Instant, u16, u16)>,
}

impl App {
    pub fn new(config: Config) -> App {
        let (collector_tx, collector_rx_cmd) = std::sync::mpsc::channel();
        let (msg_tx, collector_rx) = std::sync::mpsc::channel();
        let (dns_tx, dns_rx) = std::sync::mpsc::channel();
        let (whois_sx, whois_rx) = std::sync::mpsc::channel();

        let dns_cache: SharedDnsCache = Arc::new(Mutex::new(DnsCache::new()));
        dns::spawn_worker(dns_rx, Arc::clone(&dns_cache));

        let interval = Duration::from_millis(config.view.refresh_interval_ms.clamp(250, 60000));
        spawn_collector(collector_rx_cmd, msg_tx, interval, config.estats.enabled);

        let (column_order, column_hidden, column_width) = config.column_layout();
        let theme_name = config.view.theme.clone();

        let app = App {
            mode: Mode::Normal,
            should_quit: false,
            rows: Vec::new(),
            processes: HashMap::new(),
            services: HashMap::new(),
            visible: Vec::new(),
            display: Vec::new(),
            stats: Stats::default(),
            collector_tx,
            collector_rx,
            dns_tx,
            whois_sx,
            whois_rx,
            toggles: ViewToggles {
                show_tcp: config.view.show_tcp,
                show_udp: config.view.show_udp,
                show_unconnected: config.view.show_unconnected,
                show_loopback: config.view.show_loopback,
                resolve: config.view.resolve_addresses,
            },
            refresh_interval: interval,
            filter: None,
            filter_input: InputLine::default(),
            search: None,
            search_input: InputLine::default(),
            sort: vec![
                SortKey {
                    col: ColumnId::Process,
                    desc: false,
                },
                SortKey {
                    col: ColumnId::Protocol,
                    desc: false,
                },
                SortKey {
                    col: ColumnId::LocalPort,
                    desc: false,
                },
            ],
            selected: 0,
            offset: 0,
            marked: HashSet::new(),
            watch_pid: None,
            grouped: false,
            expanded: HashSet::new(),
            column_order,
            column_hidden,
            column_width,
            column_cursor: 0,
            confirm: None,
            detail_pid: None,
            detail_lines: Vec::new(),
            detail_scroll: 0,
            whois: None,
            help_scroll: 0,
            log_scroll: 0,
            export_sel: ExportSel {
                fmt: crate::export::ExportFormat::Csv,
                all: false,
            },
            theme: theme_by_name(&theme_name),
            theme_name,
            admin: crate::actions::is_elevated(),
            event_log: Vec::new(),
            status: None,
            dns_cache,
            estats_enabled: config.estats.enabled,
            last_snapshot_at: None,
            started: Instant::now(),
            snapshot_count: 0,
            header_cells: Vec::new(),
            table_area: ratatui::layout::Rect::default(),
            last_click: None,
        };
        app.request_refresh();
        app
    }

    // -- Channel plumbing ---------------------------------------------------

    pub fn request_refresh(&self) {
        let _ = self.collector_tx.send(CollectorCmd::RefreshNow);
    }

    pub fn set_interval_ms(&mut self, ms: u64) {
        let clamped = ms.clamp(250, 60000);
        self.refresh_interval = Duration::from_millis(clamped);
        let _ = self
            .collector_tx
            .send(CollectorCmd::SetInterval(self.refresh_interval));
    }

    pub fn step_interval(&mut self, faster: bool) {
        let current = self.refresh_interval.as_millis() as u64;
        // Snap to a 250 ms grid between 250 ms and 5 s, then 1 s steps.
        let next = if faster {
            if current <= 250 {
                250
            } else if current <= 5000 {
                current - 250
            } else {
                current - 1000
            }
        } else if current < 5000 {
            current + 250
        } else {
            (current + 1000).min(60000)
        };
        self.set_interval_ms(next);
        self.push_status(format!("Refresh interval: {} ms", next));
    }

    /// Drain background messages. Called from the main loop each tick.
    pub fn poll_channels(&mut self) {
        while let Ok(msg) = self.collector_rx.try_recv() {
            match msg {
                AppMsg::Snapshot(snap) => self.apply_snapshot(snap),
            }
        }
        while let Ok(result) = self.whois_rx.try_recv() {
            if let Some(w) = &mut self.whois {
                w.loading = false;
                match result {
                    Ok(text) => w.text = Some(text),
                    Err(e) => w.text = Some(format!("whois failed: {e}")),
                }
            }
        }
    }

    // -- Snapshot application ------------------------------------------------

    pub fn apply_snapshot(&mut self, snap: Snapshot) {
        // Event log: TCP open/close transitions (skip ghosts and first pass).
        if !self.rows.is_empty() {
            let mut events: Vec<String> = Vec::new();
            let next_ids: HashSet<&RowId> = snap.rows.iter().map(|r| &r.id).collect();
            for old in &self.rows {
                if old.protocol == Protocol::Tcp
                    && old.change != RowChange::Deleted
                    && !next_ids.contains(&old.id)
                {
                    events.push(format!(
                        "CLOSE  {} {} -> {} [{}] ({})",
                        old.protocol,
                        old.local_display(),
                        old.remote_display(),
                        old.state.map(|s| s.to_string()).unwrap_or_default(),
                        old.process_display(),
                    ));
                }
            }
            let prev_ids: HashSet<&RowId> = self.rows.iter().map(|r| &r.id).collect();
            for new in &snap.rows {
                if new.protocol == Protocol::Tcp && !prev_ids.contains(&new.id) {
                    events.push(format!(
                        "OPEN   {} {} -> {} [{}] ({})",
                        new.protocol,
                        new.local_display(),
                        new.remote_display(),
                        new.state.map(|s| s.to_string()).unwrap_or_default(),
                        new.process_display(),
                    ));
                }
            }
            for e in events {
                self.log_event(e);
            }
        }

        self.rows = merge_snapshots(&self.rows, snap.rows);
        self.processes = snap.processes;
        self.services = snap.services;
        self.stats = Stats::from_rows(&self.rows);
        self.last_snapshot_at = Some(snap.taken_at);
        self.snapshot_count += 1;
        self.refresh_display();
    }

    /// Recompute visible rows, sorting, grouping and DNS requests after any
    /// state change that affects what is shown.
    pub fn refresh_display(&mut self) {
        let mut rows = filter_rows(
            &self.rows,
            &self.toggles,
            self.watch_pid,
            self.filter.as_ref(),
            &self.processes,
        );
        sort_rows(&mut rows, &self.sort);
        self.visible = rows;

        self.display.clear();
        if self.grouped {
            let mut groups: Vec<(u32, String, Vec<usize>)> = Vec::new();
            for (idx, r) in self.visible.iter().enumerate() {
                if let Some(g) = groups.iter_mut().find(|(pid, _, _)| *pid == r.pid) {
                    g.2.push(idx);
                } else {
                    groups.push((r.pid, r.process_display(), vec![idx]));
                }
            }
            for (pid, name, idxs) in groups {
                let expanded = self.expanded.contains(&pid);
                self.display.push(DisplayNode::Group {
                    pid,
                    name,
                    count: idxs.len(),
                    expanded,
                });
                if expanded {
                    for i in idxs {
                        self.display.push(DisplayNode::Conn(i));
                    }
                }
            }
        } else {
            for i in 0..self.visible.len() {
                self.display.push(DisplayNode::Conn(i));
            }
        }

        if self.selected >= self.display.len() {
            self.selected = self.display.len().saturating_sub(1);
        }
        self.enqueue_dns();
    }

    /// Queue reverse lookups for addresses that are not cached yet.
    fn enqueue_dns(&mut self) {
        if !self.toggles.resolve {
            return;
        }
        // Cap per cycle to avoid a stampede after big changes.
        let mut queued = 0;
        let candidates: Vec<IpAddr> = self
            .visible
            .iter()
            .flat_map(|r| {
                let mut v = vec![r.local_addr];
                if let Some(a) = r.remote_addr {
                    v.push(a);
                }
                v
            })
            .collect();
        for ip in candidates {
            if queued >= 64 {
                break;
            }
            let fresh = self
                .dns_cache
                .lock()
                .map(|c| c.is_fresh(&ip))
                .unwrap_or(true);
            if !fresh {
                if let Ok(mut c) = self.dns_cache.lock() {
                    c.mark_pending(ip);
                }
                if self.dns_tx.send(ip).is_ok() {
                    queued += 1;
                }
            }
        }
    }

    // -- Navigation ------------------------------------------------------------

    pub fn display_len(&self) -> usize {
        self.display.len()
    }

    pub fn move_selection(&mut self, delta: i64) {
        if self.display.is_empty() {
            return;
        }
        let len = self.display.len() as i64;
        let current = self.selected as i64;
        let next = (current + delta).clamp(0, len - 1);
        self.selected = next as usize;
    }

    pub fn page_move(&mut self, up: bool, page: usize) {
        let step = page.max(1) as i64;
        self.move_selection(if up { -step } else { step });
    }

    /// Clamp scroll offset so the selection stays inside the viewport.
    pub fn ensure_visible(&mut self, page: usize) {
        let page = page.max(1);
        if self.selected < self.offset {
            self.offset = self.selected;
        } else if self.selected >= self.offset + page {
            self.offset = self.selected + 1 - page;
        }
    }

    pub fn current_row(&self) -> Option<&ConnectionRow> {
        match self.display.get(self.selected) {
            Some(DisplayNode::Conn(i)) => self.visible.get(*i),
            _ => None,
        }
    }

    /// Rows targeted by row-scoped actions: marked rows, else the selected one.
    pub fn target_rows(&self) -> Vec<ConnectionRow> {
        let marked: Vec<ConnectionRow> = self
            .visible
            .iter()
            .filter(|r| self.marked.contains(&r.id))
            .cloned()
            .collect();
        if !marked.is_empty() {
            return marked;
        }
        self.current_row().cloned().into_iter().collect()
    }

    pub fn toggle_mark(&mut self) {
        if let Some(DisplayNode::Conn(i)) = self.display.get(self.selected)
            && let Some(row) = self.visible.get(*i)
        {
            let id = row.id.clone();
            if !self.marked.remove(&id) {
                self.marked.insert(id);
            }
        }
    }

    // -- Sorting ---------------------------------------------------------------

    pub fn cycle_sort(&mut self) {
        let pos = self
            .sort
            .first()
            .map(|k| {
                DEFAULT_COLUMN_ORDER
                    .iter()
                    .position(|c| *c == k.col)
                    .unwrap_or(0)
            })
            .unwrap_or(0);
        let next = DEFAULT_COLUMN_ORDER[(pos + 1) % DEFAULT_COLUMN_ORDER.len()];
        self.set_sort_column(next, false);
    }

    pub fn reverse_sort(&mut self) {
        if let Some(first) = self.sort.first_mut() {
            first.desc = !first.desc;
        }
        self.refresh_display();
    }

    /// Make `col` the primary sort key; with `additive`, append a secondary key.
    pub fn set_sort_column(&mut self, col: ColumnId, additive: bool) {
        if additive {
            if let Some(existing) = self.sort.iter_mut().find(|k| k.col == col) {
                existing.desc = !existing.desc;
            } else if self.sort.len() < 4 {
                self.sort.push(SortKey { col, desc: false });
            }
        } else {
            let desc = self
                .sort
                .first()
                .map(|k| k.col == col && !k.desc)
                .unwrap_or(false);
            self.sort.insert(0, SortKey { col, desc });
            self.sort.truncate(4);
        }
        self.refresh_display();
    }

    // -- Filter / search ---------------------------------------------------------

    pub fn apply_filter_input(&mut self) {
        let text = self.filter_input.value.trim().to_string();
        self.filter = if text.is_empty() {
            None
        } else {
            match FilterKind::parse(&text) {
                Ok(f) => Some(f),
                Err(e) => {
                    self.push_status(e);
                    self.filter.clone()
                }
            }
        };
        self.mode = Mode::Normal;
        self.selected = 0;
        self.refresh_display();
    }

    pub fn clear_filter(&mut self) {
        self.filter = None;
        self.filter_input.clear();
        self.selected = 0;
        self.refresh_display();
    }

    pub fn apply_search_input(&mut self) {
        let text = self.search_input.value.trim().to_string();
        self.search = if text.is_empty() {
            None
        } else {
            match FilterKind::parse(&text) {
                Ok(f) => Some(f),
                Err(e) => {
                    self.push_status(e);
                    None
                }
            }
        };
        self.mode = Mode::Normal;
        if self.search.is_some() {
            self.search_next(true);
        }
    }

    /// Jump to the next/previous row matching the active search.
    pub fn search_next(&mut self, forward: bool) {
        let Some(search) = self.search.clone() else {
            return;
        };
        let len = self.display.len();
        if len == 0 {
            return;
        }
        let matches: Vec<usize> = self
            .display
            .iter()
            .enumerate()
            .filter(|(_, node)| match node {
                DisplayNode::Conn(i) => self
                    .visible
                    .get(*i)
                    .map(|r| search.matches(&row_haystack(r, &self.processes)))
                    .unwrap_or(false),
                DisplayNode::Group { name, .. } => search.matches(name),
            })
            .map(|(idx, _)| idx)
            .collect();
        if matches.is_empty() {
            self.push_status("No matches for search");
            return;
        }
        let pos = matches
            .iter()
            .position(|m| *m >= self.selected)
            .unwrap_or(0);
        let target = if forward {
            matches[(pos + 1) % matches.len()]
        } else {
            matches[(pos + matches.len() - 1) % matches.len()]
        };
        self.selected = target;
    }

    // -- Actions ---------------------------------------------------------------

    pub fn begin_confirm_close(&mut self) {
        let targets: Vec<ConnectionRow> = self
            .target_rows()
            .into_iter()
            .filter(|r| r.is_established() && r.remote_addr.is_some())
            .collect();
        if targets.is_empty() {
            self.push_status("No closable ESTABLISHED connection selected");
            return;
        }
        self.confirm = Some(ConfirmAction::Close(targets));
        self.mode = Mode::Confirm;
    }

    pub fn begin_confirm_kill(&mut self) {
        let mut pids: Vec<u32> = self.target_rows().iter().map(|r| r.pid).collect();
        pids.sort();
        pids.dedup();
        if pids.is_empty() {
            self.push_status("Nothing selected");
            return;
        }
        let procs: Vec<(u32, String)> = pids
            .iter()
            .map(|pid| {
                (
                    *pid,
                    self.target_rows()
                        .iter()
                        .find(|r| r.pid == *pid)
                        .map(|r| r.process_display())
                        .unwrap_or_else(|| "<unknown>".into()),
                )
            })
            .collect();
        self.confirm = Some(ConfirmAction::Kill(procs));
        self.mode = Mode::Confirm;
    }

    pub fn execute_confirm(&mut self) {
        let Some(action) = self.confirm.take() else {
            self.mode = Mode::Normal;
            return;
        };
        match action {
            ConfirmAction::Close(rows) => {
                let mut closed = 0;
                let mut errors: Vec<String> = Vec::new();
                for row in &rows {
                    match crate::actions::close_connection(row) {
                        Ok(()) => {
                            closed += 1;
                            self.log_event(format!(
                                "USER   closed connection {} -> {} ({})",
                                row.local_display(),
                                row.remote_display(),
                                row.process_display()
                            ));
                        }
                        Err(e) => errors.push(e.to_string()),
                    }
                }
                if closed > 0 {
                    self.push_status(format!("Closed {closed} connection(s)"));
                }
                if !errors.is_empty() {
                    self.push_status(format!("Close failed: {}", errors.join("; ")));
                }
                self.marked.clear();
            }
            ConfirmAction::Kill(procs) => {
                let mut sys = ProcTable::new();
                let mut killed = 0;
                let mut failed: Vec<String> = Vec::new();
                for (pid, name) in &procs {
                    if sys.kill(*pid) {
                        killed += 1;
                        self.log_event(format!("USER   ended process {name} (PID {pid})"));
                    } else {
                        failed.push(format!("{name} ({pid})"));
                    }
                }
                if killed > 0 {
                    self.push_status(format!("Terminated {killed} process(es)"));
                }
                if !failed.is_empty() {
                    self.push_status(format!("Could not terminate: {}", failed.join(", ")));
                }
                self.marked.clear();
            }
        }
        self.mode = Mode::Normal;
        self.request_refresh();
    }

    pub fn request_whois(&mut self) {
        let Some(row) = self.current_row() else {
            return;
        };
        let Some(addr) = row.remote_addr else {
            self.push_status("Selected endpoint has no remote address");
            return;
        };
        let query = addr.to_string();
        self.whois = Some(WhoisState {
            addr: query.clone(),
            loading: true,
            text: None,
            scroll: 0,
        });
        self.mode = Mode::Whois;
        let sx = self.whois_sx.clone();
        std::thread::spawn(move || {
            let result = crate::actions::whois(&query).map_err(|e| e.to_string());
            let _ = sx.send(result);
        });
    }

    pub fn begin_detail(&mut self) {
        let Some(row) = self.current_row() else {
            return;
        };
        let pid = row.pid;
        self.detail_pid = Some(pid);
        self.detail_lines = self.build_detail_lines(pid);
        self.detail_scroll = 0;
        self.mode = Mode::ProcessDetail;
    }

    /// Build process detail popup content (path, cmdline, user, services,
    /// per-process connections, usage).
    fn build_detail_lines(&self, pid: u32) -> Vec<String> {
        let mut lines = Vec::new();
        let proc = self.processes.get(&pid);
        let name = proc
            .map(|p| p.name.clone())
            .or_else(|| {
                self.rows
                    .iter()
                    .find(|r| r.pid == pid)
                    .map(|r| r.process_display())
            })
            .unwrap_or_else(|| "<unknown>".into());
        lines.push(format!("Process: {name}"));
        lines.push(format!("PID:     {pid}"));
        lines.push(format!(
            "User:    {}",
            crate::actions::process_user(pid).unwrap_or_else(|| "<unavailable>".into())
        ));
        if let Some(p) = proc {
            lines.push(format!(
                "Path:    {}",
                p.exe.clone().unwrap_or_else(|| "<n/a>".into())
            ));
            if let Some(cmd) = &p.cmd {
                let cmd_display = if cmd.chars().count() > 100 {
                    format!("{}…", cmd.chars().take(100).collect::<String>())
                } else {
                    cmd.clone()
                };
                lines.push(format!("Cmd:     {cmd_display}"));
            }
            lines.push(format!(
                "CPU:     {:.1}%   Memory: {}",
                p.cpu,
                format_bytes(p.mem)
            ));
        }
        let svcs = self.services.get(&pid).cloned().unwrap_or_default();
        if svcs.is_empty() {
            lines.push("Services: (none)".to_string());
        } else {
            lines.push(format!("Services: {} hosted", svcs.len()));
            for (name, display) in svcs.iter().take(10) {
                if display.is_empty() {
                    lines.push(format!("  - {name}"));
                } else {
                    lines.push(format!("  - {display} ({name})"));
                }
            }
            if svcs.len() > 10 {
                lines.push(format!("  ... and {} more", svcs.len() - 10));
            }
        }
        lines.push(String::new());
        let conns: Vec<&ConnectionRow> = self.rows.iter().filter(|r| r.pid == pid).collect();
        lines.push(format!("Endpoints ({}):", conns.len()));
        for c in conns.iter().take(24) {
            lines.push(format!(
                "  {} {}:{} -> {} [{}] tx={} rx={}",
                c.protocol,
                c.local_addr,
                c.local_port,
                c.remote_display(),
                c.state.map(|s| s.to_string()).unwrap_or_default(),
                c.tx_bytes.map(format_bytes).unwrap_or_else(|| "-".into()),
                c.rx_bytes.map(format_bytes).unwrap_or_else(|| "-".into()),
            ));
        }
        if conns.len() > 24 {
            lines.push(format!("  ... and {} more", conns.len() - 24));
        }
        lines
    }

    // -- Copy / export -----------------------------------------------------------

    pub fn export_headers_and_rows(&self, all: bool) -> (Vec<String>, Vec<Vec<String>>) {
        let dns_guard = self.dns_cache.lock().ok();
        let ctx = DisplayCtx {
            processes: &self.processes,
            dns: dns_guard.as_deref(),
            resolve: self.toggles.resolve,
        };
        let cols: Vec<ColumnId> = self
            .column_order
            .iter()
            .copied()
            .filter(|c| *c != ColumnId::Mark && !self.column_hidden.contains(c))
            .collect();
        let headers: Vec<String> = cols.iter().map(|c| c.header().to_string()).collect();
        let source: Vec<&ConnectionRow> = if all {
            self.rows.iter().collect()
        } else {
            self.visible.iter().collect()
        };
        let rows: Vec<Vec<String>> = source
            .iter()
            .map(|r| cols.iter().map(|c| cell_text(r, *c, &ctx)).collect())
            .collect();
        (headers, rows)
    }

    pub fn do_export(&mut self) {
        let sel = self.export_sel;
        let (headers, rows) = self.export_headers_and_rows(sel.all);
        match crate::export::render(&headers, &rows, sel.fmt) {
            Ok(content) => {
                let name = crate::export::default_file_name(sel.fmt);
                match crate::export::write_file(std::path::Path::new(&name), &content) {
                    Ok(path) => {
                        self.push_status(format!(
                            "Exported {} rows to {}",
                            rows.len(),
                            path.display()
                        ));
                        self.log_event(format!(
                            "USER   exported {} rows to {}",
                            rows.len(),
                            path.display()
                        ));
                    }
                    Err(e) => self.push_status(format!("Export failed: {e}")),
                }
            }
            Err(e) => self.push_status(format!("Export failed: {e}")),
        }
        self.mode = Mode::Normal;
    }

    pub fn copy_current_row(&mut self) {
        let (headers, rows) = self.export_headers_and_rows(false);
        if let Some(first) = rows.first() {
            let line = headers
                .iter()
                .zip(first)
                .map(|(h, v)| format!("{h}={v}"))
                .collect::<Vec<_>>()
                .join("  ");
            match crate::clipboard::copy_text(&line) {
                Ok(()) => self.push_status("Row copied to clipboard"),
                Err(e) => self.push_status(format!("Clipboard error: {e}")),
            }
        }
    }

    pub fn copy_table(&mut self) {
        let (headers, rows) = self.export_headers_and_rows(false);
        match crate::export::render(&headers, &rows, crate::export::ExportFormat::Tsv) {
            Ok(text) => match crate::clipboard::copy_text(&text) {
                Ok(()) => self.push_status(format!("{} rows copied to clipboard", rows.len())),
                Err(e) => self.push_status(format!("Clipboard error: {e}")),
            },
            Err(e) => self.push_status(format!("Clipboard error: {e}")),
        }
    }

    // -- Misc -------------------------------------------------------------------

    pub fn toggle_grouped(&mut self) {
        self.grouped = !self.grouped;
        self.selected = 0;
        self.refresh_display();
    }

    pub fn toggle_watch(&mut self) {
        let selected_pid = self.current_row().map(|r| r.pid);
        self.watch_pid = match (self.watch_pid, selected_pid) {
            (Some(_), _) => {
                self.push_status("Watch mode off");
                None
            }
            (None, Some(pid)) => {
                self.push_status(format!("Watching PID {pid}"));
                Some(pid)
            }
            (None, None) => None,
        };
        self.selected = 0;
        self.refresh_display();
    }

    pub fn toggle_resolve(&mut self) {
        self.toggles.resolve = !self.toggles.resolve;
        self.push_status(if self.toggles.resolve {
            "Address resolution on".to_string()
        } else {
            "Address resolution off".to_string()
        });
        self.refresh_display();
    }

    pub fn log_event(&mut self, message: String) {
        self.event_log.push(EventEntry {
            at: Local::now(),
            message,
        });
        if self.event_log.len() > 2000 {
            let drop = self.event_log.len() - 2000;
            self.event_log.drain(..drop);
        }
    }

    pub fn push_status(&mut self, msg: impl Into<String>) {
        self.status = Some((msg.into(), Instant::now()));
    }

    pub fn current_status(&self) -> Option<&str> {
        self.status
            .as_ref()
            .filter(|(_, t)| t.elapsed() < Duration::from_secs(4))
            .map(|(m, _)| m.as_str())
    }

    pub fn save_config(&self) {
        let mut cfg = Config::default();
        cfg.view.refresh_interval_ms = self.refresh_interval.as_millis() as u64;
        cfg.view.resolve_addresses = self.toggles.resolve;
        cfg.view.show_tcp = self.toggles.show_tcp;
        cfg.view.show_udp = self.toggles.show_udp;
        cfg.view.show_unconnected = self.toggles.show_unconnected;
        cfg.view.show_loopback = self.toggles.show_loopback;
        cfg.view.theme = self.theme_name.clone();
        cfg.estats.enabled = self.estats_enabled;
        cfg.set_column_layout(&self.column_order, &self.column_hidden, &self.column_width);
        if let Err(e) = cfg.save() {
            eprintln!("warning: could not save config: {e}");
        }
    }

    /// Screen-space row index for a mouse click inside the table body.
    pub fn row_at_screen_y(&self, y: u16) -> Option<usize> {
        let area = self.table_area;
        if area.height == 0 || y <= area.y || y >= area.y + area.height {
            return None;
        }
        let idx = self.offset + (y - area.y - 1) as usize;
        (idx < self.display.len()).then_some(idx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    fn sample_rows() -> Vec<ConnectionRow> {
        vec![
            ConnectionRow::new(
                Protocol::Tcp,
                v4(127, 0, 0, 1),
                5001,
                Some(v4(93, 184, 216, 34)),
                Some(443),
                Some(netstat2::TcpState::Established),
                100,
            ),
            ConnectionRow::new(
                Protocol::Tcp,
                v4(10, 0, 0, 5),
                7443,
                Some(v4(1, 1, 1, 1)),
                Some(853),
                Some(netstat2::TcpState::Established),
                200,
            ),
            ConnectionRow::new(
                Protocol::Tcp,
                v4(0, 0, 0, 0),
                8080,
                None,
                None,
                Some(netstat2::TcpState::Listen),
                100,
            ),
            ConnectionRow::new(Protocol::Udp, v4(127, 0, 0, 1), 5353, None, None, None, 300),
        ]
    }

    fn toggles() -> ViewToggles {
        ViewToggles {
            show_tcp: true,
            show_udp: true,
            show_unconnected: true,
            show_loopback: true,
            resolve: false,
        }
    }

    #[test]
    fn filter_by_plain_text_matches_process_pid_and_ports() {
        let mut rows = sample_rows();
        rows[0].process_name = Some("chrome.exe".into());
        let f = FilterKind::parse("chrome").unwrap();
        let out = filter_rows(&rows, &toggles(), None, Some(&f), &HashMap::new());
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].pid, 100);

        let f = FilterKind::parse("443").unwrap();
        let out = filter_rows(&rows, &toggles(), None, Some(&f), &HashMap::new());
        assert!(out.iter().any(|r| r.remote_port == Some(443)));

        let f = FilterKind::parse("ESTABLISHED").unwrap();
        let out = filter_rows(&rows, &toggles(), None, Some(&f), &HashMap::new());
        assert_eq!(out.len(), 2);
    }

    #[test]
    fn filter_regex_prefix_compiles_case_insensitive() {
        let f = FilterKind::parse("re:^chrome").unwrap();
        assert!(f.matches("Chrome.exe"));
        assert!(!f.matches("mychrome"));
        assert!(FilterKind::parse("re:[").is_err());
    }

    #[test]
    fn toggles_filter_protocols_loopback_and_unconnected() {
        let rows = sample_rows();
        let mut t = toggles();
        t.show_udp = false;
        assert!(
            filter_rows(&rows, &t, None, None, &HashMap::new())
                .iter()
                .all(|r| r.protocol == Protocol::Tcp)
        );

        let mut t = toggles();
        t.show_unconnected = false;
        let out = filter_rows(&rows, &t, None, None, &HashMap::new());
        assert!(out.iter().all(|r| r.is_connected_tcp()));

        let mut t = toggles();
        t.show_loopback = false;
        let out = filter_rows(&rows, &t, None, None, &HashMap::new());
        assert!(out.iter().all(|r| !r.is_loopback()));

        let out = filter_rows(&rows, &toggles(), Some(200), None, &HashMap::new());
        assert!(out.iter().all(|r| r.pid == 200));
    }

    #[test]
    fn sorting_numeric_and_text_columns() {
        let mut rows = sample_rows();
        rows[0].tx_bytes = Some(500);
        rows[1].tx_bytes = Some(9000);
        sort_rows(
            &mut rows,
            &[SortKey {
                col: ColumnId::Tx,
                desc: true,
            }],
        );
        assert_eq!(rows[0].remote_port, Some(853));

        sort_rows(
            &mut rows,
            &[SortKey {
                col: ColumnId::LocalPort,
                desc: false,
            }],
        );
        assert_eq!(rows[0].local_port, 5001);
    }

    #[test]
    fn cell_text_uses_hostname_when_resolving() {
        let mut cache = DnsCache::new();
        cache.resolve(v4(93, 184, 216, 34), Some("example.com".into()));
        let rows = sample_rows();
        let ctx = DisplayCtx {
            processes: &HashMap::new(),
            dns: Some(&cache),
            resolve: true,
        };
        assert_eq!(
            cell_text(&rows[0], ColumnId::RemoteAddress, &ctx),
            "example.com"
        );

        let ctx_off = DisplayCtx {
            processes: &HashMap::new(),
            dns: Some(&cache),
            resolve: false,
        };
        assert_eq!(
            cell_text(&rows[0], ColumnId::RemoteAddress, &ctx_off),
            "93.184.216.34"
        );
    }

    #[test]
    fn sort_describe_and_column_keys_roundtrip() {
        for id in DEFAULT_COLUMN_ORDER {
            assert_eq!(ColumnId::from_key(id.key()), Some(*id));
        }
    }
}
