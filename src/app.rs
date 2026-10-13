//! Application state: modes, filtering, sorting, grouping, background
//! collector thread and every state transition the UI reflects.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::mpsc::{Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use chrono::{DateTime, Local};
use ratatui::style::{Color, Style};

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
    Age,
    Country,
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
    ColumnId::Age,
    ColumnId::Country,
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
            ColumnId::Age => "age",
            ColumnId::Country => "country",
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
            ColumnId::Age => "Age",
            ColumnId::Country => "Country",
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
            ColumnId::Age => 7,
            ColumnId::Country => 12,
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

/// The default sort chain: process, then protocol, then local port.
pub fn default_sort_chain() -> Vec<SortKey> {
    vec![
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
    ]
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
        ColumnId::Age => SortValue::Num(crate::model::age_seconds(row.first_seen)),
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
    /// Structured field expression (`process=chrome and tx>1MB`).
    Expr {
        src: String,
        expr: crate::filter::Expr,
    },
}

impl FilterKind {
    /// Parse filter text. Routing: a `re:` prefix builds a regex; text with
    /// operators or boolean keywords is parsed as a structured field
    /// expression; everything else stays plain free-text search.
    pub fn parse(text: &str) -> Result<FilterKind, String> {
        if let Some(pattern) = text.strip_prefix("re:") {
            let re = regex::RegexBuilder::new(pattern)
                .case_insensitive(true)
                .build()
                .map_err(|e| format!("invalid regex: {e}"))?;
            return Ok(FilterKind::Regex(re));
        }
        if crate::filter::looks_structured(text) {
            let expr = crate::filter::parse(text)?;
            return Ok(FilterKind::Expr {
                src: text.to_string(),
                expr,
            });
        }
        Ok(FilterKind::Plain(text.to_lowercase()))
    }

    /// Evaluate against a full row (works for all variants).
    pub fn matches_row(&self, row: &ConnectionRow, processes: &HashMap<u32, ProcessInfo>) -> bool {
        match self {
            FilterKind::Plain(p) => row_haystack(row, processes)
                .to_lowercase()
                .contains(p.as_str()),
            FilterKind::Regex(re) => re.is_match(&row_haystack(row, processes)),
            FilterKind::Expr { expr, .. } => {
                crate::filter::matches(expr, &crate::filter::MatchCtx { row, processes })
            }
        }
    }

    pub fn describe(&self) -> String {
        match self {
            FilterKind::Plain(p) => p.clone(),
            FilterKind::Regex(re) => format!("re:{}", re.as_str()),
            FilterKind::Expr { src, .. } => src.clone(),
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
        ColumnId::Age => crate::model::age_string(row.first_seen),
        // Filled by the optional GeoIP resolver (Phase C); empty without it.
        ColumnId::Country => String::new(),
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
            if let Some(f) = filter
                && !f.matches_row(r, processes)
            {
                return false;
            }
            true
        })
        .cloned()
        .collect()
}

/// Text searched by both filter and search.
fn row_haystack(row: &ConnectionRow, processes: &HashMap<u32, ProcessInfo>) -> String {
    crate::filter::haystack(row, processes)
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

/// Built-in themes selectable via `--theme`, config or the settings popup.
pub const THEMES: &[&str] = &[
    "dark",
    "light",
    "gruvbox",
    "nord",
    "solarized-dark",
    "solarized-light",
];

pub fn theme_by_name(name: &str) -> Theme {
    let name = name.to_ascii_lowercase();
    match name.as_str() {
        "light" => Theme {
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
        },
        "gruvbox" => Theme {
            normal: Color::Rgb(235, 219, 178), // fg2 creamy
            dim: Color::Rgb(146, 131, 116),    // gray
            header: Color::Rgb(184, 187, 38),  // green
            new: Color::Rgb(152, 151, 26),     // green darker
            deleted: Color::Rgb(204, 36, 29),  // red
            changed: Color::Rgb(215, 153, 33), // yellow
            selected_fg: Color::Rgb(40, 40, 40),
            selected_bg: Color::Rgb(250, 189, 47), // yellow bright
            marked: Color::Rgb(211, 134, 155),     // purple
            bar: Color::Rgb(69, 133, 136),         // blue
            accent: Color::Rgb(142, 192, 124),     // aqua
            popup_border: Color::Rgb(80, 73, 69),  // bg2
        },
        "nord" => Theme {
            normal: Color::Rgb(216, 222, 233),  // snow storm
            dim: Color::Rgb(143, 152, 168),     // frost dark
            header: Color::Rgb(136, 192, 208),  // frost
            new: Color::Rgb(163, 190, 140),     // green
            deleted: Color::Rgb(191, 97, 106),  // red
            changed: Color::Rgb(235, 203, 139), // yellow
            selected_fg: Color::Rgb(46, 52, 64),
            selected_bg: Color::Rgb(129, 161, 193), // frost blue
            marked: Color::Rgb(180, 142, 173),      // purple
            bar: Color::Rgb(94, 129, 172),          // blue
            accent: Color::Rgb(136, 192, 208),
            popup_border: Color::Rgb(76, 86, 106), // polar night
        },
        "solarized-light" => Theme {
            normal: Color::Rgb(101, 123, 131), // base00
            dim: Color::Rgb(147, 161, 161),    // base1
            header: Color::Rgb(38, 139, 210),  // blue
            new: Color::Rgb(133, 153, 0),      // green
            deleted: Color::Rgb(220, 50, 47),  // red
            changed: Color::Rgb(181, 137, 0),  // yellow
            selected_fg: Color::Rgb(253, 246, 227),
            selected_bg: Color::Rgb(38, 139, 210),
            marked: Color::Rgb(108, 113, 196), // violet
            bar: Color::Rgb(147, 161, 161),
            accent: Color::Rgb(42, 161, 152), // cyan
            popup_border: Color::Rgb(88, 110, 117),
        },
        // "dark" and anything unknown
        _ => Theme {
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
        },
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
    SortSetup,
    Export,
    Stats,
    Log,
    Chart,
    Rules,
    Profiles,
    Settings,
    Vt,
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

/// A parsed alert rule.
#[derive(Clone, Debug)]
pub struct AlertState {
    pub kind: FilterKind,
    pub enabled: bool,
}

/// A parsed coloring rule with its resolved style.
#[derive(Clone, Debug)]
pub struct ColorRule {
    pub kind: FilterKind,
    pub enabled: bool,
    pub style: Style,
    /// Original config representation, preserved for lossless persistence.
    pub raw: crate::config::ColorRuleSerde,
}

/// Which tab of the rules popup is active.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RulesTab {
    Alerts,
    Colors,
}

/// Parse a ratatui color from a config-friendly name.
pub fn parse_color(name: &str) -> Option<Color> {
    let c = match name.to_ascii_lowercase().as_str() {
        "black" => Color::Black,
        "red" => Color::Red,
        "green" => Color::Green,
        "yellow" => Color::Yellow,
        "blue" => Color::Blue,
        "magenta" => Color::Magenta,
        "cyan" => Color::Cyan,
        "gray" | "grey" => Color::Gray,
        "dark_gray" | "dark_grey" => Color::DarkGray,
        "white" | "light_gray" | "light_grey" => Color::White,
        "light_red" => Color::LightRed,
        "light_green" => Color::LightGreen,
        "light_yellow" => Color::LightYellow,
        "light_blue" => Color::LightBlue,
        "light_magenta" => Color::LightMagenta,
        "light_cyan" => Color::LightCyan,
        "reset" | "default" => Color::Reset,
        _ => return None,
    };
    Some(c)
}

/// Which series the bandwidth chart shows.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum BwView {
    Total,
    Selected,
}

/// VirusTotal popup state (works with or without the cargo feature).
#[derive(Clone, Debug)]
pub struct VtState {
    pub subject: String,
    pub loading: bool,
    pub text: Option<String>,
    pub scroll: u16,
}

/// Rolling-window length for the bandwidth chart (≈2 minutes at 1 s).
pub const BW_WINDOW: usize = 120;

/// Per-interval byte delta, tolerant of counter resets; 0 when the row was
/// not seen on the previous snapshot (first sighting establishes a baseline).
pub fn bw_delta(new: u64, old: Option<u64>) -> u64 {
    match old {
        Some(old) if new >= old => new - old,
        Some(_) => new, // counter reset: everything since the reset
        None => 0,
    }
}

/// Push a sample into a rolling window capped at `cap`.
pub fn bw_push(window: &mut std::collections::VecDeque<(u64, u64)>, tx: u64, rx: u64, cap: usize) {
    window.push_back((tx, rx));
    while window.len() > cap {
        window.pop_front();
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
    /// Live updates frozen (p toggles); snapshots are dropped while on.
    pub paused: bool,
    pub filter: Option<FilterKind>,
    pub filter_input: InputLine,
    pub search: Option<FilterKind>,
    pub search_input: InputLine,
    pub sort: Vec<SortKey>,
    pub selected: usize,
    pub offset: usize,
    pub marked: HashSet<RowId>,
    /// Anchor for Shift+arrow range marking.
    pub select_anchor: usize,
    pub watch_pid: Option<u32>,
    pub grouped: bool,

    // Rules (alerts + coloring)
    pub alerts: Vec<AlertState>,
    pub color_rules: Vec<ColorRule>,
    /// Unacknowledged alert messages (newest last, capped).
    pub alert_pending: Vec<String>,
    pub rules_cursor: usize,
    pub rules_tab: RulesTab,
    /// Active text input inside the rules popup, if any.
    pub rules_input: Option<InputLine>,

    // Bandwidth chart state
    /// Cumulative EStats counters as of the previous snapshot.
    pub bw_prev: HashMap<RowId, (u64, u64)>,
    pub bw_total: std::collections::VecDeque<(u64, u64)>,
    pub bw_selected: std::collections::VecDeque<(u64, u64)>,
    pub bw_selected_id: Option<RowId>,
    pub bw_view: BwView,
    pub expanded: HashSet<u32>,

    // Phase C: geoip, profiles, settings
    /// Optional GeoIP resolver; `None` when the feature is off, disabled in
    /// config or the database file is missing.
    pub geo: Option<std::sync::Mutex<crate::geoip::GeoResolver>>,
    pub geoip_enabled: bool,
    /// Named view profiles (persisted verbatim).
    pub profiles: Vec<crate::config::ProfileSerde>,
    pub profile_cursor: usize,
    pub profile_input: Option<InputLine>,
    pub settings_cursor: usize,

    // Experimental ETW mode (Phase D)
    /// Keep-alive for the ETW session; dropping it stops the session.
    pub etw_session: Option<crate::etw::EtwSession>,
    pub etw_rx: Option<std::sync::mpsc::Receiver<crate::etw::EtwEvent>>,
    /// Connect timestamps seen via ETW, used to correct `first_seen`.
    pub etw_connects: HashMap<RowId, DateTime<Local>>,

    // Authenticode cache (Phase D)
    pub signed_cache: HashMap<String, Option<bool>>,

    // VirusTotal (Phase E)
    pub vt_state: Option<VtState>,
    pub vt_rx: Option<std::sync::mpsc::Receiver<Result<String, String>>>,
    pub vt_api_key: String,

    // Columns
    pub column_order: Vec<ColumnId>,
    pub column_hidden: HashSet<ColumnId>,
    pub column_width: HashMap<ColumnId, u16>,
    pub column_cursor: usize,
    /// Cursor inside the sort-order editor popup.
    pub sort_cursor: usize,
    /// Recently applied filters, newest last (max 20).
    pub filter_history: Vec<String>,
    /// Position while walking the history with Up/Down.
    pub filter_history_idx: Option<usize>,

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
    pub fn new(
        config: Config,
        etw_rx: Option<std::sync::mpsc::Receiver<crate::etw::EtwEvent>>,
    ) -> App {
        let (collector_tx, collector_rx_cmd) = std::sync::mpsc::channel();
        let (msg_tx, collector_rx) = std::sync::mpsc::channel();
        let (dns_tx, dns_rx) = std::sync::mpsc::channel();
        let (whois_sx, whois_rx) = std::sync::mpsc::channel();

        let dns_cache: SharedDnsCache = Arc::new(Mutex::new(DnsCache::new()));
        dns::spawn_worker(dns_rx, Arc::clone(&dns_cache));

        let interval = Duration::from_millis(config.view.refresh_interval_ms.clamp(250, 60000));
        spawn_collector(collector_rx_cmd, msg_tx, interval, config.estats.enabled);

        let theme_name = config.view.theme.clone();

        // Sort order from config; fall back to the default chain.
        let mut config_sort: Vec<SortKey> = config
            .view
            .sort
            .iter()
            .filter_map(|s| ColumnId::from_key(&s.col).map(|col| SortKey { col, desc: s.desc }))
            .collect();
        if config_sort.is_empty() {
            config_sort = default_sort_chain();
        }

        // Rules from config; unparsable entries are skipped (not fatal).
        let alerts: Vec<AlertState> = config
            .alerts
            .iter()
            .filter_map(|a| {
                FilterKind::parse(&a.expression)
                    .ok()
                    .map(|kind| AlertState {
                        kind,
                        enabled: a.enabled,
                    })
            })
            .collect();
        let color_rules: Vec<ColorRule> = config
            .colors
            .iter()
            .filter_map(|c| {
                FilterKind::parse(&c.expression).ok().map(|kind| {
                    let mut style = Style::default();
                    if let Some(fg) = c.fg.as_deref().and_then(parse_color) {
                        style = style.fg(fg);
                    }
                    if let Some(bg) = c.bg.as_deref().and_then(parse_color) {
                        style = style.bg(bg);
                    }
                    if c.bold {
                        style = style.add_modifier(ratatui::style::Modifier::BOLD);
                    }
                    if c.underline {
                        style = style.add_modifier(ratatui::style::Modifier::UNDERLINED);
                    }
                    ColorRule {
                        kind,
                        enabled: c.enabled,
                        style,
                        raw: c.clone(),
                    }
                })
            })
            .collect();

        // GeoIP resolver: only when enabled AND the database opens. Without
        // it the Country column stays hidden (soft failure).
        let geo = if config.geoip.enabled {
            crate::geoip::GeoResolver::open(std::path::Path::new(&config.geoip.path))
                .ok()
                .map(std::sync::Mutex::new)
        } else {
            None
        };
        let geoip_enabled = config.geoip.enabled;
        let (column_order, mut column_hidden, column_width) = config.column_layout();
        if geo.is_none() {
            column_hidden.insert(ColumnId::Country);
        }

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
            paused: false,
            filter: None,
            filter_input: InputLine::default(),
            filter_history: Vec::new(),
            filter_history_idx: None,
            search: None,
            search_input: InputLine::default(),
            sort: config_sort,
            selected: 0,
            offset: 0,
            marked: HashSet::new(),
            select_anchor: 0,
            watch_pid: None,
            grouped: false,
            alerts,
            color_rules,
            alert_pending: Vec::new(),
            rules_cursor: 0,
            rules_tab: RulesTab::Alerts,
            rules_input: None,
            bw_prev: HashMap::new(),
            bw_total: std::collections::VecDeque::new(),
            bw_selected: std::collections::VecDeque::new(),
            bw_selected_id: None,
            bw_view: BwView::Total,
            expanded: HashSet::new(),
            geo,
            geoip_enabled,
            profiles: config.profiles.clone(),
            profile_cursor: 0,
            profile_input: None,
            settings_cursor: 0,
            etw_session: None,
            etw_rx,
            etw_connects: HashMap::new(),
            signed_cache: HashMap::new(),
            vt_state: None,
            vt_rx: None,
            vt_api_key: config.virustotal.api_key.clone(),
            column_order,
            column_hidden,
            column_width,
            column_cursor: 0,
            sort_cursor: 0,
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
        let mut etw_events = Vec::new();
        if let Some(rx) = &self.etw_rx {
            while let Ok(event) = rx.try_recv() {
                etw_events.push(event);
            }
        }
        for event in etw_events {
            self.handle_etw_event(event);
        }
        let vt_results: Vec<Result<String, String>> = self
            .vt_rx
            .as_ref()
            .map(|rx| {
                let mut out = Vec::new();
                while let Ok(r) = rx.try_recv() {
                    out.push(r);
                }
                out
            })
            .unwrap_or_default();
        for result in vt_results {
            if let Some(state) = &mut self.vt_state {
                state.loading = false;
                match result {
                    Ok(text) => state.text = Some(text),
                    Err(e) => state.text = Some(format!("VirusTotal lookup failed: {e}")),
                }
            }
        }
    }

    /// Apply one ETW event: remember connect timestamps, log connections
    /// that closed before any snapshot could see them.
    pub(crate) fn handle_etw_event(&mut self, event: crate::etw::EtwEvent) {
        use crate::etw::EtwEvent;
        match event {
            EtwEvent::Connect {
                pid, local, remote, ..
            } => {
                let id = RowId {
                    protocol: Protocol::Tcp,
                    local,
                    remote: Some(remote),
                    pid,
                };
                self.etw_connects.insert(id, Local::now());
            }
            EtwEvent::Disconnect {
                pid, local, remote, ..
            } => {
                let id = RowId {
                    protocol: Protocol::Tcp,
                    local,
                    remote: Some(remote),
                    pid,
                };
                if let Some(opened) = self.etw_connects.remove(&id) {
                    // Rows already visible are closed by the snapshot diff;
                    // anything else lived entirely between two snapshots.
                    let known = self.rows.iter().any(|r| r.id == id);
                    if !known {
                        let lived = Local::now()
                            .signed_duration_since(opened)
                            .num_milliseconds();
                        self.log_event(format!(
                            "OPEN+CLOSE (transient, {lived} ms) tcp {local} -> {remote} pid {pid}"
                        ));
                    }
                }
            }
        }
    }

    // -- Snapshot application ------------------------------------------------

    pub fn apply_snapshot(&mut self, snap: Snapshot) {
        if self.paused {
            return; // frozen view: snapshots are dropped until resumed
        }
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

        let mut rows = merge_snapshots(&self.rows, snap.rows);
        // ETW knows the real connect time even when the snapshot is late.
        for row in rows.iter_mut() {
            if let Some(opened) = self.etw_connects.get(&row.id).copied() {
                row.first_seen = Some(opened);
            }
        }
        self.rows = rows;
        self.processes = snap.processes;
        self.services = snap.services;
        self.stats = Stats::from_rows(&self.rows);
        self.last_snapshot_at = Some(snap.taken_at);
        let first_snapshot = self.snapshot_count == 0;
        self.snapshot_count += 1;
        self.evaluate_alerts(first_snapshot);
        self.update_bandwidth();
        self.refresh_display();
    }

    /// Fire alert rules on genuinely new endpoints. The first snapshot is
    /// skipped so startup does not trigger every rule at once.
    fn evaluate_alerts(&mut self, first_snapshot: bool) {
        if first_snapshot || self.alerts.is_empty() {
            return;
        }
        let mut fired: Vec<String> = Vec::new();
        for row in &self.rows {
            if row.change != RowChange::New {
                continue;
            }
            for alert in &self.alerts {
                if alert.enabled && alert.kind.matches_row(row, &self.processes) {
                    let msg = format!(
                        "ALERT  '{}' matched {} {} -> {} ({})",
                        alert.kind.describe(),
                        row.protocol,
                        row.local_display(),
                        row.remote_display(),
                        row.process_display(),
                    );
                    fired.push(msg);
                }
            }
        }
        for msg in &fired {
            self.log_event(msg.clone());
        }
        self.alert_pending.extend(fired);
        if self.alert_pending.len() > 100 {
            let drop = self.alert_pending.len() - 100;
            self.alert_pending.drain(..drop);
        }
    }

    /// Update the bandwidth rolling windows from cumulative EStats counters.
    fn update_bandwidth(&mut self) {
        let current: HashMap<RowId, (u64, u64)> = self
            .rows
            .iter()
            .filter_map(|r| match (r.tx_bytes, r.rx_bytes) {
                (Some(tx), Some(rx)) => Some((r.id.clone(), (tx, rx))),
                _ => None,
            })
            .collect();

        let mut dtx = 0u64;
        let mut drx = 0u64;
        for (id, (tx, rx)) in &current {
            if let Some((ptx, prx)) = self.bw_prev.get(id) {
                dtx += bw_delta(*tx, Some(*ptx));
                drx += bw_delta(*rx, Some(*prx));
            }
        }
        bw_push(&mut self.bw_total, dtx, drx, BW_WINDOW);

        if let Some(id) = &self.bw_selected_id
            && let Some((tx, rx)) = current.get(id)
            && let Some((ptx, prx)) = self.bw_prev.get(id)
        {
            bw_push(
                &mut self.bw_selected,
                bw_delta(*tx, Some(*ptx)),
                bw_delta(*rx, Some(*prx)),
                BW_WINDOW,
            );
        }

        self.bw_prev = current;
    }

    /// Open the bandwidth chart, tracking the selected row when there is one.
    pub fn open_chart(&mut self) {
        self.bw_selected_id = self.current_row().map(|r| r.id.clone());
        self.bw_selected.clear();
        self.bw_view = BwView::Total;
        self.mode = Mode::Chart;
    }

    /// Style for a non-selected row: change highlight wins, then the first
    /// matching coloring rule, then the theme default.
    pub fn row_style(&self, row: &ConnectionRow) -> Style {
        match row.change {
            RowChange::New => Style::default().fg(self.theme.new),
            RowChange::Deleted => Style::default().fg(self.theme.deleted),
            RowChange::Changed => Style::default().fg(self.theme.changed),
            RowChange::Unchanged => {
                for rule in &self.color_rules {
                    if rule.enabled && rule.kind.matches_row(row, &self.processes) {
                        return rule.style;
                    }
                }
                Style::default().fg(self.theme.normal)
            }
        }
    }

    /// Add an alert rule from raw input; returns an error message on parse failure.
    pub fn add_alert_rule(&mut self, expression: &str) -> Result<(), String> {
        let kind = FilterKind::parse(expression)?;
        self.alerts.push(AlertState {
            kind,
            enabled: true,
        });
        Ok(())
    }

    /// Add a coloring rule from `<expr> | fg=cyan bold` style input.
    pub fn add_color_rule(&mut self, input: &str) -> Result<(), String> {
        let (expr, style_part) = match input.split_once('|') {
            Some((e, s)) => (e.trim(), s.trim()),
            None => (input.trim(), ""),
        };
        let kind = FilterKind::parse(expr)?;
        let mut style = Style::default();
        let mut raw = crate::config::ColorRuleSerde {
            expression: kind.describe(),
            ..Default::default()
        };
        for token in style_part.split_whitespace() {
            let token = token.trim();
            if let Some(name) = token.strip_prefix("fg=") {
                let color = parse_color(name).ok_or_else(|| format!("unknown color '{name}'"))?;
                style = style.fg(color);
                raw.fg = Some(name.to_ascii_lowercase());
            } else if let Some(name) = token.strip_prefix("bg=") {
                let color = parse_color(name).ok_or_else(|| format!("unknown color '{name}'"))?;
                style = style.bg(color);
                raw.bg = Some(name.to_ascii_lowercase());
            } else if token == "bold" {
                style = style.add_modifier(ratatui::style::Modifier::BOLD);
                raw.bold = true;
            } else if token == "underline" {
                style = style.add_modifier(ratatui::style::Modifier::UNDERLINED);
                raw.underline = true;
            } else {
                return Err(format!(
                    "unknown style token '{token}' (expected fg=, bg=, bold, underline)"
                ));
            }
        }
        self.color_rules.push(ColorRule {
            kind,
            enabled: true,
            style,
            raw,
        });
        Ok(())
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
        // Plain navigation resets the range-selection anchor.
        self.select_anchor = self.selected;
    }

    /// Extend the mark from the anchor to the (moved) cursor: Shift+arrows.
    pub fn range_select(&mut self, delta: i64) {
        if self.display.is_empty() {
            return;
        }
        let len = self.display.len() as i64;
        let next = (self.selected as i64 + delta).clamp(0, len - 1) as usize;
        self.selected = next;
        let (lo, hi) = (
            self.select_anchor.min(self.selected),
            self.select_anchor.max(self.selected),
        );
        for idx in lo..=hi {
            if let Some(DisplayNode::Conn(vi)) = self.display.get(idx)
                && let Some(row) = self.visible.get(*vi)
            {
                self.marked.insert(row.id.clone());
            }
        }
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

    /// Columns offered by the sort editor (everything sortable).
    pub fn sortable_columns(&self) -> Vec<ColumnId> {
        self.column_order
            .iter()
            .copied()
            .filter(|c| *c != ColumnId::Mark)
            .collect()
    }

    /// Toggle a column's sort direction; append it to the chain if absent.
    pub fn sort_toggle_column(&mut self, col: ColumnId) {
        if let Some(existing) = self.sort.iter_mut().find(|k| k.col == col) {
            existing.desc = !existing.desc;
        } else if self.sort.len() < 6 {
            self.sort.push(SortKey { col, desc: false });
        }
        self.refresh_display();
    }

    /// Drop a column from the sort chain (keeps at least one key).
    pub fn sort_remove_column(&mut self, col: ColumnId) {
        self.sort.retain(|k| k.col != col);
        if self.sort.is_empty() {
            self.sort = default_sort_chain();
        }
        self.refresh_display();
    }

    /// Move a column's priority inside the sort chain by `delta` slots.
    pub fn sort_move_column(&mut self, col: ColumnId, delta: i32) {
        let Some(pos) = self.sort.iter().position(|k| k.col == col) else {
            return;
        };
        let target = (pos as i32 + delta).clamp(0, self.sort.len() as i32 - 1) as usize;
        let key = self.sort.remove(pos);
        self.sort.insert(target, key);
        self.refresh_display();
    }

    pub fn sort_reset_default(&mut self) {
        self.sort = default_sort_chain();
        self.refresh_display();
    }

    /// Quick filter presets bound to the number keys.
    pub fn apply_preset(&mut self, n: u8) {
        let text = match n {
            1 => "proto=tcp",
            2 => "proto=udp",
            3 => "state=established",
            4 => "state=listen",
            5 => "loopback=true",
            6 => "loopback=false",
            7 => "change=new",
            8 => "",
            _ => return,
        };
        if text.is_empty() {
            self.clear_filter();
            self.push_status("Filter cleared");
            return;
        }
        match FilterKind::parse(text) {
            Ok(f) => {
                self.filter = Some(f);
                self.filter_input.value = text.to_string();
                self.selected = 0;
                self.refresh_display();
                self.push_status(format!("Preset {n}: {text}"));
            }
            Err(e) => self.push_status(e),
        }
    }

    /// Live feedback while typing in the filter prompt: either the number of
    /// rows the current text would keep, or a parse error.
    pub fn filter_feedback(&self) -> Option<Result<usize, String>> {
        if self.mode != Mode::Filtering {
            return None;
        }
        let text = self.filter_input.value.trim();
        if text.is_empty() {
            let base = filter_rows(
                &self.rows,
                &self.toggles,
                self.watch_pid,
                None,
                &self.processes,
            );
            return Some(Ok(base.len()));
        }
        Some(FilterKind::parse(text).map(|f| {
            filter_rows(
                &self.rows,
                &self.toggles,
                self.watch_pid,
                None,
                &self.processes,
            )
            .iter()
            .filter(|r| f.matches_row(r, &self.processes))
            .count()
        }))
    }

    /// Recall an earlier filter (Up in the filter prompt).
    pub fn filter_history_prev(&mut self) {
        if self.filter_history.is_empty() {
            return;
        }
        let idx = match self.filter_history_idx {
            Some(i) if i > 0 => i - 1,
            Some(_) => 0,
            None => self.filter_history.len() - 1,
        };
        self.filter_history_idx = Some(idx);
        self.filter_input.value = self.filter_history[idx].clone();
    }

    /// Walk back towards the newest entry (Down in the filter prompt).
    pub fn filter_history_next(&mut self) {
        let Some(idx) = self.filter_history_idx else {
            return;
        };
        if idx + 1 < self.filter_history.len() {
            self.filter_history_idx = Some(idx + 1);
            self.filter_input.value = self.filter_history[idx + 1].clone();
        } else {
            self.filter_history_idx = None;
            self.filter_input.clear();
        }
    }

    fn remember_filter(&mut self, text: &str) {
        if text.is_empty() {
            return;
        }
        if self.filter_history.last().is_none_or(|last| last != text) {
            self.filter_history.push(text.to_string());
        }
        if self.filter_history.len() > 20 {
            let drop = self.filter_history.len() - 20;
            self.filter_history.drain(..drop);
        }
        self.filter_history_idx = None;
    }

    // -- Filter / search ---------------------------------------------------------

    pub fn apply_filter_input(&mut self) {
        let text = self.filter_input.value.trim().to_string();
        self.filter = if text.is_empty() {
            None
        } else {
            match FilterKind::parse(&text) {
                Ok(f) => {
                    self.remember_filter(&text);
                    Some(f)
                }
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
                    .map(|r| search.matches_row(r, &self.processes))
                    .unwrap_or(false),
                DisplayNode::Group { name, .. } => match &search {
                    FilterKind::Plain(p) => name.to_lowercase().contains(p),
                    FilterKind::Regex(re) => re.is_match(name),
                    // Structured filters apply to rows, not group headers.
                    FilterKind::Expr { .. } => false,
                },
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

    // -- GeoIP -------------------------------------------------------------

    /// Country cell text ("TR 🇹🇷") for a row's remote address.
    pub fn country_for(&self, row: &ConnectionRow) -> String {
        let Some(ip) = row.remote_addr else {
            return String::new();
        };
        let Some(geo) = &self.geo else {
            return String::new();
        };
        let code = geo.lock().ok().and_then(|mut g| g.country_code(ip));
        match code {
            Some(code) => match crate::geoip::flag_emoji(&code) {
                Some(flag) => format!("{code} {flag}"),
                None => code,
            },
            None => String::new(),
        }
    }

    /// Try to enable GeoIP (settings toggle): opens the configured database.
    pub fn geoip_try_enable(&mut self, path: &str) -> bool {
        match crate::geoip::GeoResolver::open(std::path::Path::new(path)) {
            Ok(resolver) => {
                self.geo = Some(std::sync::Mutex::new(resolver));
                self.column_hidden.remove(&ColumnId::Country);
                true
            }
            Err(_) => {
                self.geo = None;
                self.column_hidden.insert(ColumnId::Country);
                false
            }
        }
    }

    pub fn geoip_disable(&mut self) {
        self.geo = None;
        self.column_hidden.insert(ColumnId::Country);
    }

    // -- View profiles -------------------------------------------------------

    /// Apply a saved profile by index.
    pub fn apply_profile(&mut self, idx: usize) {
        let Some(profile) = self.profiles.get(idx).cloned() else {
            return;
        };
        self.toggles.show_tcp = profile.show_tcp;
        self.toggles.show_udp = profile.show_udp;
        self.toggles.show_unconnected = profile.show_unconnected;
        self.toggles.show_loopback = profile.show_loopback;
        self.grouped = profile.grouped;
        self.filter = match &profile.filter {
            Some(text) => FilterKind::parse(text).ok(),
            None => None,
        };
        let mut sort: Vec<SortKey> = profile
            .sort
            .iter()
            .filter_map(|s| ColumnId::from_key(&s.col).map(|col| SortKey { col, desc: s.desc }))
            .collect();
        if sort.is_empty() {
            sort = default_sort_chain();
        }
        self.sort = sort;
        self.selected = 0;
        self.refresh_display();
        self.push_status(format!("Profile applied: {}", profile.name));
    }

    /// Capture the current view (filter, sort, toggles) as a named profile.
    pub fn save_current_profile(&mut self, name: &str) -> Result<(), String> {
        let name = name.trim();
        if name.is_empty() {
            return Err("profile name is empty".to_string());
        }
        if self.profiles.len() >= 10 {
            return Err("profile limit reached (10)".to_string());
        }
        let profile = crate::config::ProfileSerde {
            name: name.to_string(),
            filter: self.filter.as_ref().map(|f| f.describe()),
            sort: self
                .sort
                .iter()
                .map(|k| crate::config::SortKeySerde {
                    col: k.col.key().to_string(),
                    desc: k.desc,
                })
                .collect(),
            show_tcp: self.toggles.show_tcp,
            show_udp: self.toggles.show_udp,
            show_unconnected: self.toggles.show_unconnected,
            show_loopback: self.toggles.show_loopback,
            grouped: self.grouped,
        };
        // Replace an existing profile with the same name.
        self.profiles.retain(|p| p.name != name);
        self.profiles.push(profile);
        Ok(())
    }

    pub fn delete_profile(&mut self, idx: usize) {
        if idx < self.profiles.len() {
            self.profiles.remove(idx);
            self.profile_cursor = self
                .profile_cursor
                .min(self.profiles.len().saturating_sub(1));
        }
    }

    // -- Settings screen -----------------------------------------------------

    /// Number of rows in the settings popup.
    pub fn settings_count(&self) -> usize {
        10
    }

    /// Toggle/cycle the setting under the cursor.
    pub fn settings_activate(&mut self) {
        match self.settings_cursor {
            0 => self.step_interval(false),
            1 => self.toggle_resolve(),
            2 => {
                self.toggles.show_tcp = !self.toggles.show_tcp;
                self.refresh_display();
            }
            3 => {
                self.toggles.show_udp = !self.toggles.show_udp;
                self.refresh_display();
            }
            4 => {
                self.toggles.show_unconnected = !self.toggles.show_unconnected;
                self.refresh_display();
            }
            5 => {
                self.toggles.show_loopback = !self.toggles.show_loopback;
                self.refresh_display();
            }
            6 => self.toggle_grouped(),
            7 => {
                let current = THEMES
                    .iter()
                    .position(|t| t.eq_ignore_ascii_case(&self.theme_name))
                    .unwrap_or(0);
                let next = THEMES[(current + 1) % THEMES.len()];
                self.theme_name = next.to_string();
                self.theme = theme_by_name(next);
            }
            8 => {
                self.estats_enabled = !self.estats_enabled;
                let _ = self
                    .collector_tx
                    .send(CollectorCmd::SetEstats(self.estats_enabled));
            }
            9 => {
                self.geoip_enabled = !self.geoip_enabled;
                if self.geoip_enabled {
                    let path = crate::config::GeoIpConfig::default().path;
                    if !self.geoip_try_enable(&path) {
                        self.push_status(format!("GeoIP database not found: {path}"));
                    }
                } else {
                    self.geoip_disable();
                }
            }
            _ => {}
        }
    }

    /// Adjust the setting under the cursor (+/-).
    pub fn settings_adjust(&mut self, plus: bool) {
        match self.settings_cursor {
            0 => self.step_interval(!plus),
            7 => {
                let current = THEMES
                    .iter()
                    .position(|t| t.eq_ignore_ascii_case(&self.theme_name))
                    .unwrap_or(0);
                let next = if plus {
                    THEMES[(current + 1) % THEMES.len()]
                } else {
                    THEMES[(current + THEMES.len() - 1) % THEMES.len()]
                };
                self.theme_name = next.to_string();
                self.theme = theme_by_name(next);
            }
            _ => self.settings_activate(),
        }
    }

    /// Launch a VirusTotal lookup for the selected row's executable.
    pub fn request_vt(&mut self) {
        let Some(row) = self.current_row() else {
            return;
        };
        let Some(exe) = self.processes.get(&row.pid).and_then(|p| p.exe.clone()) else {
            self.push_status("No executable path known for this endpoint");
            return;
        };

        #[cfg(not(feature = "virustotal"))]
        {
            let _ = exe;
            self.push_status(
                "built without the 'virustotal' feature (rebuild with --features virustotal)",
            );
        }

        #[cfg(feature = "virustotal")]
        {
            if self.vt_api_key.trim().is_empty() {
                self.push_status("set [virustotal] api_key in config.toml to enable lookups");
                return;
            }
            let subject = row.process_display();
            self.vt_state = Some(VtState {
                subject: format!("{subject} — {exe}"),
                loading: true,
                text: None,
                scroll: 0,
            });
            self.mode = Mode::Vt;
            let (sx, rx) = std::sync::mpsc::channel();
            self.vt_rx = Some(rx);
            let key = self.vt_api_key.clone();
            std::thread::spawn(move || {
                let result = crate::vt::sha256_file(std::path::Path::new(&exe))
                    .and_then(|hash| crate::vt::lookup(&key, &hash))
                    .map_err(|e| e.to_string());
                let _ = sx.send(result);
            });
        }
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
    fn build_detail_lines(&mut self, pid: u32) -> Vec<String> {
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
        // Authenticode status (cached; verification touches the file).
        if let Some(exe) = proc.and_then(|p| p.exe.as_deref()) {
            let verdict = match self.signed_cache.get(exe) {
                Some(v) => *v,
                None => {
                    let v = crate::actions::verify_signed(std::path::Path::new(exe));
                    self.signed_cache.insert(exe.to_string(), v);
                    v
                }
            };
            let label = match verdict {
                Some(true) => "yes",
                Some(false) => "no",
                None => "unknown",
            };
            lines.push(format!("Signed:  {label}"));
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
            .map(|r| {
                cols.iter()
                    .map(|c| {
                        if *c == ColumnId::Country {
                            self.country_for(r)
                        } else {
                            cell_text(r, *c, &ctx)
                        }
                    })
                    .collect()
            })
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

    /// Freeze or resume live updates (p).
    pub fn toggle_pause(&mut self) {
        self.paused = !self.paused;
        self.push_status(if self.paused {
            "Refresh paused — press p to resume".to_string()
        } else {
            "Refresh resumed".to_string()
        });
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
        cfg.view.sort = self
            .sort
            .iter()
            .map(|k| crate::config::SortKeySerde {
                col: k.col.key().to_string(),
                desc: k.desc,
            })
            .collect();
        cfg.estats.enabled = self.estats_enabled;
        cfg.geoip.enabled = self.geoip_enabled;
        cfg.profiles = self.profiles.clone();
        cfg.set_column_layout(&self.column_order, &self.column_hidden, &self.column_width);
        cfg.alerts = self
            .alerts
            .iter()
            .map(|a| crate::config::AlertSerde {
                expression: a.kind.describe(),
                enabled: a.enabled,
            })
            .collect();
        cfg.colors = self
            .color_rules
            .iter()
            .map(|c| crate::config::ColorRuleSerde {
                expression: c.kind.describe(),
                enabled: c.enabled,
                ..c.raw.clone()
            })
            .collect();
        if let Err(e) = cfg.save() {
            eprintln!("warning: could not save config: {e}");
        }
    }

    /// Screen-space row index for a mouse click inside the table body.
    /// Layout inside the table area: border, header row, data rows, border.
    pub fn row_at_screen_y(&self, y: u16) -> Option<usize> {
        let area = self.table_area;
        if area.height <= 3 || y < area.y + 2 || y >= area.y + area.height - 1 {
            return None;
        }
        let idx = self.offset + (y - area.y - 2) as usize;
        (idx < self.display.len()).then_some(idx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    pub(crate) fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
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
        let mut r = sample_rows().remove(0);
        r.process_name = Some("Chrome.exe".into());
        assert!(f.matches_row(&r, &HashMap::new()));
        r.process_name = Some("mychrome".into());
        assert!(!f.matches_row(&r, &HashMap::new()));
        assert!(FilterKind::parse("re:[").is_err());
    }

    #[test]
    fn structured_expression_filter_end_to_end() {
        let mut rows = sample_rows();
        rows[0].process_name = Some("chrome.exe".into());
        rows[1].process_name = Some("firefox.exe".into());

        let f = FilterKind::parse("process:chrome and port=443").unwrap();
        let out = filter_rows(&rows, &toggles(), None, Some(&f), &HashMap::new());
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].pid, 100);

        let f = FilterKind::parse("state=established and pid>=200").unwrap();
        let out = filter_rows(&rows, &toggles(), None, Some(&f), &HashMap::new());
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].pid, 200);

        let f = FilterKind::parse("proto=udp or rport=853").unwrap();
        let out = filter_rows(&rows, &toggles(), None, Some(&f), &HashMap::new());
        assert_eq!(out.len(), 2);

        // Free text keeps working for addr:port style searches.
        let f = FilterKind::parse("93.184.216.34:443").unwrap();
        let out = filter_rows(&rows, &toggles(), None, Some(&f), &HashMap::new());
        assert_eq!(out.len(), 1);

        assert!(FilterKind::parse("bogus=1").is_err());
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

    #[test]
    fn presets_filter_and_clear() {
        let mut app = App::new(crate::config::Config::default(), None);
        app.apply_snapshot(synthetic_snapshot_like());

        app.apply_preset(3); // state=established
        assert!(app.filter.is_some());
        assert!(app.visible.iter().all(|r| r.is_established()));

        app.apply_preset(2); // proto=udp
        assert!(app.visible.iter().all(|r| r.protocol == Protocol::Udp));

        app.apply_preset(8); // clear
        assert!(app.filter.is_none());
        assert_eq!(app.visible.len(), 2);
    }

    #[test]
    fn filter_history_navigates() {
        let mut app = App::new(crate::config::Config::default(), None);
        app.filter_input.value = "proto=tcp".into();
        app.apply_filter_input();
        app.filter_input.value = "pid>1".into();
        app.apply_filter_input();

        app.filter_history_prev();
        assert_eq!(app.filter_input.value, "pid>1");
        app.filter_history_prev();
        assert_eq!(app.filter_input.value, "proto=tcp");
        app.filter_history_next();
        assert_eq!(app.filter_input.value, "pid>1");
        app.filter_history_next();
        assert!(app.filter_input.value.is_empty());
    }

    #[test]
    fn sort_editor_operations() {
        let mut app = App::new(crate::config::Config::default(), None);
        app.apply_snapshot(synthetic_snapshot_like());

        app.sort_toggle_column(ColumnId::Pid); // append
        assert!(app.sort.iter().any(|k| k.col == ColumnId::Pid));
        app.sort_toggle_column(ColumnId::Pid); // flip direction
        assert!(app.sort.iter().any(|k| k.col == ColumnId::Pid && k.desc));

        app.sort_move_column(ColumnId::Pid, -1);
        assert_ne!(app.sort.first().map(|k| k.col), Some(ColumnId::Pid));

        app.sort_remove_column(ColumnId::Pid);
        assert!(!app.sort.iter().any(|k| k.col == ColumnId::Pid));

        app.sort_reset_default();
        assert_eq!(app.sort, default_sort_chain());
    }

    /// Two-row snapshot with distinct protocols/states shared by the
    /// stateful tests above.
    pub(crate) fn synthetic_snapshot_like() -> Snapshot {
        Snapshot {
            taken_at: Local::now(),
            rows: vec![
                ConnectionRow::new(
                    Protocol::Tcp,
                    v4(127, 0, 0, 1),
                    5001,
                    Some(v4(93, 184, 216, 34)),
                    Some(443),
                    Some(netstat2::TcpState::Established),
                    42,
                ),
                ConnectionRow::new(Protocol::Udp, v4(0, 0, 0, 0), 5353, None, None, None, 7),
            ],
            processes: HashMap::new(),
            services: HashMap::new(),
        }
    }
}

#[cfg(test)]
mod phase_b_tests {
    use super::tests::{synthetic_snapshot_like, v4};
    use super::*;

    #[test]
    fn bw_delta_baselines_and_resets() {
        // First sighting: establish baseline, no delta.
        assert_eq!(bw_delta(1000, None), 0);
        // Normal growth.
        assert_eq!(bw_delta(1500, Some(1000)), 500);
        // Counter reset: everything since the reset counts.
        assert_eq!(bw_delta(50, Some(1000)), 50);
        assert_eq!(bw_delta(1000, Some(1000)), 0);
    }

    #[test]
    fn bw_window_caps_length() {
        let mut w = std::collections::VecDeque::new();
        for i in 0..BW_WINDOW + 20 {
            bw_push(&mut w, i as u64, 0, BW_WINDOW);
        }
        assert_eq!(w.len(), BW_WINDOW);
        assert_eq!(w.front().copied(), Some((20u64, 0u64)));
    }

    #[test]
    fn color_names_parse() {
        assert_eq!(parse_color("Cyan"), Some(Color::Cyan));
        assert_eq!(parse_color("dark_grey"), Some(Color::DarkGray));
        assert_eq!(parse_color("nope"), None);
    }

    #[test]
    fn rules_add_toggle_and_style_precedence() {
        let mut app = App::new(crate::config::Config::default(), None);
        app.apply_snapshot(synthetic_snapshot_like());

        app.add_alert_rule("proto=udp").unwrap();
        assert!(app.add_alert_rule("bogus=1").is_err());
        assert_eq!(app.alerts.len(), 1);

        app.add_color_rule("rport=443 | fg=cyan bold").unwrap();
        assert!(app.add_color_rule("x | fg=nope").is_err());
        assert_eq!(app.color_rules.len(), 1);

        // Unchanged matching row takes the rule style; changed rows keep
        // their change color; non-matching rows use the theme default.
        let mut udp_row =
            ConnectionRow::new(Protocol::Udp, v4(0, 0, 0, 0), 5353, None, None, None, 7);
        udp_row.change = RowChange::Unchanged;
        app.color_rules[0].kind = FilterKind::parse("proto=udp").unwrap();
        let style = app.row_style(&udp_row);
        assert_eq!(style.fg, Some(Color::Cyan));

        udp_row.change = RowChange::New;
        assert_eq!(app.row_style(&udp_row).fg, Some(app.theme.new));

        let mut tcp_row = ConnectionRow::new(
            Protocol::Tcp,
            v4(127, 0, 0, 1),
            5001,
            Some(v4(93, 184, 216, 34)),
            Some(443),
            Some(netstat2::TcpState::Established),
            42,
        );
        tcp_row.change = RowChange::Unchanged;
        assert_eq!(app.row_style(&tcp_row).fg, Some(app.theme.normal));
    }

    #[test]
    fn alerts_fire_on_new_rows_only() {
        let mut app = App::new(crate::config::Config::default(), None);
        app.add_alert_rule("proto=udp").unwrap();

        // First snapshot: everything New, but alerts must stay silent.
        app.apply_snapshot(synthetic_snapshot_like());
        assert!(app.alert_pending.is_empty());

        // Second snapshot with an extra UDP endpoint triggers the rule.
        let mut snap = synthetic_snapshot_like();
        snap.rows.push(ConnectionRow::new(
            Protocol::Udp,
            v4(127, 0, 0, 1),
            9999,
            None,
            None,
            None,
            9,
        ));
        app.apply_snapshot(snap);
        assert_eq!(app.alert_pending.len(), 1);
        assert!(app.alert_pending[0].contains("ALERT"));

        // A repeat of the same snapshot adds nothing new.
        let snap2 = synthetic_snapshot_like();
        app.apply_snapshot(snap2);
        assert_eq!(app.alert_pending.len(), 1);
    }
}

#[cfg(test)]
mod phase_c_tests {
    use super::tests::{synthetic_snapshot_like, v4};
    use super::*;

    #[test]
    fn country_cell_without_database_is_blank() {
        // Default config has no GeoLite2 file around -> soft failure.
        let mut app = App::new(crate::config::Config::default(), None);
        app.apply_snapshot(synthetic_snapshot_like());
        let row = app.rows.first().unwrap().clone();
        assert!(app.geo.is_none());
        assert_eq!(app.country_for(&row), "");
        // The Country column is auto-hidden in that case.
        assert!(app.column_hidden.contains(&ColumnId::Country));
    }

    #[test]
    fn profiles_save_apply_delete() {
        let mut app = App::new(crate::config::Config::default(), None);
        app.apply_snapshot(synthetic_snapshot_like());

        // Configure a distinctive view, save it, wreck the view, re-apply.
        app.filter = Some(FilterKind::parse("proto=udp").unwrap());
        app.toggles.show_tcp = false;
        app.grouped = true;
        app.save_current_profile("UDP only").unwrap();
        assert_eq!(app.profiles.len(), 1);
        assert!(app.save_current_profile("  ").is_err());

        app.filter = None;
        app.toggles.show_tcp = true;
        app.grouped = false;

        app.apply_profile(0);
        assert!(app.filter.is_some());
        assert!(!app.toggles.show_tcp);
        assert!(app.grouped);

        // Same-name save replaces instead of duplicating.
        app.toggles.show_tcp = true;
        app.save_current_profile("UDP only").unwrap();
        assert_eq!(app.profiles.len(), 1);
        assert!(app.profiles[0].show_tcp);

        app.delete_profile(0);
        assert!(app.profiles.is_empty());
    }

    #[test]
    fn settings_toggles_flip_state() {
        let mut app = App::new(crate::config::Config::default(), None);
        app.apply_snapshot(synthetic_snapshot_like());

        // Cursor 2 == "Show TCP"
        app.settings_cursor = 2;
        let before = app.toggles.show_tcp;
        app.settings_activate();
        assert_eq!(app.toggles.show_tcp, !before);

        // Cursor 7 == theme cycling
        app.settings_cursor = 7;
        let theme_before = app.theme_name.clone();
        app.settings_activate();
        assert_ne!(app.theme_name, theme_before);

        // Cursor 9 == GeoIP toggle (no database -> resolver stays None)
        app.settings_cursor = 9;
        app.settings_activate();
        assert!(!app.geoip_enabled);
        assert!(app.column_hidden.contains(&ColumnId::Country));
    }

    #[test]
    fn country_flag_helper() {
        // Country display shape once a resolver exists: "XX <flag>".
        let code = "tr".to_ascii_uppercase();
        let flag = crate::geoip::flag_emoji(&code).unwrap();
        assert_eq!(format!("{code} {flag}"), "TR \u{1F1F9}\u{1F1F7}");
        let _ = v4(127, 0, 0, 1);
    }
}

#[cfg(test)]
mod phase_d_tests {
    use super::tests::{synthetic_snapshot_like, v4};
    use super::*;
    use crate::etw::EtwEvent;
    use std::net::SocketAddr;

    fn connect_event() -> EtwEvent {
        EtwEvent::Connect {
            v6: false,
            pid: 42,
            local: SocketAddr::new(v4(127, 0, 0, 1), 5001),
            remote: SocketAddr::new(v4(93, 184, 216, 34), 443),
        }
    }

    #[test]
    fn etw_timestamps_override_first_seen() {
        let mut app = App::new(crate::config::Config::default(), None);
        // A connect arrives before the row shows up in any snapshot.
        app.handle_etw_event(connect_event());

        let before = Local::now() - chrono::Duration::seconds(5);
        let mut snap = synthetic_snapshot_like();
        if let Some(row) = snap.rows.iter_mut().find(|r| r.local_port == 5001) {
            // Simulate the ETW connect having happened 5 s ago.
            let id = row.id.clone();
            app.etw_connects.insert(id, before);
        }
        app.apply_snapshot(snap);
        let row = app.rows.iter().find(|r| r.local_port == 5001).unwrap();
        assert!(row.first_seen.is_some());
        assert!(crate::model::age_seconds(row.first_seen) >= 5);
    }

    #[test]
    fn transient_etw_connections_are_logged() {
        let mut app = App::new(crate::config::Config::default(), None);
        app.handle_etw_event(connect_event());
        // Disconnect without any snapshot in between: transient entry.
        let EtwEvent::Connect {
            pid, local, remote, ..
        } = connect_event()
        else {
            unreachable!()
        };
        app.handle_etw_event(EtwEvent::Disconnect {
            v6: false,
            pid,
            local,
            remote,
        });
        assert!(
            app.event_log
                .iter()
                .any(|e| e.message.contains("transient"))
        );
    }

    #[test]
    fn pause_freezes_and_resume_applies_snapshots() {
        let mut app = App::new(crate::config::Config::default(), None);

        app.toggle_pause();
        assert!(app.paused);
        app.apply_snapshot(synthetic_snapshot_like());
        assert!(
            app.rows.is_empty(),
            "snapshots must be dropped while paused"
        );
        assert_eq!(app.snapshot_count, 0);

        app.toggle_pause();
        assert!(!app.paused);
        app.apply_snapshot(synthetic_snapshot_like());
        assert_eq!(app.rows.len(), 2);
        assert_eq!(app.snapshot_count, 1);
        assert_eq!(app.stats.total, 2);
    }

    #[test]
    fn signature_verification_runs_on_real_binary() {
        // Tolerant: value depends on the environment, but it must not panic
        // and must answer for an existing file.
        let exe = std::env::current_exe().unwrap();
        let verdict = crate::actions::verify_signed(&exe);
        assert!(verdict.is_some());
        // A nonexistent path reports unsigned rather than panicking.
        assert_eq!(
            crate::actions::verify_signed(std::path::Path::new("Z:/no/such/file.exe")),
            Some(false)
        );
    }
}
