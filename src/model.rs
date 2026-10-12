//! Core data model: connection rows, snapshot diffing and statistics.
//!
//! This module is deliberately free of any terminal or Windows API
//! dependencies so that the diff/statistics logic can be unit tested.

use std::collections::HashMap;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

/// Transport protocol of an endpoint.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, PartialOrd, Ord)]
pub enum Protocol {
    Tcp,
    Udp,
}

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Protocol::Tcp => "TCP",
            Protocol::Udp => "UDP",
        })
    }
}

/// Stable identity of an endpoint across snapshots.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct RowId {
    pub protocol: Protocol,
    pub local: SocketAddr,
    pub remote: Option<SocketAddr>,
    pub pid: u32,
}

/// How a row changed relative to the previous snapshot.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RowChange {
    Unchanged,
    New,
    Changed,
    /// Present in the previous snapshot but gone in the current one.
    /// Kept visible (in red) for one refresh cycle.
    Deleted,
}

/// A single endpoint row, enriched with process/service info.
#[derive(Clone, Debug)]
pub struct ConnectionRow {
    pub id: RowId,
    pub protocol: Protocol,
    pub pid: u32,
    pub local_addr: IpAddr,
    pub local_port: u16,
    pub remote_addr: Option<IpAddr>,
    pub remote_port: Option<u16>,
    /// TCP state; `None` for UDP endpoints.
    pub state: Option<netstat2::TcpState>,
    pub process_name: Option<String>,
    pub service_name: Option<String>,
    /// Cumulative EStats byte counters, when collection is enabled.
    pub tx_bytes: Option<u64>,
    pub rx_bytes: Option<u64>,
    pub change: RowChange,
}

impl ConnectionRow {
    pub fn new(
        protocol: Protocol,
        local_addr: IpAddr,
        local_port: u16,
        remote_addr: Option<IpAddr>,
        remote_port: Option<u16>,
        state: Option<netstat2::TcpState>,
        pid: u32,
    ) -> Self {
        let local = SocketAddr::new(local_addr, local_port);
        let remote = match (remote_addr, remote_port) {
            (Some(a), Some(p)) => Some(SocketAddr::new(a, p)),
            _ => None,
        };
        Self {
            id: RowId {
                protocol,
                local,
                remote,
                pid,
            },
            protocol,
            pid,
            local_addr,
            local_port,
            remote_addr,
            remote_port,
            state,
            process_name: None,
            service_name: None,
            tx_bytes: None,
            rx_bytes: None,
            change: RowChange::New,
        }
    }

    /// A connected TCP endpoint (has a remote peer).
    pub fn is_connected_tcp(&self) -> bool {
        self.protocol == Protocol::Tcp && self.remote_addr.is_some()
    }

    pub fn is_established(&self) -> bool {
        matches!(self.state, Some(netstat2::TcpState::Established))
    }

    pub fn is_loopback(&self) -> bool {
        let local_loop = matches!(
            self.local_addr,
            IpAddr::V4(ip) if ip.is_loopback()
        ) || matches!(self.local_addr, IpAddr::V6(ip) if ip.is_loopback());
        let remote_loop = self.remote_addr.is_none_or(|a| match a {
            IpAddr::V4(ip) => ip.is_loopback(),
            IpAddr::V6(ip) => ip.is_loopback(),
        });
        local_loop || remote_loop
    }

    pub fn is_unconnected(&self) -> bool {
        match self.protocol {
            Protocol::Udp => true,
            Protocol::Tcp => self.remote_addr.is_none(),
        }
    }

    /// Remote address as "ip:port" or "*:*" when there is no peer.
    pub fn remote_display(&self) -> String {
        match (self.remote_addr, self.remote_port) {
            (Some(a), Some(p)) => format!("{a}:{p}"),
            _ => "*:*".to_string(),
        }
    }

    pub fn local_display(&self) -> String {
        format!("{}:{}", self.local_addr, self.local_port)
    }

    pub fn process_display(&self) -> String {
        self.process_name
            .clone()
            .unwrap_or_else(|| "<unknown>".to_string())
    }
}

/// Process metadata resolved from a PID.
#[derive(Clone, Debug)]
pub struct ProcessInfo {
    pub pid: u32,
    pub name: String,
    pub exe: Option<String>,
    pub cmd: Option<String>,
    pub cpu: f32,
    pub mem: u64,
}

/// A full snapshot taken by the collector thread.
#[derive(Clone, Debug)]
pub struct Snapshot {
    pub taken_at: chrono::DateTime<chrono::Local>,
    pub rows: Vec<ConnectionRow>,
    pub processes: HashMap<u32, ProcessInfo>,
    /// PID -> (service name, display name) list
    pub services: HashMap<u32, Vec<(String, String)>>,
}

/// Aggregated endpoint statistics for the status bar and stats popup.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct Stats {
    pub total: usize,
    pub tcp: usize,
    pub udp: usize,
    pub established: usize,
    pub listening: usize,
    pub time_wait: usize,
    pub close_wait: usize,
}

impl Stats {
    pub fn from_rows(rows: &[ConnectionRow]) -> Self {
        let mut s = Self {
            total: rows.len(),
            ..Self::default()
        };
        for r in rows {
            match r.protocol {
                Protocol::Tcp => {
                    s.tcp += 1;
                    match r.state {
                        Some(netstat2::TcpState::Established) => s.established += 1,
                        Some(netstat2::TcpState::Listen) => s.listening += 1,
                        Some(netstat2::TcpState::TimeWait) => s.time_wait += 1,
                        Some(netstat2::TcpState::CloseWait) => s.close_wait += 1,
                        _ => {}
                    }
                }
                Protocol::Udp => s.udp += 1,
            }
        }
        s
    }
}

/// Merge a fresh snapshot into the previous row list, computing per-row
/// change flags the way TCPView does:
/// - new endpoints are flagged [`RowChange::New`] (shown in green),
/// - endpoints with a changed state are flagged [`RowChange::Changed`] (yellow),
/// - endpoints that disappeared are kept for one cycle as [`RowChange::Deleted`] (red).
pub fn merge_snapshots(prev: &[ConnectionRow], next: Vec<ConnectionRow>) -> Vec<ConnectionRow> {
    let mut prev_map: HashMap<RowId, &ConnectionRow> = HashMap::with_capacity(prev.len());
    for r in prev {
        if r.change != RowChange::Deleted {
            prev_map.insert(r.id.clone(), r);
        }
    }

    let mut next_ids: HashMap<RowId, ()> = HashMap::with_capacity(next.len());
    let mut merged: Vec<ConnectionRow> = Vec::with_capacity(next.len() + 8);
    for mut row in next {
        next_ids.insert(row.id.clone(), ());
        row.change = match prev_map.get(&row.id) {
            None => RowChange::New,
            Some(old) => {
                if old.state != row.state || old.remote_port != row.remote_port {
                    RowChange::Changed
                } else {
                    RowChange::Unchanged
                }
            }
        };
        merged.push(row);
    }

    // Carry over rows that disappeared, keeping them visible one last cycle.
    for old in prev {
        if old.change != RowChange::Deleted && !next_ids.contains_key(&old.id) {
            let mut ghost = old.clone();
            ghost.change = RowChange::Deleted;
            merged.push(ghost);
        }
    }

    merged
}

/// Format a byte count for humans (e.g. `1.5 MB`).
pub fn format_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    if bytes < 1024 {
        return format!("{bytes} B");
    }
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    format!("{value:.1} {}", UNITS[unit])
}

/// Local IPv4 "any" address used by listening sockets.
pub fn is_ipv4_any(ip: &IpAddr) -> bool {
    matches!(ip, IpAddr::V4(v4) if *v4 == Ipv4Addr::UNSPECIFIED)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv6Addr;

    fn row(
        protocol: Protocol,
        lport: u16,
        rport: Option<u16>,
        state: Option<netstat2::TcpState>,
    ) -> ConnectionRow {
        let remote = rport.map(|_p| IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)));
        ConnectionRow::new(
            protocol,
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            lport,
            remote,
            rport,
            state,
            42,
        )
    }

    #[test]
    fn merge_flags_new_changed_and_deleted() {
        let a = row(
            Protocol::Tcp,
            100,
            Some(443),
            Some(netstat2::TcpState::Established),
        );
        let b = row(Protocol::Tcp, 200, None, Some(netstat2::TcpState::Listen));

        // First snapshot: everything is new.
        let first = merge_snapshots(&[], vec![a.clone(), b.clone()]);
        assert_eq!(first[0].change, RowChange::New);
        assert_eq!(first[1].change, RowChange::New);

        // Second snapshot: `a` changed state, `b` disappeared, `c` is new.
        let mut a2 = a.clone();
        a2.state = Some(netstat2::TcpState::CloseWait);
        let c = row(Protocol::Udp, 300, None, None);
        let second = merge_snapshots(&first, vec![a2.clone(), c.clone()]);
        let by_port = |p: u16| second.iter().find(|r| r.local_port == p).unwrap();
        assert_eq!(by_port(100).change, RowChange::Changed);
        assert_eq!(by_port(200).change, RowChange::Deleted);
        assert_eq!(by_port(300).change, RowChange::New);

        // Third snapshot: the ghost of `b` is gone for good.
        let third = merge_snapshots(&second, vec![a2, c]);
        assert!(third.iter().all(|r| r.local_port != 200));
    }

    #[test]
    fn stats_count_by_protocol_and_state() {
        let rows = vec![
            row(
                Protocol::Tcp,
                1,
                Some(80),
                Some(netstat2::TcpState::Established),
            ),
            row(
                Protocol::Tcp,
                2,
                Some(81),
                Some(netstat2::TcpState::Established),
            ),
            row(Protocol::Tcp, 3, None, Some(netstat2::TcpState::Listen)),
            row(
                Protocol::Tcp,
                4,
                Some(82),
                Some(netstat2::TcpState::TimeWait),
            ),
            row(Protocol::Udp, 5, None, None),
        ];
        let s = Stats::from_rows(&rows);
        assert_eq!(s.total, 5);
        assert_eq!(s.tcp, 4);
        assert_eq!(s.udp, 1);
        assert_eq!(s.established, 2);
        assert_eq!(s.listening, 1);
        assert_eq!(s.time_wait, 1);
    }

    #[test]
    fn loopback_detection_covers_both_families() {
        let v4 = row(
            Protocol::Tcp,
            1,
            Some(80),
            Some(netstat2::TcpState::Established),
        );
        assert!(v4.is_loopback());

        let mut v6 = row(Protocol::Tcp, 1, None, Some(netstat2::TcpState::Listen));
        v6.local_addr = IpAddr::V6(Ipv6Addr::LOCALHOST);
        v6.id.local = SocketAddr::new(v6.local_addr, 1);
        assert!(v6.is_loopback());

        let mut ext = row(
            Protocol::Tcp,
            2,
            Some(80),
            Some(netstat2::TcpState::Established),
        );
        ext.local_addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5));
        ext.id.local = SocketAddr::new(ext.local_addr, 2);
        assert!(!ext.is_loopback());
    }

    #[test]
    fn formats_bytes_at_boundaries() {
        assert_eq!(format_bytes(0), "0 B");
        assert_eq!(format_bytes(512), "512 B");
        assert_eq!(format_bytes(2048), "2.0 KB");
        assert_eq!(format_bytes(5 * 1024 * 1024), "5.0 MB");
    }
}
