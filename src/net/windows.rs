//! Windows IPv4 TCP EStats counters and IP Helper types.
//!
use std::collections::HashSet;
use std::net::IpAddr;

use anyhow::Result;
use windows::Win32::NetworkManagement::IpHelper::{
    GetPerTcpConnectionEStats, MIB_TCP_STATE_DELETE_TCB, MIB_TCPROW_LH, SetPerTcpConnectionEStats,
    TCP_ESTATS_DATA_ROD_v0, TCP_ESTATS_DATA_RW_v0, TcpConnectionEstatsData,
};
use windows::Win32::Networking::WinSock::{WSADATA, WSAStartup};

use crate::model::{ConnectionRow, Protocol, RowId};

/// Call `WSAStartup` once per process; required for `GetNameInfoW`.
pub fn init_wsa() -> Result<()> {
    let mut data = WSADATA::default();
    // 0x0202 is MAKEWORD(2, 2).
    let rc = unsafe { WSAStartup(0x0202, &mut data) };
    if rc != 0 {
        anyhow::bail!("WSAStartup failed with error {rc}");
    }
    Ok(())
}

/// Build the IPv4 `MIB_TCPROW_LH` Windows expects. Address and port fields
/// are stored in network byte order, which on a little-endian host means the
/// raw bytes in memory are already `[a, b, c, d]` / `[hi, lo]`.
pub fn make_v4_tcp_row(
    local: std::net::Ipv4Addr,
    local_port: u16,
    remote: std::net::Ipv4Addr,
    remote_port: u16,
    state: u32,
) -> MIB_TCPROW_LH {
    let la = u32::from_ne_bytes(local.octets());
    let ra = u32::from_ne_bytes(remote.octets());
    let lp = u32::from(local_port.to_be());
    let rp = u32::from(remote_port.to_be());
    let mut row = MIB_TCPROW_LH::default();
    row.Anonymous.dwState = state;
    row.dwLocalAddr = la;
    row.dwLocalPort = lp;
    row.dwRemoteAddr = ra;
    row.dwRemotePort = rp;
    row
}

/// State constant used to abort a TCP connection (same trick TCPView uses).
pub const MIB_TCP_STATE_DELETE_TCB_U32: u32 = MIB_TCP_STATE_DELETE_TCB.0 as u32;

/// Reads per-connection `DataBytesIn`/`DataBytesOut` counters via
/// `GetPerTcpConnectionEStats`, enabling collection on first sight of a
/// connection. This backend currently collects IPv4 counters.
pub struct TrafficReader {
    enabled: bool,
    tracking: HashSet<RowId>,
    /// Set once if the API is not available so we stop paying for attempts.
    unavailable: bool,
}

impl TrafficReader {
    pub fn new(enabled: bool) -> Self {
        Self {
            enabled,
            tracking: HashSet::new(),
            unavailable: false,
        }
    }

    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
        if !enabled {
            self.tracking.clear();
        }
    }

    pub fn collect(&mut self) -> Result<Vec<ConnectionRow>> {
        let mut rows = super::collect_sockets_with_netstat()?;
        self.poll(&mut rows);
        Ok(rows)
    }

    /// Fill `tx_bytes`/`rx_bytes` on IPv4 TCP rows that have a remote peer.
    pub fn poll(&mut self, rows: &mut [ConnectionRow]) {
        if !self.enabled || self.unavailable {
            return;
        }
        let current: HashSet<_> = rows.iter().map(|row| &row.id).collect();
        self.tracking.retain(|id| current.contains(id));
        for row in rows.iter_mut() {
            if row.protocol != Protocol::Tcp || !row.is_established() {
                continue;
            }
            let (IpAddr::V4(l4), Some(IpAddr::V4(r4))) = (row.local_addr, row.remote_addr) else {
                continue; // Windows backend currently collects IPv4 EStats.
            };
            let Some(rp) = row.remote_port else {
                continue;
            };
            let id = row.id.clone();
            let wrow = make_v4_tcp_row(
                l4,
                row.local_port,
                r4,
                rp,
                row.state
                    .map(tcp_state_to_u32)
                    .unwrap_or(MIB_TCP_STATE_DELETE_TCB_U32),
            );

            if !self.tracking.contains(&id) {
                let mut rw = TCP_ESTATS_DATA_RW_v0 {
                    EnableCollection: true,
                };
                let rw_bytes = unsafe {
                    std::slice::from_raw_parts_mut(
                        &mut rw as *mut _ as *mut u8,
                        std::mem::size_of::<TCP_ESTATS_DATA_RW_v0>(),
                    )
                };
                let rc = unsafe {
                    SetPerTcpConnectionEStats(&wrow, TcpConnectionEstatsData, rw_bytes, 0, 0)
                };
                if rc != 0 {
                    // A vanished endpoint only invalidates its own counters.
                    if rc == 5 || rc == 50 {
                        self.unavailable = true;
                        return;
                    }
                    continue;
                }
                self.tracking.insert(id);
            }

            let mut rw = TCP_ESTATS_DATA_RW_v0::default();
            let rw_bytes = unsafe {
                std::slice::from_raw_parts_mut(
                    (&raw mut rw).cast::<u8>(),
                    std::mem::size_of::<TCP_ESTATS_DATA_RW_v0>(),
                )
            };
            let mut rod = TCP_ESTATS_DATA_ROD_v0::default();
            let rod_bytes = unsafe {
                std::slice::from_raw_parts_mut(
                    &mut rod as *mut _ as *mut u8,
                    std::mem::size_of::<TCP_ESTATS_DATA_ROD_v0>(),
                )
            };
            let rc = unsafe {
                GetPerTcpConnectionEStats(
                    &wrow,
                    TcpConnectionEstatsData,
                    Some(rw_bytes),
                    0,
                    None,
                    0,
                    Some(rod_bytes),
                    0,
                )
            };
            if rc == 0 && rw.EnableCollection {
                row.tx_bytes = Some(rod.DataBytesOut);
                row.rx_bytes = Some(rod.DataBytesIn);
            }
        }
    }
}

/// Map our TCP state enum to the MIB numeric value.
pub fn tcp_state_to_u32(state: netstat2::TcpState) -> u32 {
    use netstat2::TcpState::*;
    match state {
        Closed => 1,
        Listen => 2,
        SynSent => 3,
        SynReceived => 4,
        Established => 5,
        FinWait1 => 6,
        FinWait2 => 7,
        CloseWait => 8,
        Closing => 9,
        LastAck => 10,
        TimeWait => 11,
        DeleteTcb => 12,
        Unknown => 0,
    }
}

/// Ensure WSA is initialized (idempotent, thread-safe).
pub fn ensure_wsa() -> Result<()> {
    // `anyhow::Error` is not `Clone`, so persist the message instead.
    static ERR: std::sync::OnceLock<Option<String>> = std::sync::OnceLock::new();
    match ERR.get_or_init(|| init_wsa().err().map(|e| e.to_string())) {
        Some(msg) => Err(anyhow::anyhow!("failed to initialize Winsock: {msg}")),
        None => Ok(()),
    }
}
