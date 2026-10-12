//! Socket enumeration (via `netstat2`) and TCP EStats byte counters.
//!
//! All Windows-specific `unsafe` code lives in this module and in
//! `dns.rs` / `services.rs` / `actions.rs`, kept in small reviewed blocks.

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

/// Enumerate every TCP and UDP endpoint (IPv4 + IPv6) with owning PIDs.
pub fn collect_sockets() -> Result<Vec<ConnectionRow>> {
    let af = netstat2::AddressFamilyFlags::IPV4 | netstat2::AddressFamilyFlags::IPV6;
    let proto = netstat2::ProtocolFlags::TCP | netstat2::ProtocolFlags::UDP;

    let sockets = netstat2::get_sockets_info(af, proto)
        .map_err(|e| anyhow::anyhow!("failed to enumerate sockets: {e}"))?;

    let mut rows = Vec::with_capacity(sockets.len());
    for si in sockets {
        // `associated_pids` is a vec because some platforms report several
        // owners per socket; on Windows it always holds exactly one entry.
        let pid = si.associated_pids.first().copied().unwrap_or(0);
        match si.protocol_socket_info {
            netstat2::ProtocolSocketInfo::Tcp(t) => {
                let has_remote = t.remote_port != 0
                    && !crate::model::is_ipv4_any(&t.remote_addr)
                    && t.remote_addr.to_string() != "::";
                let (raddr, rport) = if has_remote {
                    (Some(t.remote_addr), Some(t.remote_port))
                } else {
                    (None, None)
                };
                rows.push(ConnectionRow::new(
                    Protocol::Tcp,
                    t.local_addr,
                    t.local_port,
                    raddr,
                    rport,
                    Some(t.state),
                    pid,
                ));
            }
            netstat2::ProtocolSocketInfo::Udp(u) => {
                rows.push(ConnectionRow::new(
                    Protocol::Udp,
                    u.local_addr,
                    u.local_port,
                    None,
                    None,
                    None,
                    pid,
                ));
            }
        }
    }
    Ok(rows)
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
    let lp = u32::from_ne_bytes([0, 0, (local_port >> 8) as u8, local_port as u8]);
    let rp = u32::from_ne_bytes([0, 0, (remote_port >> 8) as u8, remote_port as u8]);
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
/// connection. IPv4 only (the Windows API has no IPv6 equivalent).
pub struct EStatsReader {
    enabled: bool,
    tracking: HashSet<RowId>,
    /// Set once if the API is not available so we stop paying for attempts.
    unavailable: bool,
}

impl EStatsReader {
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

    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Fill `tx_bytes`/`rx_bytes` on IPv4 TCP rows that have a remote peer.
    pub fn poll(&mut self, rows: &mut [ConnectionRow]) {
        if !self.enabled || self.unavailable {
            return;
        }
        for row in rows.iter_mut() {
            if row.protocol != Protocol::Tcp || row.remote_addr.is_none() {
                continue;
            }
            let (IpAddr::V4(l4), IpAddr::V4(r4)) = (row.local_addr, row.remote_addr.unwrap())
            else {
                continue; // IPv6 not supported by this API
            };
            let (Some(rp), Some(lport)) = (row.remote_port, Some(row.local_port)) else {
                continue;
            };
            let id = row.id.clone();
            let wrow = make_v4_tcp_row(
                l4,
                lport,
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
                    // Access denied or unsupported platform: give up globally.
                    self.unavailable = true;
                    return;
                }
                self.tracking.insert(id);
            }

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
                    None,
                    0,
                    None,
                    0,
                    Some(rod_bytes),
                    0,
                )
            };
            if rc == 0 {
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
