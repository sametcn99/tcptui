//! Platform socket enumeration and optional per-connection traffic counters.

use anyhow::Result;

use crate::model::ConnectionRow;
#[cfg(windows)]
use crate::model::Protocol;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(windows)]
mod windows;

#[cfg(target_os = "linux")]
pub use linux::TrafficReader;
#[cfg(target_os = "linux")]
pub(crate) use linux::destroy_connection;
#[cfg(target_os = "macos")]
pub use macos::TrafficReader;
#[cfg(windows)]
pub use windows::{
    MIB_TCP_STATE_DELETE_TCB_U32, TrafficReader, ensure_wsa, init_wsa, make_v4_tcp_row,
    tcp_state_to_u32,
};

pub const TRAFFIC_SOURCE: &str = if cfg!(windows) {
    "EStats"
} else if cfg!(target_os = "linux") {
    "TCP_INFO"
} else {
    "nettop"
};

pub fn initialize() -> Result<()> {
    #[cfg(windows)]
    ensure_wsa()?;
    Ok(())
}

/// Enumerate visible endpoints without optional traffic statistics.
pub fn collect_sockets() -> Result<Vec<ConnectionRow>> {
    #[cfg(target_os = "linux")]
    return linux::collect(false);
    #[cfg(target_os = "macos")]
    return macos::collect();
    #[cfg(windows)]
    collect_sockets_with_netstat()
}

#[cfg(windows)]
/// Enumerate every TCP and UDP endpoint (IPv4 + IPv6) with owning PIDs.
fn collect_sockets_with_netstat() -> Result<Vec<ConnectionRow>> {
    let af = netstat2::AddressFamilyFlags::IPV4 | netstat2::AddressFamilyFlags::IPV6;
    let proto = netstat2::ProtocolFlags::TCP | netstat2::ProtocolFlags::UDP;

    let sockets = netstat2::get_sockets_info(af, proto)
        .map_err(|e| anyhow::anyhow!("failed to enumerate sockets: {e}"))?;

    let mut rows = Vec::with_capacity(sockets.len());
    for si in sockets {
        // `associated_pids` is a vec because some platforms report several
        // owners per socket; on Windows it always holds exactly one entry.
        let pid = si
            .associated_pids
            .into_iter()
            .filter(|pid| *pid != 0)
            .min()
            .unwrap_or(0);
        match si.protocol_socket_info {
            netstat2::ProtocolSocketInfo::Tcp(t) => {
                let has_remote = t.remote_port != 0 && !t.remote_addr.is_unspecified();
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
