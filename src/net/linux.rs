//! Linux inet_diag dumps, socket ownership and exact-identity TCP teardown.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::net::{IpAddr, SocketAddr, SocketAddrV6};
use std::os::fd::AsRawFd;

use anyhow::{Context, Result, bail, ensure};
use netlink_packet_core::{
    NLM_F_ACK, NLM_F_DUMP, NLM_F_DUMP_INTR, NLM_F_REQUEST, NetlinkHeader, NetlinkMessage,
    NetlinkPayload,
};
use netlink_packet_sock_diag::{
    SockDiagMessage,
    constants::*,
    inet::{ExtensionFlags, InetRequest, InetResponse, SocketId, StateFlags, nlas::Nla},
};
use netlink_sys::{Socket, SocketAddr as NetlinkAddr, protocols::NETLINK_SOCK_DIAG};
use netstat2::TcpState;

use crate::model::{ConnectionRow, Protocol};

pub struct TrafficReader {
    enabled: bool,
}

impl TrafficReader {
    pub fn new(enabled: bool) -> Self {
        Self { enabled }
    }

    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    pub fn collect(&mut self) -> Result<Vec<ConnectionRow>> {
        collect(self.enabled)
    }
}

fn open_diag() -> std::io::Result<Socket> {
    let mut socket = Socket::new(NETLINK_SOCK_DIAG)?;
    socket.bind_auto()?;
    socket.connect(&NetlinkAddr::new(0, 0))?;
    let timeout = libc::timeval {
        tv_sec: 2,
        tv_usec: 0,
    };
    // SAFETY: the option value points to a fully initialized timeval.
    if unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            (&raw const timeout).cast(),
            std::mem::size_of_val(&timeout) as libc::socklen_t,
        )
    } == -1
    {
        return Err(std::io::Error::last_os_error());
    }
    Ok(socket)
}

fn request(
    socket: &Socket,
    request: InetRequest,
    sequence: u32,
    destroy: bool,
    mut response: impl FnMut(InetResponse),
) -> Result<()> {
    let mut header = NetlinkHeader::default();
    header.sequence_number = sequence;
    header.flags = NLM_F_REQUEST | if destroy { NLM_F_ACK } else { NLM_F_DUMP };
    let mut message = NetlinkMessage::new(header, SockDiagMessage::InetRequest(request).into());
    message.finalize();
    if destroy {
        message.header.message_type = SOCK_DESTROY;
    }
    let mut bytes = vec![0; message.buffer_len()];
    message.serialize(&mut bytes);
    ensure!(
        socket.send(&bytes, 0)? == bytes.len(),
        "short inet_diag request"
    );

    loop {
        let (datagram, sender) = socket
            .recv_from_full()
            .context("receiving inet_diag reply")?;
        ensure!(
            sender.port_number() == 0 && !datagram.is_empty(),
            "invalid inet_diag sender or reply"
        );
        let mut remaining = datagram.as_slice();
        while !remaining.is_empty() {
            let message = NetlinkMessage::<SockDiagMessage>::deserialize(remaining)?;
            let length = message.header.length as usize;
            ensure!(
                length >= 16 && length <= remaining.len(),
                "invalid inet_diag message length"
            );
            remaining = &remaining[length.next_multiple_of(4).min(remaining.len())..];

            ensure!(
                message.header.sequence_number == sequence,
                "unexpected inet_diag sequence"
            );
            ensure!(
                message.header.flags & NLM_F_DUMP_INTR == 0,
                "inet_diag dump interrupted; retrying at next refresh"
            );
            match message.payload {
                NetlinkPayload::Error(error) if error.code.is_some() => {
                    return Err(error.to_io().into());
                }
                NetlinkPayload::Error(_) if destroy => return Ok(()),
                NetlinkPayload::Done(done) if !destroy && done.code == 0 => return Ok(()),
                NetlinkPayload::Done(done) if done.code != 0 => {
                    return Err(std::io::Error::from_raw_os_error(-done.code).into());
                }
                NetlinkPayload::InnerMessage(SockDiagMessage::InetResponse(row)) if !destroy => {
                    response(*row);
                }
                NetlinkPayload::Noop => {}
                _ => bail!("unexpected inet_diag response"),
            }
        }
    }
}

pub(super) fn collect(traffic: bool) -> Result<Vec<ConnectionRow>> {
    let socket = open_diag().context("opening NETLINK_SOCK_DIAG")?;
    let mut sockets = Vec::new();
    let mut sequence = 0;
    for family in [AF_INET, AF_INET6] {
        for (ip_protocol, protocol) in [(IPPROTO_TCP, Protocol::Tcp), (IPPROTO_UDP, Protocol::Udp)]
        {
            sequence += 1;
            let mut socket_id = if family == AF_INET {
                SocketId::new_v4()
            } else {
                SocketId::new_v6()
            };
            socket_id.cookie = [u8::MAX; 8];
            let extensions = if traffic && protocol == Protocol::Tcp {
                ExtensionFlags::INFO
            } else {
                ExtensionFlags::empty()
            };
            let result = request(
                &socket,
                InetRequest {
                    family,
                    protocol: ip_protocol,
                    extensions,
                    states: StateFlags::all(),
                    socket_id,
                },
                sequence,
                false,
                |row| sockets.push((protocol, row)),
            );
            if family == AF_INET6
                && result
                    .as_ref()
                    .err()
                    .and_then(|e| e.downcast_ref::<std::io::Error>())
                    .is_some_and(|e| {
                        matches!(
                            e.raw_os_error(),
                            Some(libc::EAFNOSUPPORT | libc::EPROTONOSUPPORT)
                        )
                    })
            {
                continue;
            }
            result.with_context(|| format!("enumerating {protocol} address family {family}"))?;
        }
    }

    let inodes: HashSet<u32> = sockets
        .iter()
        .map(|(_, row)| row.header.inode)
        .filter(|&i| i != 0)
        .collect();
    let owners = socket_owners(inodes)?;
    Ok(sockets
        .into_iter()
        .map(|(protocol, socket)| {
            let id = socket.header.socket_id;
            let pid = owners
                .get(&socket.header.inode)
                .copied()
                .unwrap_or_default();
            let connected = protocol == Protocol::Tcp
                && id.destination_port != 0
                && !id.destination_address.is_unspecified();
            let mut row = ConnectionRow::new(
                protocol,
                id.source_address,
                id.source_port,
                connected.then_some(id.destination_address),
                connected.then_some(id.destination_port),
                (protocol == Protocol::Tcp).then(|| tcp_state(socket.header.state)),
                pid,
            );
            let cookie = u64::from(u32::from_ne_bytes(id.cookie[..4].try_into().unwrap()))
                | (u64::from(u32::from_ne_bytes(id.cookie[4..].try_into().unwrap())) << 32);
            row.id.socket_cookie = (cookie != 0 && cookie != u64::MAX).then_some(cookie);
            row.socket_interface = id.interface_id;
            row.id.local = scoped_addr(row.id.local, id.interface_id);
            row.id.remote = row.id.remote.map(|addr| scoped_addr(addr, id.interface_id));
            if connected {
                for attribute in socket.nlas {
                    if let Nla::TcpInfo(bytes) = attribute {
                        // Linux UAPI struct tcp_info. Older kernels may omit the tail.
                        row.rx_bytes = counter(&bytes, 128);
                        row.tx_bytes = counter(&bytes, 200);
                    }
                }
            }
            row
        })
        .collect())
}

fn counter(bytes: &[u8], offset: usize) -> Option<u64> {
    Some(u64::from_ne_bytes(
        bytes.get(offset..offset + 8)?.try_into().ok()?,
    ))
}

fn scoped_addr(addr: SocketAddr, interface: u32) -> SocketAddr {
    match addr.ip() {
        IpAddr::V6(ip) if ip.is_unicast_link_local() => {
            SocketAddrV6::new(ip, addr.port(), 0, interface).into()
        }
        _ => addr,
    }
}

fn tcp_state(state: u8) -> TcpState {
    match state {
        TCP_ESTABLISHED => TcpState::Established,
        TCP_SYN_SENT => TcpState::SynSent,
        TCP_SYN_RECV => TcpState::SynReceived,
        TCP_FIN_WAIT1 => TcpState::FinWait1,
        TCP_FIN_WAIT2 => TcpState::FinWait2,
        TCP_TIME_WAIT => TcpState::TimeWait,
        TCP_CLOSE => TcpState::Closed,
        TCP_CLOSE_WAIT => TcpState::CloseWait,
        TCP_LAST_ACK => TcpState::LastAck,
        TCP_LISTEN => TcpState::Listen,
        TCP_CLOSING => TcpState::Closing,
        _ => TcpState::Unknown,
    }
}

fn socket_owners(mut pending: HashSet<u32>) -> Result<HashMap<u32, u32>> {
    let mut owners = HashMap::new();
    if pending.is_empty() {
        return Ok(owners);
    }
    let proc = match fs::read_dir("/proc") {
        Ok(proc) => proc,
        // Socket enumeration still works with PID metadata hidden.
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::NotFound | std::io::ErrorKind::PermissionDenied
            ) =>
        {
            return Ok(owners);
        }
        Err(error) => return Err(error).context("reading /proc for socket ownership"),
    };
    let mut processes: Vec<_> = proc
        .flatten()
        .filter_map(|entry| {
            let pid = entry.file_name().to_str()?.parse::<u32>().ok()?;
            Some((pid, entry.path()))
        })
        .collect();
    // For shared sockets keep one deterministic PID without duplicating byte counts.
    processes.sort_unstable_by_key(|(pid, _)| *pid);
    for (pid, path) in processes {
        let Ok(fds) = fs::read_dir(path.join("fd")) else {
            continue;
        };
        for fd in fds.flatten() {
            let Ok(target) = fs::read_link(fd.path()) else {
                continue;
            };
            if let Some(inode) = target
                .to_str()
                .and_then(|target| target.strip_prefix("socket:["))
                .and_then(|number| number.strip_suffix(']'))
                .and_then(|number| number.parse().ok())
                && pending.remove(&inode)
            {
                owners.insert(inode, pid);
            }
        }
        if pending.is_empty() {
            break;
        }
    }
    Ok(owners)
}

pub(crate) fn destroy_connection(row: &ConnectionRow) -> Result<()> {
    let cookie = row
        .id
        .socket_cookie
        .context("Linux socket identity is unavailable")?;
    let remote = row.id.remote.context("the socket has no remote endpoint")?;
    let family = if row.id.local.is_ipv4() {
        AF_INET
    } else {
        AF_INET6
    };
    let mut cookie_bytes = [0; 8];
    cookie_bytes[..4].copy_from_slice(&(cookie as u32).to_ne_bytes());
    cookie_bytes[4..].copy_from_slice(&((cookie >> 32) as u32).to_ne_bytes());
    let socket = open_diag()?;
    request(
        &socket,
        InetRequest {
            family,
            protocol: IPPROTO_TCP,
            extensions: ExtensionFlags::empty(),
            states: StateFlags::ESTABLISHED,
            socket_id: SocketId {
                source_port: row.id.local.port(),
                destination_port: remote.port(),
                source_address: row.id.local.ip(),
                destination_address: remote.ip(),
                interface_id: row.socket_interface,
                cookie: cookie_bytes,
            },
        },
        1,
        true,
        |_| {},
    )
    .context("closing TCP socket (requires CAP_NET_ADMIN in this network namespace)")
}
