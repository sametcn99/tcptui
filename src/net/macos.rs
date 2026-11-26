//! Best-effort TCP counters sampled from macOS's system nettop command.

use std::collections::{HashMap, HashSet};
use std::io::Read;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::process::{Command, Stdio};
use std::sync::mpsc::{self, RecvTimeoutError, Sender};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail, ensure};

use crate::model::{ConnectionRow, Protocol};
use netstat2::TcpState;

const SAMPLE_INTERVAL: Duration = Duration::from_secs(2);
const MAX_SAMPLE_AGE: Duration = Duration::from_secs(5);
const MAX_OUTPUT: u64 = 8 * 1024 * 1024;

type SocketKey = (u32, SocketAddr, SocketAddr);
type Counters = HashMap<SocketKey, Option<(u64, u64)>>;

type Sample = Option<(Instant, Counters)>;

pub struct TrafficReader {
    enabled: bool,
    sampler: Option<Sampler>,
}

impl TrafficReader {
    pub fn new(enabled: bool) -> Self {
        Self {
            enabled,
            sampler: None,
        }
    }

    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
        if !enabled {
            self.sampler = None;
        }
    }

    pub fn collect(&mut self) -> Result<Vec<ConnectionRow>> {
        let mut rows = collect()?;
        if !self.enabled {
            return Ok(rows);
        }
        if self.sampler.is_none() {
            self.sampler = Sampler::start().ok();
        }
        if let Some(sampler) = &self.sampler
            && let Ok(sample) = sampler.latest.lock()
            && let Some((at, counters)) = sample.as_ref()
            && at.elapsed() <= MAX_SAMPLE_AGE
        {
            for row in &mut rows {
                if row.is_connected_tcp()
                    && let Some(remote) = row.id.remote
                    && let Some(Some((tx, rx))) = counters.get(&(row.pid, row.id.local, remote))
                {
                    row.tx_bytes = Some(*tx);
                    row.rx_bytes = Some(*rx);
                }
            }
        }
        Ok(rows)
    }
}

struct Sampler {
    latest: Arc<Mutex<Sample>>,
    stop: Sender<()>,
    worker: Option<JoinHandle<()>>,
}

impl Sampler {
    fn start() -> std::io::Result<Self> {
        let latest = Arc::new(Mutex::new(None));
        let result = Arc::clone(&latest);
        let (stop, stopped) = mpsc::channel();
        let worker = std::thread::Builder::new()
            .name("nettop-sample".into())
            .spawn(move || {
                loop {
                    let sample = sample().ok().map(|sample| (Instant::now(), sample));
                    let Ok(mut current) = result.lock() else {
                        break;
                    };
                    *current = sample;
                    drop(current);
                    if stopped.recv_timeout(SAMPLE_INTERVAL) != Err(RecvTimeoutError::Timeout) {
                        break;
                    }
                }
            })?;
        Ok(Self {
            latest,
            stop,
            worker: Some(worker),
        })
    }
}

impl Drop for Sampler {
    fn drop(&mut self) {
        let _ = self.stop.send(());
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

#[repr(C)]
#[derive(Default)]
struct SocketInfo {
    generation: u64,
    local: [u8; 16],
    remote: [u8; 16],
    local_port: u16,
    remote_port: u16,
    family: u8,
    protocol: u8,
    state: u8,
    reserved: u8,
}

unsafe extern "C" {
    fn tcptui_socket_info(pid: libc::pid_t, fd: libc::c_int, out: *mut SocketInfo) -> libc::c_int;
}

pub(super) fn collect() -> Result<Vec<ConnectionRow>> {
    let mut rows = Vec::new();
    let mut seen = HashSet::new();
    for pid in visible_pids()? {
        // SAFETY: a null buffer and zero size ask libproc for the required bytes.
        let size =
            unsafe { libc::proc_pidinfo(pid, libc::PROC_PIDLISTFDS, 0, std::ptr::null_mut(), 0) };
        if size <= 0 {
            continue;
        }
        let entry_size = std::mem::size_of::<libc::proc_fdinfo>();
        let capacity = (size as usize / entry_size + 16).min(1_048_576);
        let mut fds = vec![
            libc::proc_fdinfo {
                proc_fd: 0,
                proc_fdtype: 0
            };
            capacity
        ];
        // SAFETY: the C call can write at most the capacity of the initialized array.
        let written = unsafe {
            libc::proc_pidinfo(
                pid,
                libc::PROC_PIDLISTFDS,
                0,
                fds.as_mut_ptr().cast(),
                (capacity * entry_size) as i32,
            )
        };
        if written <= 0 {
            continue;
        }
        fds.truncate(written as usize / entry_size);
        for fd in fds {
            if fd.proc_fdtype as i32 != libc::PROX_FDTYPE_SOCKET {
                continue;
            }
            let mut info = SocketInfo::default();
            // SAFETY: the SDK-backed helper initializes out on success and
            // rejects disappeared, inaccessible or unsupported descriptors.
            if unsafe { tcptui_socket_info(pid, fd.proc_fd, &raw mut info) } != 1 {
                continue;
            }
            let (local, remote): (IpAddr, IpAddr) = match info.family {
                4 => (
                    Ipv4Addr::new(info.local[0], info.local[1], info.local[2], info.local[3])
                        .into(),
                    Ipv4Addr::new(
                        info.remote[0],
                        info.remote[1],
                        info.remote[2],
                        info.remote[3],
                    )
                    .into(),
                ),
                6 => (
                    Ipv6Addr::from(info.local).into(),
                    Ipv6Addr::from(info.remote).into(),
                ),
                _ => continue,
            };
            let tcp = i32::from(info.protocol) == libc::IPPROTO_TCP;
            let connected = tcp && info.remote_port != 0 && !remote.is_unspecified();
            let mut row = ConnectionRow::new(
                if tcp { Protocol::Tcp } else { Protocol::Udp },
                local,
                info.local_port,
                connected.then_some(remote),
                connected.then_some(info.remote_port),
                tcp.then(|| tcp_state(info.state)),
                pid as u32,
            );
            row.id.socket_cookie = (info.generation != 0).then_some(info.generation);
            if seen.insert(row.id.clone()) {
                rows.push(row);
            }
        }
    }
    Ok(rows)
}

fn visible_pids() -> Result<Vec<libc::pid_t>> {
    const PROC_ALL_PIDS: libc::c_uint = 1;
    // SAFETY: querying with a null buffer returns the required byte count.
    let size = unsafe { libc::proc_listpids(PROC_ALL_PIDS, 0, std::ptr::null_mut(), 0) };
    if size <= 0 {
        return Err(std::io::Error::last_os_error()).context("listing macOS processes");
    }
    let pid_size = std::mem::size_of::<libc::pid_t>();
    let mut pids = vec![0; size as usize / pid_size + 128];
    loop {
        let bytes =
            i32::try_from(pids.len() * pid_size).context("macOS process list is too large")?;
        // SAFETY: the buffer contains bytes writable by libproc.
        let written =
            unsafe { libc::proc_listpids(PROC_ALL_PIDS, 0, pids.as_mut_ptr().cast(), bytes) };
        if written <= 0 {
            return Err(std::io::Error::last_os_error()).context("reading macOS process list");
        }
        if written < bytes {
            pids.truncate(written as usize / pid_size);
            pids.retain(|&pid| pid > 0);
            return Ok(pids);
        }
        pids.resize(pids.len() * 2, 0);
    }
}

fn tcp_state(state: u8) -> TcpState {
    match state {
        0 => TcpState::Closed,
        1 => TcpState::Listen,
        2 => TcpState::SynSent,
        3 => TcpState::SynReceived,
        4 => TcpState::Established,
        5 => TcpState::CloseWait,
        6 => TcpState::FinWait1,
        7 => TcpState::Closing,
        8 => TcpState::LastAck,
        9 => TcpState::FinWait2,
        10 => TcpState::TimeWait,
        _ => TcpState::Unknown,
    }
}

fn sample() -> Result<Counters> {
    let mut child = Command::new("/usr/bin/nettop")
        .args([
            "-L",
            "1",
            "-n",
            "-x",
            "-m",
            "tcp",
            "-J",
            "bytes_in,bytes_out",
        ])
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .context("starting nettop")?;
    let stdout = child.stdout.take().context("capturing nettop output")?;
    let reader = std::thread::spawn(move || {
        let mut data = Vec::new();
        stdout.take(MAX_OUTPUT + 1).read_to_end(&mut data)?;
        Ok::<_, std::io::Error>(data)
    });
    let started = Instant::now();
    let result = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Ok(status),
            Ok(None) if started.elapsed() < Duration::from_secs(3) => {
                std::thread::sleep(Duration::from_millis(20));
            }
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                break Err(anyhow::anyhow!("nettop did not finish within 3 seconds"));
            }
        }
    };
    let output = reader
        .join()
        .map_err(|_| anyhow::anyhow!("nettop reader failed"))??;
    ensure!(result?.success(), "nettop exited unsuccessfully");
    ensure!(
        output.len() as u64 <= MAX_OUTPUT,
        "nettop sample is too large"
    );
    parse_sample(&output)
}

fn parse_sample(output: &[u8]) -> Result<Counters> {
    let mut reader = csv::ReaderBuilder::new()
        .has_headers(false)
        .flexible(true)
        .from_reader(output);
    let mut counters = Counters::new();
    let mut columns = None;
    let mut pid = None;
    for record in reader.byte_records() {
        let record = record?;
        let Some(key) = record
            .get(0)
            .and_then(|value| std::str::from_utf8(value).ok())
            .map(str::trim)
        else {
            pid = None;
            continue;
        };
        let rx_col = record.iter().position(|value| value == b"bytes_in");
        let tx_col = record.iter().position(|value| value == b"bytes_out");
        if let (Some(rx), Some(tx)) = (rx_col, tx_col) {
            columns = Some((rx, tx));
            pid = None;
            continue;
        }
        let Some((rx_col, tx_col)) = columns else {
            continue;
        };
        if let Some(endpoints) = key
            .strip_prefix("tcp4 ")
            .or_else(|| key.strip_prefix("tcp6 "))
        {
            if let (Some(pid), Some((local, remote))) = (
                pid,
                endpoints
                    .split_once("<->")
                    .and_then(|(a, b)| Some((parse_addr(a)?, parse_addr(b)?))),
            ) {
                let tx = record.get(tx_col).and_then(parse_bytes);
                let rx = record.get(rx_col).and_then(parse_bytes);
                counters
                    .entry((pid, local, remote))
                    .and_modify(|entry| *entry = None)
                    .or_insert(tx.zip(rx));
            }
        } else {
            pid = key
                .rsplit_once('.')
                .and_then(|(name, pid)| {
                    if name.contains(':') {
                        None
                    } else {
                        pid.parse::<u32>().ok()
                    }
                })
                .filter(|&pid| pid != 0);
        }
    }
    if columns.is_none() {
        bail!("nettop CSV lacks byte columns");
    }
    Ok(counters)
}

fn parse_bytes(bytes: &[u8]) -> Option<u64> {
    std::str::from_utf8(bytes).ok()?.trim().parse().ok()
}

fn parse_addr(text: &str) -> Option<SocketAddr> {
    let text = text.trim();
    if let Ok(addr) = text.parse() {
        return Some(addr);
    }
    // nettop uses IP.port for IPv6, including %interface on scoped addresses.
    let (ip, port) = text.rsplit_once('.').or_else(|| text.rsplit_once(':'))?;
    let ip = ip
        .trim_matches(['[', ']'])
        .split('%')
        .next()?
        .parse::<IpAddr>()
        .ok()?;
    Some(SocketAddr::new(ip, port.parse().ok()?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sample_matches_numeric_ipv4_and_ipv6_connections() {
        let data = b"time,bytes_in,bytes_out,\nserver.42,,,\ntcp4 127.0.0.1:5000<->127.0.0.1:5001,12,34,\ntcp6 ::1.5000<->::1.5001,56,78,\n";
        let sample = parse_sample(data).unwrap();
        let endpoints = (
            42,
            "127.0.0.1:5000".parse().unwrap(),
            "127.0.0.1:5001".parse().unwrap(),
        );
        assert_eq!(sample[&endpoints], Some((34, 12)));
        let endpoints = (
            42,
            "[::1]:5000".parse().unwrap(),
            "[::1]:5001".parse().unwrap(),
        );
        assert_eq!(sample[&endpoints], Some((78, 56)));
    }
}
