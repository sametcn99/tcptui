//! Lifecycle and decoding for the Linux CO-RE probe.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::fd::AsRawFd;
use std::os::unix::fs::MetadataExt;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, TrySendError, sync_channel};
use std::thread::JoinHandle;

use anyhow::{Context, Result};
use aya::maps::{Array, RingBuf};
use aya::programs::BtfTracePoint;
use aya::{Btf, EbpfLoader, include_bytes_aligned};
use chrono::{Local, TimeDelta};

use super::{Event, Message};

const OBJECT: &[u8] = include_bytes_aligned!(concat!(env!("OUT_DIR"), "/tcptui.bpf.o"));

pub(super) struct Session {
    stop: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
}

impl Drop for Session {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

pub(super) fn start() -> Result<(Session, Receiver<Message>), String> {
    start_inner().map_err(|error| format!("{error:#}"))
}

fn start_inner() -> Result<(Session, Receiver<Message>)> {
    let btf = Btf::from_sys_fs().context("loading kernel BTF")?;
    let namespace =
        std::fs::metadata("/proc/self/ns/net").context("identifying network namespace")?;
    let netns = u32::try_from(namespace.ino()).context("network namespace ID is out of range")?;
    let mut bpf = EbpfLoader::new()
        .btf(Some(&btf))
        .override_global("netns", &netns, true)
        .load(OBJECT)
        .context("loading Linux trace probe")?;
    let program: &mut BtfTracePoint = bpf
        .program_mut("observe_state")
        .context("missing TCP state probe")?
        .try_into()?;
    program
        .load("inet_sock_set_state", &btf)
        .context("loading inet_sock_set_state (check BPF permissions and kernel support)")?;
    program.attach().context("attaching Linux TCP tracepoint")?;
    let mut events = RingBuf::try_from(bpf.take_map("EVENTS").context("missing trace ring")?)?;
    let lost =
        Array::<_, u64>::try_from(bpf.take_map("LOST").context("missing trace loss counter")?)?;
    let stop = Arc::new(AtomicBool::new(false));
    let stop_worker = stop.clone();
    let (tx, rx) = sync_channel(1024);
    let worker = std::thread::Builder::new()
        .name("tcp-trace".into())
        .spawn(move || {
            // Keep the BPF program and its link alive until the reader is stopped.
            let _bpf = bpf;
            let mut previous_loss = 0u64;
            let mut userspace_loss = 0u64;
            let mut poll = libc::pollfd {
                fd: events.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            while !stop_worker.load(Ordering::Relaxed) {
                // SAFETY: poll reads/writes a single initialized pollfd, with a bounded wait.
                let ready = unsafe { libc::poll(&raw mut poll, 1, 100) };
                if ready < 0
                    && std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted
                {
                    break;
                }
                for _ in 0..1024 {
                    let Some(item) = events.next() else { break };
                    let Some(event) = decode(&item) else { continue };
                    match tx.try_send(Message::Event(event)) {
                        Ok(()) => {}
                        Err(TrySendError::Full(_)) => {
                            userspace_loss = userspace_loss.saturating_add(1)
                        }
                        Err(TrySendError::Disconnected(_)) => return,
                    }
                }
                let kernel_loss = lost.get(&0, 0).unwrap_or(previous_loss);
                let loss = userspace_loss.saturating_add(kernel_loss.saturating_sub(previous_loss));
                if loss > 0 && tx.try_send(Message::Lost(loss)).is_ok() {
                    previous_loss = kernel_loss;
                    userspace_loss = 0;
                }
            }
        })?;
    Ok((
        Session {
            stop,
            worker: Some(worker),
        },
        rx,
    ))
}

fn decode(data: &[u8]) -> Option<Event> {
    let cookie = u64::from_ne_bytes(data.get(..8)?.try_into().ok()?);
    let when = u64::from_ne_bytes(data.get(8..16)?.try_into().ok()?);
    let family = u16::from_ne_bytes(data.get(52..54)?.try_into().ok()?);
    let ip = |bytes: &[u8]| -> Option<IpAddr> {
        match i32::from(family) {
            libc::AF_INET => {
                Some(Ipv4Addr::from(<[u8; 4]>::try_from(bytes.get(..4)?).ok()?).into())
            }
            libc::AF_INET6 => Some(Ipv6Addr::from(<[u8; 16]>::try_from(bytes).ok()?).into()),
            _ => None,
        }
    };
    let local = SocketAddr::new(
        ip(data.get(16..32)?)?,
        u16::from_ne_bytes(data.get(48..50)?.try_into().ok()?),
    );
    let remote = SocketAddr::new(
        ip(data.get(32..48)?)?,
        u16::from_ne_bytes(data.get(50..52)?.try_into().ok()?),
    );
    let now = Local::now();
    let mut clock = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: clock_gettime writes into a valid timespec.
    let at = if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &raw mut clock) } == 0 {
        let elapsed =
            (clock.tv_sec as u64 * 1_000_000_000 + clock.tv_nsec as u64).saturating_sub(when);
        now - TimeDelta::milliseconds((elapsed / 1_000_000) as i64)
    } else {
        now
    };
    Some(Event {
        connected: *data.get(54)? != 0,
        local,
        remote,
        pid: None,
        cookie: (cookie != 0).then_some(cookie),
        at,
    })
}
