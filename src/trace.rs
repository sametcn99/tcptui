//! Events from optional operating-system TCP tracing.

use std::net::SocketAddr;
use std::sync::mpsc::Receiver;

use chrono::{DateTime, Local};

#[cfg(all(target_os = "linux", feature = "linux-trace"))]
mod linux;

pub const SOURCE: Option<&str> = if cfg!(windows) {
    Some("ETW")
} else if cfg!(all(target_os = "linux", feature = "linux-trace")) {
    Some("eBPF")
} else {
    None
};

pub struct Session {
    #[cfg(windows)]
    _inner: crate::etw::EtwSession,
    #[cfg(all(target_os = "linux", feature = "linux-trace"))]
    _inner: linux::Session,
}

pub struct Event {
    pub connected: bool,
    pub local: SocketAddr,
    pub remote: SocketAddr,
    pub pid: Option<u32>,
    pub cookie: Option<u64>,
    pub at: DateTime<Local>,
}

pub enum Message {
    Event(Event),
    Lost(u64),
}

pub fn start() -> Result<(Session, Receiver<Message>), String> {
    #[cfg(windows)]
    return crate::etw::EtwSession::start().map(|(inner, rx)| (Session { _inner: inner }, rx));
    #[cfg(all(target_os = "linux", feature = "linux-trace"))]
    return linux::start().map(|(inner, rx)| (Session { _inner: inner }, rx));
    #[cfg(not(any(windows, all(target_os = "linux", feature = "linux-trace"))))]
    Err("TCP tracing is unavailable in this build".into())
}
