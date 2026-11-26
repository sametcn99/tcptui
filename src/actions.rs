//! User-triggered actions and platform capability checks.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use anyhow::{Result, anyhow, bail};

use crate::model::{ConnectionRow, Protocol, RowChange};

#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub use windows::{is_elevated, process_user, verify_signed};

#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
pub use macos::verify_signed;

pub const CLOSE_SUPPORTED: bool = cfg!(any(windows, target_os = "linux"));

#[cfg(unix)]
pub fn is_elevated() -> bool {
    // SAFETY: geteuid has no arguments and reads the calling process's ID.
    unsafe { libc::geteuid() == 0 }
}

#[cfg(unix)]
pub fn process_user(pid: u32) -> Option<String> {
    crate::proc::ProcTable::new().get(pid)?.user
}

#[cfg(target_os = "linux")]
pub fn verify_signed(_: &std::path::Path) -> Option<bool> {
    None
}

pub fn can_close(row: &ConnectionRow) -> bool {
    CLOSE_SUPPORTED
        && row.protocol == Protocol::Tcp
        && row.is_established()
        && row.change != RowChange::Deleted
        && row.id.remote.is_some()
        && (!cfg!(windows)
            || (row.local_addr.is_ipv4() && row.remote_addr.is_some_and(|ip| ip.is_ipv4())))
        && (!cfg!(target_os = "linux") || row.id.socket_cookie.is_some())
}

pub fn close_connection(row: &ConnectionRow) -> Result<()> {
    if !CLOSE_SUPPORTED {
        bail!("Closing individual connections is unavailable on this platform");
    }
    if !can_close(row) {
        bail!("The selected row is not a closable established TCP connection");
    }
    #[cfg(windows)]
    return windows::close_connection(row);
    #[cfg(target_os = "linux")]
    return crate::net::destroy_connection(row);
    #[cfg(target_os = "macos")]
    unreachable!()
}

/// Maximum referral hops when following `whois:` server entries.
const WHOIS_MAX_HOPS: usize = 3;
const WHOIS_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const WHOIS_READ_TIMEOUT: Duration = Duration::from_secs(15);

/// Perform a whois query for an IP address, following server referrals
/// starting from `whois.iana.org` (RFC 3912 style).
pub fn whois(query: &str) -> Result<String> {
    let mut server = "whois.iana.org".to_string();
    let mut response = String::new();

    for _ in 0..=WHOIS_MAX_HOPS {
        response = whois_query_server(&server, query)?;
        if let Some(next) = extract_referral(&response)
            && next != server
        {
            server = next;
            continue;
        }
        return Ok(normalize_whois(&response));
    }
    Ok(normalize_whois(&response))
}

fn whois_query_server(server: &str, query: &str) -> Result<String> {
    let mut stream = TcpStream::connect((server, 43))
        .map_err(|e| anyhow!("cannot connect to whois server {server}: {e}"))?;
    stream.set_read_timeout(Some(WHOIS_READ_TIMEOUT))?;
    stream.set_write_timeout(Some(WHOIS_CONNECT_TIMEOUT))?;
    stream.write_all(format!("{query}\r\n").as_bytes())?;

    let mut buf = Vec::new();
    stream.read_to_end(&mut buf)?;
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

/// Extract a `whois: <server>` referral line, if present.
fn extract_referral(response: &str) -> Option<String> {
    for line in response.lines() {
        let line = line.trim();
        if let Some(rest) = line
            .strip_prefix("whois:")
            .or_else(|| line.strip_prefix("Whois:"))
        {
            let server = rest.trim();
            if !server.is_empty() && server.contains('.') {
                return Some(server.to_string());
            }
        }
    }
    None
}

fn normalize_whois(response: &str) -> String {
    let unified = response.replace("\r\n", "\n");
    let normalized: Vec<&str> = unified.lines().map(str::trim_end).collect();
    // Trim leading/trailing blank lines but keep interior formatting.
    let start = normalized.iter().position(|l| !l.is_empty()).unwrap_or(0);
    let end = normalized
        .iter()
        .rposition(|l| !l.is_empty())
        .map(|i| i + 1)
        .unwrap_or(0);
    normalized[start..end].join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Protocol;
    use std::net::{IpAddr, Ipv4Addr};

    fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    fn established_row_v4() -> ConnectionRow {
        ConnectionRow::new(
            Protocol::Tcp,
            v4(192, 168, 1, 10),
            50000,
            Some(v4(93, 184, 216, 34)),
            Some(443),
            Some(netstat2::TcpState::Established),
            1234,
        )
    }

    #[test]
    fn close_connection_rejects_udp_and_non_established() {
        let mut row = established_row_v4();
        row.protocol = Protocol::Udp;
        assert!(close_connection(&row).is_err());

        let mut row = established_row_v4();
        row.state = Some(netstat2::TcpState::Listen);
        assert!(close_connection(&row).is_err());
    }

    #[test]
    fn close_connection_rejects_ipv6() {
        let mut row = established_row_v4();
        row.local_addr = IpAddr::V6(std::net::Ipv6Addr::LOCALHOST);
        row.id.local = std::net::SocketAddr::new(row.local_addr, 50000);
        assert!(close_connection(&row).is_err());
    }

    #[test]
    fn whois_referral_extraction() {
        assert_eq!(
            extract_referral("foo: bar\nwhois: whois.example.org\n"),
            Some("whois.example.org".to_string())
        );
        assert_eq!(extract_referral("no referrals here"), None);
        // Self-referral must not cause an infinite loop upstream.
        assert_eq!(
            extract_referral("whois: whois.iana.org"),
            Some("whois.iana.org".to_string())
        );
    }

    #[test]
    fn whois_normalization_trims_and_unifies_line_endings() {
        assert_eq!(
            normalize_whois("\r\nRegistrar: Example\r\n\r\n\r\n"),
            "Registrar: Example"
        );
        assert_eq!(normalize_whois(""), "");
    }

    #[test]
    fn elevation_check_runs() {
        let _ = is_elevated();
    }

    #[test]
    fn process_user_of_current_process() {
        // May legitimately be None under restricted tokens.
        let _ = process_user(std::process::id());
    }
}
