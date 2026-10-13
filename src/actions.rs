//! User-triggered actions: close connection, whois, elevation check and
//! process user account resolution.

use std::io::{Read, Write};
use std::net::{IpAddr, TcpStream};
use std::time::Duration;

use anyhow::{Result, anyhow, bail};
use windows::Win32::Foundation::{CloseHandle, HANDLE, HLOCAL, LocalFree};
use windows::Win32::NetworkManagement::IpHelper::SetTcpEntry;
use windows::Win32::Security::Authorization::ConvertSidToStringSidW;
use windows::Win32::Security::{
    GetTokenInformation, LookupAccountSidW, PSID, TOKEN_ELEVATION, TOKEN_QUERY, TOKEN_QUERY_SOURCE,
    TOKEN_USER, TokenElevation, TokenUser,
};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

use crate::model::ConnectionRow;
use crate::net::{MIB_TCP_STATE_DELETE_TCB_U32, make_v4_tcp_row};

/// Close an ESTABLISHED TCP connection by setting its state to
/// `MIB_TCP_STATE_DELETE_TCB` — the same mechanism TCPView uses.
///
/// Requires elevation for connections owned by other users. IPv4 only:
/// Windows exposes no setter for the IPv6 table.
pub fn close_connection(row: &ConnectionRow) -> Result<()> {
    if row.protocol != crate::model::Protocol::Tcp {
        bail!("only TCP connections can be closed");
    }
    if !row.is_established() {
        bail!("only ESTABLISHED connections can be closed");
    }
    let Some(IpAddr::V4(local)) = Some(row.local_addr) else {
        bail!("closing IPv6 connections is not supported by the Windows API");
    };
    let Some(IpAddr::V4(remote)) = row.remote_addr else {
        bail!("closing IPv6 connections is not supported by the Windows API");
    };
    let Some(remote_port) = row.remote_port else {
        bail!("connection has no remote endpoint");
    };

    let mib_row = make_v4_tcp_row(
        local,
        row.local_port,
        remote,
        remote_port,
        MIB_TCP_STATE_DELETE_TCB_U32,
    );
    let rc = unsafe { SetTcpEntry(&mib_row) };
    if rc != 0 {
        // ERROR_ACCESS_DENIED (5) is the common case without elevation.
        return Err(anyhow!(
            "SetTcpEntry failed with Windows error {rc}: {}",
            std::io::Error::from_raw_os_error(rc as i32)
        ));
    }
    Ok(())
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

/// Whether the current process runs with an elevated (administrator) token.
pub fn is_elevated() -> bool {
    unsafe {
        let mut token = HANDLE::default();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).is_err() {
            return false;
        }
        let mut elevation = TOKEN_ELEVATION::default();
        let mut returned = 0u32;
        let ok = GetTokenInformation(
            token,
            TokenElevation,
            Some((&mut elevation as *mut TOKEN_ELEVATION).cast::<core::ffi::c_void>()),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut returned,
        )
        .is_ok();
        let _ = CloseHandle(token);
        ok && elevation.TokenIsElevated != 0
    }
}

/// Resolve the user account that owns a process, e.g. `DESKTOP-1\alice`.
/// Falls back to the raw SID string when the account cannot be looked up.
pub fn process_user(pid: u32) -> Option<String> {
    // Open the target process token.
    let handle = unsafe {
        let rights = windows::Win32::System::Threading::PROCESS_QUERY_LIMITED_INFORMATION;
        let process = windows::Win32::System::Threading::OpenProcess(rights, false, pid).ok()?;
        let mut token = HANDLE::default();
        if OpenProcessToken(process, TOKEN_QUERY | TOKEN_QUERY_SOURCE, &mut token).is_err() {
            let _ = CloseHandle(process);
            return None;
        }
        let _ = CloseHandle(process);
        token
    };

    // Two-call pattern: discover the required size, then fetch the data.
    let mut needed = 0u32;
    unsafe {
        let _ = GetTokenInformation(handle, TokenUser, None, 0, &mut needed);
    }
    if needed == 0 {
        let _ = unsafe { CloseHandle(handle) };
        return None;
    }
    let mut buffer = vec![0u8; needed as usize];
    let ok = unsafe {
        GetTokenInformation(
            handle,
            TokenUser,
            Some(buffer.as_mut_ptr().cast::<core::ffi::c_void>()),
            needed,
            &mut needed,
        )
        .is_ok()
    };
    let _ = unsafe { CloseHandle(handle) };
    if !ok {
        return None;
    }

    let user = unsafe { &*(buffer.as_ptr() as *const TOKEN_USER) };
    let sid = user.User.Sid;

    // Convert to a string account name when possible.
    if let Some(name) = sid_to_account(sid) {
        return Some(name);
    }
    sid_to_string(sid)
}

/// Use `LookupAccountSidW` to turn a SID into `DOMAIN\name`.
fn sid_to_account(sid: PSID) -> Option<String> {
    let mut name = [0u16; 256];
    let mut domain = [0u16; 256];
    let mut name_len = name.len() as u32;
    let mut domain_len = domain.len() as u32;
    let mut usage = windows::Win32::Security::SID_NAME_USE::default();

    let ok = unsafe {
        LookupAccountSidW(
            None,
            sid,
            Some(windows::core::PWSTR::from_raw(name.as_mut_ptr())),
            &mut name_len,
            Some(windows::core::PWSTR::from_raw(domain.as_mut_ptr())),
            &mut domain_len,
            &mut usage,
        )
    }
    .is_ok();
    if !ok {
        return None;
    }
    let name_str = String::from_utf16(&name[..name_len as usize]).unwrap_or_default();
    let domain_str = String::from_utf16(&domain[..domain_len as usize]).unwrap_or_default();
    if domain_str.is_empty() {
        Some(name_str)
    } else {
        Some(format!("{domain_str}\\{name_str}"))
    }
}

/// Fallback: render the SID as its `S-1-5-...` string form.
fn sid_to_string(sid: PSID) -> Option<String> {
    let mut str_ptr = windows::core::PWSTR::null();
    let ok = unsafe { ConvertSidToStringSidW(sid, &mut str_ptr) }.is_ok();
    if !ok || str_ptr.is_null() {
        return None;
    }
    let s = unsafe { str_ptr.to_string() }.ok();
    unsafe { LocalFree(Some(HLOCAL(str_ptr.as_ptr() as *mut core::ffi::c_void))) };
    s
}

/// Whether the file at `path` carries a valid Authenticode signature
/// (`WinVerifyTrust`, no revocation check). `None` when the input is
/// unusable; `Some(false)` when unsigned or invalid.
pub fn verify_signed(path: &std::path::Path) -> Option<bool> {
    use std::os::windows::ffi::OsStrExt;
    use windows::Win32::Security::WinTrust::{
        WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_DATA, WINTRUST_FILE_INFO, WTD_CHOICE_FILE,
        WTD_REVOKE_NONE, WTD_STATEACTION_CLOSE, WTD_STATEACTION_VERIFY, WTD_UI_NONE,
        WinVerifyTrust,
    };

    let wide: Vec<u16> = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    if wide.len() < 2 {
        return None;
    }

    unsafe {
        let mut file_info: WINTRUST_FILE_INFO = std::mem::zeroed();
        file_info.cbStruct = std::mem::size_of::<WINTRUST_FILE_INFO>() as u32;
        file_info.pcwszFilePath = windows::core::PCWSTR(wide.as_ptr());

        let mut trust: WINTRUST_DATA = std::mem::zeroed();
        trust.cbStruct = std::mem::size_of::<WINTRUST_DATA>() as u32;
        trust.dwUIChoice = WTD_UI_NONE;
        trust.fdwRevocationChecks = WTD_REVOKE_NONE;
        trust.dwUnionChoice = WTD_CHOICE_FILE;
        trust.Anonymous.pFile = &mut file_info;
        trust.dwStateAction = WTD_STATEACTION_VERIFY;

        let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
        let hwnd = windows::Win32::Foundation::HWND::default();
        let rc = WinVerifyTrust(
            hwnd,
            &mut action,
            &mut trust as *mut _ as *mut core::ffi::c_void,
        );

        // Release the verification state data.
        trust.dwStateAction = WTD_STATEACTION_CLOSE;
        let _ = WinVerifyTrust(
            hwnd,
            &mut action,
            &mut trust as *mut _ as *mut core::ffi::c_void,
        );

        Some(rc == 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Protocol;
    use std::net::Ipv4Addr;

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
