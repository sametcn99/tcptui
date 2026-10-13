//! Experimental ETW mode: real connection events from the
//! `Microsoft-Windows-Kernel-Network` provider instead of polling alone.
//!
//! Opt-in via `--etw` or `[etw] enabled = true`. Requires an elevated
//! (administrator) terminal; every failure degrades gracefully back to the
//! polling pipeline.
//!
//! Event payload layout (documented provider schema):
//! - TCP connect: id 12 (IPv4) / 14 (IPv6)
//! - TCP disconnect: id 13 (IPv4) / 15 (IPv6)
//! - payload: `PID u32, size u32, daddr, saddr, dport u16 (BE), sport u16 (BE)`
//!   with 4-byte addresses for IPv4 and 16-byte for IPv6.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::OnceLock;
use std::sync::mpsc::Receiver;

use windows::Win32::System::Diagnostics::Etw::{
    CloseTrace, ControlTraceW, EVENT_CONTROL_CODE_ENABLE_PROVIDER, EVENT_TRACE_CONTROL_STOP,
    EVENT_TRACE_LOGFILEW, EVENT_TRACE_PROPERTIES, EVENT_TRACE_REAL_TIME_MODE, EnableTraceEx2,
    OpenTraceW, PROCESS_TRACE_MODE_EVENT_RECORD, PROCESS_TRACE_MODE_REAL_TIME, ProcessTrace,
    StartTraceW, TRACE_LEVEL_VERBOSE, WNODE_FLAG_TRACED_GUID,
};
use windows::core::{GUID, PCWSTR, PWSTR};

/// Microsoft-Windows-Kernel-Network provider GUID.
pub const KERNEL_NETWORK_GUID: GUID = GUID::from_values(
    0x9a280ac0,
    0xc8e0,
    0x11d1,
    [0x84, 0xe2, 0x00, 0xc0, 0x4f, 0xb9, 0x98, 0xa2],
);

const SESSION_NAME: &str = "tcptui-etw-session";

/// A parsed connection event.
#[derive(Clone, Debug, PartialEq)]
pub enum EtwEvent {
    Connect {
        v6: bool,
        pid: u32,
        local: SocketAddr,
        remote: SocketAddr,
    },
    Disconnect {
        v6: bool,
        pid: u32,
        local: SocketAddr,
        remote: SocketAddr,
    },
}

/// Parse the user payload of a Kernel-Network event record. Pure and unit
/// tested; `None` for unrelated event ids or truncated payloads.
pub fn parse_event(id: u16, user_data: &[u8]) -> Option<EtwEvent> {
    let (connect, v6) = match id {
        12 => (true, false),
        13 => (false, false),
        14 => (true, true),
        15 => (false, true),
        _ => return None,
    };
    let need = if v6 { 44 } else { 20 };
    if user_data.len() < need {
        return None;
    }
    let pid = u32::from_ne_bytes(user_data[0..4].try_into().ok()?);
    let (local, remote) = if v6 {
        let s6: [u8; 16] = user_data[24..40].try_into().ok()?;
        let d6: [u8; 16] = user_data[8..24].try_into().ok()?;
        let dport = port_be(&user_data[40..42]);
        let sport = port_be(&user_data[42..44]);
        (
            SocketAddr::new(IpAddr::V6(Ipv6Addr::from(s6)), sport),
            SocketAddr::new(IpAddr::V6(Ipv6Addr::from(d6)), dport),
        )
    } else {
        // Addresses arrive in network byte order; build from octets.
        let d4: [u8; 4] = user_data[8..12].try_into().ok()?;
        let s4: [u8; 4] = user_data[12..16].try_into().ok()?;
        let dport = port_be(&user_data[16..18]);
        let sport = port_be(&user_data[18..20]);
        (
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(s4[0], s4[1], s4[2], s4[3])), sport),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(d4[0], d4[1], d4[2], d4[3])), dport),
        )
    };
    Some(if connect {
        EtwEvent::Connect {
            v6,
            pid,
            local,
            remote,
        }
    } else {
        EtwEvent::Disconnect {
            v6,
            pid,
            local,
            remote,
        }
    })
}

fn port_be(bytes: &[u8]) -> u16 {
    u16::from_be(u16::from_ne_bytes([bytes[0], bytes[1]]))
}

// The ETW callback has no user context parameter, so events travel through
// a process-global channel installed when the session starts.
static EVENT_SINK: OnceLock<std::sync::mpsc::Sender<EtwEvent>> = OnceLock::new();

unsafe extern "system" fn event_record_callback(
    record: *mut windows::Win32::System::Diagnostics::Etw::EVENT_RECORD,
) {
    let Some(record) = (unsafe { record.as_ref() }) else {
        return;
    };
    if record.EventHeader.ProviderId != KERNEL_NETWORK_GUID {
        return;
    }
    let len = record.UserDataLength as usize;
    if len == 0 || record.UserData.is_null() {
        return;
    }
    let data = unsafe { std::slice::from_raw_parts(record.UserData as *const u8, len) };
    let id = record.EventHeader.EventDescriptor.Id;
    if let Some(event) = parse_event(id, data)
        && let Some(sink) = EVENT_SINK.get()
    {
        let _ = sink.send(event);
    }
}

/// A running real-time ETW session. Stopping everything on drop.
pub struct EtwSession {
    trace_handle: windows::Win32::System::Diagnostics::Etw::CONTROLTRACE_HANDLE,
    process_handle: windows::Win32::System::Diagnostics::Etw::PROCESSTRACE_HANDLE,
    props: Vec<u8>,
    name_wide: Vec<u16>,
}

impl EtwSession {
    /// Start the session; returns the event receiver on success.
    pub fn start() -> Result<(EtwSession, Receiver<EtwEvent>), String> {
        if !crate::actions::is_elevated() {
            return Err("ETW requires an elevated (administrator) terminal".to_string());
        }

        let (tx, rx) = std::sync::mpsc::channel();
        let _ = EVENT_SINK.set(tx);

        let mut name_wide: Vec<u16> = SESSION_NAME
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();

        // Properties struct plus room for the session name string.
        let props_size = std::mem::size_of::<EVENT_TRACE_PROPERTIES>();
        let mut props = vec![0u8; props_size + (name_wide.len() * 2)];
        {
            let p = unsafe { (props.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES).as_mut() };
            let Some(p) = p else {
                return Err("internal error: properties alignment".to_string());
            };
            p.Wnode.BufferSize = props_size as u32;
            p.Wnode.Flags = WNODE_FLAG_TRACED_GUID;
            p.LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
            p.LoggerNameOffset = props_size as u32;
        }
        // Write the session name right behind the struct.
        props[props_size..props_size + name_wide.len() * 2].copy_from_slice(unsafe {
            std::slice::from_raw_parts(name_wide.as_ptr().cast::<u8>(), name_wide.len() * 2)
        });

        let mut trace_handle = Default::default();
        let mut rc = unsafe {
            StartTraceW(
                &mut trace_handle,
                PCWSTR(name_wide.as_ptr()),
                props.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES,
            )
        };
        if rc.0 == 183 {
            // ERROR_ALREADY_EXISTS: stop a leftover session and retry once.
            let _ = unsafe {
                ControlTraceW(
                    Default::default(),
                    PCWSTR(name_wide.as_ptr()),
                    props.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES,
                    EVENT_TRACE_CONTROL_STOP,
                )
            };
            rc = unsafe {
                StartTraceW(
                    &mut trace_handle,
                    PCWSTR(name_wide.as_ptr()),
                    props.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES,
                )
            };
        }
        if rc.0 == 5 {
            return Err("access denied: start tcptui from an elevated terminal".to_string());
        }
        if rc.0 != 0 {
            return Err(format!("StartTraceW failed with error {}", rc.0));
        }

        let enable_rc = unsafe {
            EnableTraceEx2(
                trace_handle,
                &KERNEL_NETWORK_GUID,
                EVENT_CONTROL_CODE_ENABLE_PROVIDER.0,
                TRACE_LEVEL_VERBOSE as u8,
                u64::MAX,
                0,
                0,
                None,
            )
        };
        if enable_rc.0 != 0 {
            unsafe { stop_session(trace_handle, &mut props, &mut name_wide) };
            return Err(format!("EnableTraceEx2 failed with error {}", enable_rc.0));
        }

        let mut logfile: EVENT_TRACE_LOGFILEW = unsafe { std::mem::zeroed() };
        logfile.LoggerName = PWSTR(name_wide.as_mut_ptr());
        logfile.Anonymous1.ProcessTraceMode =
            PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
        logfile.Anonymous2.EventRecordCallback = Some(event_record_callback);

        let process_handle = unsafe { OpenTraceW(&mut logfile) };
        if process_handle.Value == u64::MAX {
            unsafe { stop_session(trace_handle, &mut props, &mut name_wide) };
            return Err("OpenTraceW failed".to_string());
        }

        // ProcessTrace blocks until CloseTrace, so it owns its own thread.
        std::thread::Builder::new()
            .name("etw-process".into())
            .spawn(move || {
                let _ = unsafe { ProcessTrace(&[process_handle], None, None) };
            })
            .map_err(|e| format!("failed to spawn ETW thread: {e}"))?;

        Ok((
            EtwSession {
                trace_handle,
                process_handle,
                props,
                name_wide,
            },
            rx,
        ))
    }
}

unsafe fn stop_session(
    trace_handle: windows::Win32::System::Diagnostics::Etw::CONTROLTRACE_HANDLE,
    props: &mut [u8],
    name_wide: &mut [u16],
) {
    unsafe {
        let _ = ControlTraceW(
            trace_handle,
            PCWSTR(name_wide.as_ptr()),
            props.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES,
            EVENT_TRACE_CONTROL_STOP,
        );
    }
}

impl Drop for EtwSession {
    fn drop(&mut self) {
        // Closing the processing handle unblocks ProcessTrace.
        unsafe {
            let _ = CloseTrace(self.process_handle);
            stop_session(self.trace_handle, &mut self.props, &mut self.name_wide);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4_payload(pid: u32, saddr: [u8; 4], sport: u16, daddr: [u8; 4], dport: u16) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&pid.to_ne_bytes());
        v.extend_from_slice(&0u32.to_ne_bytes()); // size
        v.extend_from_slice(&daddr); // daddr
        v.extend_from_slice(&saddr); // saddr
        v.extend_from_slice(&dport.to_be_bytes());
        v.extend_from_slice(&sport.to_be_bytes());
        v
    }

    #[test]
    fn parses_v4_connect_and_disconnect() {
        let data = v4_payload(4242, [192, 168, 1, 10], 50001, [142, 250, 4, 46], 443);
        let e = parse_event(12, &data).unwrap();
        match e {
            EtwEvent::Connect {
                v6,
                pid,
                local,
                remote,
            } => {
                assert!(!v6);
                assert_eq!(pid, 4242);
                assert_eq!(local.to_string(), "192.168.1.10:50001");
                assert_eq!(remote.to_string(), "142.250.4.46:443");
            }
            other => panic!("expected connect, got {other:?}"),
        }
        assert!(matches!(
            parse_event(13, &data).unwrap(),
            EtwEvent::Disconnect { .. }
        ));
    }

    #[test]
    fn parses_v6_events() {
        let mut v = Vec::new();
        v.extend_from_slice(&7u32.to_ne_bytes());
        v.extend_from_slice(&0u32.to_ne_bytes());
        v.extend_from_slice(&[0x20u8; 16]); // daddr
        v.extend_from_slice(&[0x01u8; 16]); // saddr
        v.extend_from_slice(&443u16.to_be_bytes()); // dport
        v.extend_from_slice(&1234u16.to_be_bytes()); // sport
        let e = parse_event(14, &v).unwrap();
        match e {
            EtwEvent::Connect {
                v6, local, remote, ..
            } => {
                assert!(v6);
                assert_eq!(local.port(), 1234);
                assert_eq!(remote.port(), 443);
                assert!(matches!(local.ip(), IpAddr::V6(_)));
            }
            other => panic!("expected connect, got {other:?}"),
        }
    }

    #[test]
    fn unrelated_and_truncated_events_are_ignored() {
        assert!(parse_event(10, &[0u8; 64]).is_none()); // send events
        assert!(parse_event(12, &[]).is_none());
        assert!(parse_event(12, &[0u8; 19]).is_none());
        assert!(parse_event(14, &[0u8; 43]).is_none());
    }
}
