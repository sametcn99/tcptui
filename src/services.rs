//! PID -> Windows service mapping via the Service Control Manager.
//!
//! TCPView shows the service display name next to processes that host a
//! service; this reproduces that via `EnumServicesStatusExW` with
//! `SC_ENUM_PROCESS_INFO`.

use std::collections::HashMap;

use windows::Win32::System::Services::{
    CloseServiceHandle, ENUM_SERVICE_STATUS_PROCESSW, EnumServicesStatusExW, OpenSCManagerW,
    SC_ENUM_PROCESS_INFO, SC_MANAGER_ENUMERATE_SERVICE, SERVICE_DRIVER, SERVICE_STATE_ALL,
    SERVICE_WIN32,
};
use windows::core::PCWSTR;

/// Map every running service's PID to its (service name, display name) pairs.
pub fn map_pid_to_services() -> HashMap<u32, Vec<(String, String)>> {
    let mut result: HashMap<u32, Vec<(String, String)>> = HashMap::new();

    unsafe {
        let scm = match OpenSCManagerW(None, None, SC_MANAGER_ENUMERATE_SERVICE) {
            Ok(h) => h,
            Err(_) => return result, // e.g. service database locked; non-fatal
        };

        let mut buffer: Vec<u8> = vec![0; 128 * 1024];
        let mut needed: u32 = 0;
        let mut count: u32 = 0;
        let service_type = SERVICE_WIN32 | SERVICE_DRIVER;
        let ok = EnumServicesStatusExW(
            scm,
            SC_ENUM_PROCESS_INFO,
            service_type,
            SERVICE_STATE_ALL,
            Some(&mut buffer),
            &mut needed,
            &mut count,
            None,
            PCWSTR::null(),
        );
        if ok.is_err() {
            // Grow to the required size and retry once.
            buffer = vec![0; needed as usize];
            let _ = EnumServicesStatusExW(
                scm,
                SC_ENUM_PROCESS_INFO,
                service_type,
                SERVICE_STATE_ALL,
                Some(&mut buffer),
                &mut needed,
                &mut count,
                None,
                PCWSTR::null(),
            );
        }

        let entries = std::slice::from_raw_parts(
            buffer.as_ptr() as *const ENUM_SERVICE_STATUS_PROCESSW,
            count as usize,
        );
        for e in entries {
            let pid = e.ServiceStatusProcess.dwProcessId;
            if pid == 0 {
                continue; // stopped service or driver without a process
            }
            let name = if e.lpServiceName.is_null() {
                String::new()
            } else {
                PCWSTR::from_raw(e.lpServiceName.0)
                    .to_string()
                    .unwrap_or_default()
            };
            let display = if e.lpDisplayName.is_null() {
                String::new()
            } else {
                PCWSTR::from_raw(e.lpDisplayName.0)
                    .to_string()
                    .unwrap_or_default()
            };
            result.entry(pid).or_default().push((name, display));
        }

        let _ = CloseServiceHandle(scm);
    }

    result
}

#[cfg(test)]
mod tests {
    #[test]
    fn service_map_returns_without_panicking() {
        // On CI/developer machines the SCM is available; the call must at
        // worst return an empty map, never panic.
        let map = super::map_pid_to_services();
        for (pid, svcs) in &map {
            assert!(*pid > 0);
            assert!(!svcs.is_empty());
        }
    }
}
