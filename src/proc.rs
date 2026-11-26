//! Process table wrapper around `sysinfo`: PID resolution and termination.

use std::collections::HashMap;

use sysinfo::{Pid, ProcessRefreshKind, ProcessesToUpdate, System, UpdateKind, Users};

use crate::model::ProcessInfo;

/// Owns the `sysinfo::System` instance; refreshed by the collector thread.
pub struct ProcTable {
    sys: System,
    users: Users,
}

impl Default for ProcTable {
    fn default() -> Self {
        Self::new()
    }
}

impl ProcTable {
    pub fn new() -> Self {
        let mut table = Self {
            sys: System::new(),
            users: Users::new_with_refreshed_list(),
        };
        table.refresh();
        table
    }

    /// Refresh process list and usage counters.
    pub fn refresh(&mut self) {
        self.sys.refresh_processes_specifics(
            ProcessesToUpdate::All,
            true,
            ProcessRefreshKind::everything().with_user(UpdateKind::OnlyIfNotSet),
        );
    }

    pub fn get(&self, pid: u32) -> Option<ProcessInfo> {
        let p = self.sys.process(Pid::from_u32(pid))?;
        Some(ProcessInfo {
            pid,
            name: p.name().to_string_lossy().into_owned(),
            exe: p.exe().map(|e| e.to_string_lossy().into_owned()),
            cmd: if p.cmd().is_empty() {
                None
            } else {
                Some(
                    p.cmd()
                        .iter()
                        .map(|c| c.to_string_lossy())
                        .collect::<Vec<_>>()
                        .join(" "),
                )
            },
            user: p.user_id().map(|uid| {
                self.users
                    .get_user_by_id(uid)
                    .map(|user| user.name().to_owned())
                    .unwrap_or_else(|| uid.to_string())
            }),
            start_time: p.start_time(),
            cpu: p.cpu_usage(),
            mem: p.memory(),
        })
    }

    /// Snapshot metadata for the given PIDs only (keeps messages small).
    pub fn snapshot_for(&self, pids: &[u32]) -> HashMap<u32, ProcessInfo> {
        pids.iter()
            .filter_map(|&pid| self.get(pid).map(|info| (pid, info)))
            .collect()
    }

    /// Terminate the process observed before confirmation, if it still matches.
    pub fn kill(&mut self, expected: &ProcessInfo) -> bool {
        if expected.pid == 0 || expected.start_time == 0 {
            return false;
        }

        #[cfg(target_os = "linux")]
        let handle = {
            use std::os::fd::{FromRawFd, OwnedFd};
            // SAFETY: pidfd_open takes a numeric PID and flags, returning an owned fd.
            let fd =
                unsafe { libc::syscall(libc::SYS_pidfd_open, expected.pid as libc::pid_t, 0u32) };
            if fd < 0 {
                return false;
            }
            unsafe { OwnedFd::from_raw_fd(fd as i32) }
        };

        let pid = Pid::from_u32(expected.pid);
        self.sys.refresh_processes_specifics(
            ProcessesToUpdate::Some(&[pid]),
            true,
            ProcessRefreshKind::everything().with_exe(UpdateKind::Always),
        );
        let Some(current) = self.get(expected.pid) else {
            return false;
        };
        if current.start_time != expected.start_time || current.exe != expected.exe {
            return false;
        }

        #[cfg(target_os = "linux")]
        {
            use std::os::fd::AsRawFd;
            // SAFETY: the live pidfd pins the target across verification and signaling.
            unsafe {
                libc::syscall(
                    libc::SYS_pidfd_send_signal,
                    handle.as_raw_fd(),
                    libc::SIGKILL,
                    std::ptr::null::<libc::siginfo_t>(),
                    0u32,
                ) == 0
            }
        }
        #[cfg(not(target_os = "linux"))]
        self.sys.process(pid).is_some_and(|process| process.kill())
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn current_process_is_resolved() {
        let table = super::ProcTable::new();
        let info = table
            .get(std::process::id())
            .expect("own PID should resolve");
        assert!(!info.name.is_empty());
        assert!(info.exe.is_some());
    }
}
