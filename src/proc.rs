//! Process table wrapper around `sysinfo`: PID resolution and termination.

use std::collections::HashMap;

use sysinfo::{Pid, ProcessesToUpdate, System};

use crate::model::ProcessInfo;

/// Owns the `sysinfo::System` instance; refreshed by the collector thread.
pub struct ProcTable {
    sys: System,
}

impl Default for ProcTable {
    fn default() -> Self {
        Self::new()
    }
}

impl ProcTable {
    pub fn new() -> Self {
        let mut sys = System::new();
        // Prime the table so the very first snapshot already has names.
        sys.refresh_processes(ProcessesToUpdate::All, true);
        Self { sys }
    }

    /// Refresh process list and usage counters.
    pub fn refresh(&mut self) {
        self.sys.refresh_processes(ProcessesToUpdate::All, true);
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

    /// Terminate a process. Returns `false` when the PID is gone or the
    /// termination request could not be delivered.
    pub fn kill(&mut self, pid: u32) -> bool {
        match self.sys.process(Pid::from_u32(pid)) {
            Some(p) => p.kill(),
            None => false,
        }
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
