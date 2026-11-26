//! Service names associated with monitored processes.

use std::collections::HashMap;

#[cfg(windows)]
mod windows;

#[cfg(windows)]
pub use windows::map_pid_to_services;

pub fn for_processes(_pids: &[u32]) -> HashMap<u32, Vec<(String, String)>> {
    #[cfg(windows)]
    return map_pid_to_services();

    #[cfg(target_os = "linux")]
    return linux::for_processes(_pids);

    #[cfg(target_os = "macos")]
    HashMap::new()
}

#[cfg(target_os = "linux")]
mod linux {
    use std::collections::HashMap;
    use std::ffi::CStr;
    use std::sync::OnceLock;

    type GetUnit = unsafe extern "C" fn(libc::pid_t, *mut *mut libc::c_char) -> libc::c_int;

    pub(super) fn for_processes(pids: &[u32]) -> HashMap<u32, Vec<(String, String)>> {
        static LIBRARY: OnceLock<Option<libloading::Library>> = OnceLock::new();
        // SAFETY: the OS-provided systemd library stays loaded for the life of the process.
        let library =
            LIBRARY.get_or_init(|| unsafe { libloading::Library::new("libsystemd.so.0").ok() });
        let Some(library) = library else {
            return HashMap::new();
        };
        // SAFETY: these symbols have the sd-login ABI and return caller-owned C strings.
        let user_unit = unsafe { library.get::<GetUnit>(b"sd_pid_get_user_unit\0") }.ok();
        let system_unit = unsafe { library.get::<GetUnit>(b"sd_pid_get_unit\0") }.ok();

        pids.iter()
            .filter(|&&pid| pid > 0 && pid <= libc::pid_t::MAX as u32)
            .filter_map(|&pid| {
                let name = user_unit
                    .as_ref()
                    .and_then(|f| lookup(**f, pid))
                    .or_else(|| system_unit.as_ref().and_then(|f| lookup(**f, pid)))?;
                Some((pid, vec![(name.clone(), name)]))
            })
            .collect()
    }

    fn lookup(get_unit: GetUnit, pid: u32) -> Option<String> {
        let mut name = std::ptr::null_mut();
        // SAFETY: out parameter is valid; on success the returned string is freed with libc.
        unsafe {
            if get_unit(pid as libc::pid_t, &raw mut name) < 0 || name.is_null() {
                return None;
            }
            let unit = CStr::from_ptr(name).to_string_lossy().into_owned();
            libc::free(name.cast());
            unit.ends_with(".service").then_some(unit)
        }
    }
}
