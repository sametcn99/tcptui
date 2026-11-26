//! macOS executable signature verification using Security.framework.

use std::ffi::c_void;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::ptr;

type CfRef = *const c_void;

#[link(name = "CoreFoundation", kind = "framework")]
unsafe extern "C" {
    fn CFURLCreateFromFileSystemRepresentation(
        allocator: CfRef,
        path: *const u8,
        length: isize,
        is_directory: u8,
    ) -> CfRef;
    fn CFRelease(object: CfRef);
}

#[link(name = "Security", kind = "framework")]
unsafe extern "C" {
    fn SecStaticCodeCreateWithPath(path: CfRef, flags: u32, code: *mut CfRef) -> i32;
    fn SecStaticCodeCheckValidity(code: CfRef, flags: u32, requirement: CfRef) -> i32;
}

pub fn verify_signed(path: &Path) -> Option<bool> {
    const CHECK_ALL_ARCHITECTURES: u32 = 1;
    const UNSIGNED: i32 = -67062;
    const SIGNATURE_FAILED: i32 = -67061;
    const BAD_OBJECT_FORMAT: i32 = -67049;
    const BAD_MAIN_EXECUTABLE: i32 = -67010;
    let bytes = path.as_os_str().as_bytes();
    let length = isize::try_from(bytes.len()).ok()?;
    let mut code = ptr::null();

    // SAFETY: Core Foundation receives an explicit byte count and produces
    // retained objects, released on all paths after successful creation.
    unsafe {
        let url = CFURLCreateFromFileSystemRepresentation(ptr::null(), bytes.as_ptr(), length, 0);
        if url.is_null() {
            return None;
        }
        let result = SecStaticCodeCreateWithPath(url, 0, &raw mut code);
        CFRelease(url);
        if result != 0 || code.is_null() {
            return None;
        }
        let result = SecStaticCodeCheckValidity(code, CHECK_ALL_ARCHITECTURES, ptr::null());
        CFRelease(code);
        match result {
            0 => Some(true),
            UNSIGNED | SIGNATURE_FAILED | BAD_OBJECT_FORMAT | BAD_MAIN_EXECUTABLE => Some(false),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn apple_system_binary_has_a_valid_signature() {
        assert_eq!(
            super::verify_signed(std::path::Path::new("/bin/ls")),
            Some(true)
        );
    }
}
