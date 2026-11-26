//! Clipboard access via arboard.

use anyhow::{Context, Result};

pub fn copy_text(text: &str) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        use std::sync::Mutex;

        // X11 serves clipboard data from its owner until another app takes over.
        static CLIPBOARD: Mutex<Option<arboard::Clipboard>> = Mutex::new(None);
        let mut clipboard = CLIPBOARD
            .lock()
            .map_err(|_| anyhow::anyhow!("clipboard lock failed"))?;
        if clipboard.is_none() {
            *clipboard = Some(arboard::Clipboard::new().context("failed to open clipboard")?);
        }
        clipboard
            .as_mut()
            .unwrap()
            .set_text(text)
            .context("failed to write clipboard")
    }

    #[cfg(not(target_os = "linux"))]
    arboard::Clipboard::new()
        .context("failed to open clipboard")?
        .set_text(text)
        .context("failed to write clipboard")
}
