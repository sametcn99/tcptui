//! Clipboard access via `arboard`.

use anyhow::{Context, Result};

/// Copy text to the system clipboard.
pub fn copy_text(text: &str) -> Result<()> {
    let mut clipboard = arboard::Clipboard::new().context("failed to open clipboard")?;
    clipboard
        .set_text(text.to_string())
        .context("failed to write clipboard")?;
    Ok(())
}
