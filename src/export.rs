//! Table export in CSV, TSV, JSON and aligned-text formats.

use anyhow::{Context, Result};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ExportFormat {
    Csv,
    Tsv,
    Json,
    Txt,
}

impl ExportFormat {
    pub fn name(self) -> &'static str {
        match self {
            ExportFormat::Csv => "csv",
            ExportFormat::Tsv => "tsv",
            ExportFormat::Json => "json",
            ExportFormat::Txt => "txt",
        }
    }

    pub fn all() -> [ExportFormat; 4] {
        [
            ExportFormat::Csv,
            ExportFormat::Tsv,
            ExportFormat::Json,
            ExportFormat::Txt,
        ]
    }
}

/// Render a header + string rows into the requested format.
pub fn render(headers: &[String], rows: &[Vec<String>], format: ExportFormat) -> Result<String> {
    match format {
        ExportFormat::Csv => delimited(headers, rows, b','),
        ExportFormat::Tsv => delimited(headers, rows, b'\t'),
        ExportFormat::Json => json(headers, rows),
        ExportFormat::Txt => Ok(text(headers, rows)),
    }
}

fn delimited(headers: &[String], rows: &[Vec<String>], delim: u8) -> Result<String> {
    let mut out = Vec::new();
    {
        let mut writer = csv::WriterBuilder::new()
            .delimiter(delim)
            .from_writer(&mut out);
        writer
            .write_record(headers)
            .context("failed to write header")?;
        for row in rows {
            writer.write_record(row).context("failed to write row")?;
        }
        writer.flush().context("failed to flush writer")?;
    }
    Ok(String::from_utf8_lossy(&out).into_owned())
}

fn json(headers: &[String], rows: &[Vec<String>]) -> Result<String> {
    let list: Vec<serde_json::Map<String, serde_json::Value>> = rows
        .iter()
        .map(|row| {
            headers
                .iter()
                .zip(row)
                .map(|(h, v)| (h.clone(), serde_json::Value::String(v.clone())))
                .collect()
        })
        .collect();
    serde_json::to_string_pretty(&list).context("failed to serialize JSON")
}

fn text(headers: &[String], rows: &[Vec<String>]) -> String {
    let ncols = headers.len();
    let mut widths = vec![0usize; ncols];
    for (i, h) in headers.iter().enumerate() {
        widths[i] = h.chars().count();
    }
    for row in rows {
        for (i, cell) in row.iter().enumerate().take(ncols) {
            widths[i] = widths[i].max(cell.chars().count());
        }
    }
    let mut out = String::new();
    let fmt_row = |cells: &[String]| -> String {
        cells
            .iter()
            .enumerate()
            .take(ncols)
            .map(|(i, c)| format!("{c:<width$}", width = widths[i]))
            .collect::<Vec<_>>()
            .join("  ")
    };
    out.push_str(&fmt_row(headers));
    out.push('\n');
    out.push_str(&"─".repeat(widths.iter().sum::<usize>() + 2 * (ncols.saturating_sub(1))));
    out.push('\n');
    for row in rows {
        out.push_str(&fmt_row(row));
        out.push('\n');
    }
    out
}

/// Timestamped default file name, e.g. `tcptui-export-20260101-153000.csv`.
pub fn default_file_name(format: ExportFormat) -> String {
    let ts = chrono::Local::now().format("%Y%m%d-%H%M%S");
    format!("tcptui-export-{ts}.{}", format.name())
}

/// Write content to disk and return the canonical path used.
pub fn write_file(path: &std::path::Path, content: &str) -> Result<std::path::PathBuf> {
    std::fs::write(path, content).with_context(|| format!("failed to write {}", path.display()))?;
    Ok(path.to_path_buf())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> (Vec<String>, Vec<Vec<String>>) {
        (
            vec!["Process".into(), "PID".into()],
            vec![
                vec!["chrome.exe".into(), "42".into()],
                vec!["svc, host".into(), "7".into()],
            ],
        )
    }

    #[test]
    fn csv_escapes_delimiters() {
        let (h, r) = sample();
        let out = render(&h, &r, ExportFormat::Csv).unwrap();
        assert!(out.starts_with("Process,PID\n"));
        assert!(out.contains("\"svc, host\",7"));
    }

    #[test]
    fn tsv_uses_tabs() {
        let (h, r) = sample();
        let out = render(&h, &r, ExportFormat::Tsv).unwrap();
        assert!(out.starts_with("Process\tPID\r\n") || out.starts_with("Process\tPID\n"));
        // Tabs never appear in the content, so no quoting is needed there.
        assert!(out.contains("svc, host\t7"));
    }

    #[test]
    fn json_is_valid_and_complete() {
        let (h, r) = sample();
        let out = render(&h, &r, ExportFormat::Json).unwrap();
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        let arr = v.as_array().unwrap();
        assert_eq!(arr.len(), 2);
        assert_eq!(arr[0]["Process"], "chrome.exe");
        assert_eq!(arr[1]["PID"], "7");
    }

    #[test]
    fn text_aligns_columns() {
        let (h, r) = sample();
        let out = render(&h, &r, ExportFormat::Txt).unwrap();
        let mut lines = out.lines();
        let header = lines.next().unwrap();
        assert!(header.starts_with("Process"));
        assert!(header.contains("PID"));
        let sep = lines.next().unwrap();
        assert!(sep.starts_with('─'));
        assert!(lines.next().unwrap().starts_with("chrome.exe"));
    }

    #[test]
    fn default_file_name_has_extension() {
        let name = default_file_name(ExportFormat::Csv);
        assert!(name.starts_with("tcptui-export-2"));
        assert!(name.ends_with(".csv"));
    }
}
