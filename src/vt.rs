//! Optional VirusTotal lookups for the executable behind an endpoint.
//!
//! Compiled behind the `virustotal` cargo feature because it adds network
//! dependencies (ureq, sha2). Requires a free VirusTotal API key in
//! `[virustotal] api_key`; without one the feature stays dormant.

use anyhow::{Context, Result, anyhow};

/// SHA-256 of a file, streamed in 64 KiB chunks.
pub fn sha256_file(path: &std::path::Path) -> Result<String> {
    use sha2::{Digest, Sha256};

    let mut file =
        std::fs::File::open(path).with_context(|| format!("cannot open {}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let n = std::io::Read::read(&mut file, &mut buffer)?;
        if n == 0 {
            break;
        }
        hasher.update(&buffer[..n]);
    }
    let digest = hasher.finalize();
    let mut out = String::with_capacity(64);
    for byte in digest {
        out.push_str(&format!("{byte:02x}"));
    }
    Ok(out)
}

/// Query the VirusTotal v3 API for a file hash and render a compact report.
pub fn lookup(api_key: &str, hash: &str) -> Result<String> {
    let url = format!("https://www.virustotal.com/api/v3/files/{hash}");
    let response = ureq::get(&url)
        .set("x-apikey", api_key)
        .timeout(std::time::Duration::from_secs(20))
        .call()
        .map_err(|e| anyhow!("request failed: {e}"))?;

    let value: serde_json::Value = response
        .into_json()
        .map_err(|e| anyhow!("invalid response body: {e}"))?;

    let attributes = value
        .pointer("/data/attributes")
        .ok_or_else(|| anyhow!("unexpected response shape (no attributes)"))?;
    let stats = attributes
        .pointer("/last_analysis_stats")
        .ok_or_else(|| anyhow!("no analysis stats for this hash (unknown file)"))?;

    let malicious = stats["malicious"].as_i64().unwrap_or(0);
    let suspicious = stats["suspicious"].as_i64().unwrap_or(0);
    let harmless = stats["harmless"].as_i64().unwrap_or(0);
    let undetected = stats["undetected"].as_i64().unwrap_or(0);
    let name = attributes["meaningful_name"]
        .as_str()
        .unwrap_or("(unknown name)");
    let last = attributes["last_analysis_date"]
        .as_i64()
        .map(|ts| {
            chrono::DateTime::from_timestamp(ts, 0)
                .map(|d| d.format("%Y-%m-%d %H:%M UTC").to_string())
                .unwrap_or_else(|| "unknown".to_string())
        })
        .unwrap_or_else(|| "unknown".to_string());

    let verdict = if malicious > 0 {
        format!("MALICIOUS ({malicious} engines)")
    } else if suspicious > 0 {
        format!("SUSPICIOUS ({suspicious} engines)")
    } else {
        "clean".to_string()
    };

    Ok(format!(
        "Verdict : {verdict}\nName    : {name}\nEngines : {malicious} malicious, {suspicious} suspicious, {harmless} harmless, {undetected} undetected\nAnalyzed: {last}\nLink    : https://www.virustotal.com/gui/file/{hash}"
    ))
}

#[cfg(test)]
mod tests {
    #[test]
    fn hashes_known_vectors() {
        // SHA-256 of an empty file is a well-known constant.
        let dir = std::env::temp_dir().join("tcptui-vt-test");
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("empty.bin");
        std::fs::write(&file, b"").unwrap();
        assert_eq!(
            super::sha256_file(&file).unwrap(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        std::fs::write(&file, b"abc").unwrap();
        assert_eq!(
            super::sha256_file(&file).unwrap(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
