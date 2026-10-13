//! Optional GeoIP country resolution for remote addresses.
//!
//! Compiled behind the `geoip` cargo feature (on by default). The MaxMind
//! GeoLite2-Country database file is NOT bundled: when it is missing the
//! resolver stays `None`, the Country column stays hidden and everything
//! else keeps working (soft failure, same pattern as EStats).

#[cfg(feature = "geoip")]
use std::collections::HashMap;
use std::net::IpAddr;

/// ISO 3166-1 alpha-2 code -> flag emoji via regional indicator symbols.
pub fn flag_emoji(iso: &str) -> Option<String> {
    let chars: Vec<char> = iso.chars().collect();
    if chars.len() != 2 || !chars.iter().all(|c| c.is_ascii_alphabetic()) {
        return None;
    }
    let a = 'A' as u32;
    let mut out = String::new();
    for c in chars {
        out.push(char::from_u32(
            0x1F1E6 + (c.to_ascii_uppercase() as u32 - a),
        )?);
    }
    Some(out)
}

#[cfg(feature = "geoip")]
pub struct GeoResolver {
    reader: maxminddb::Reader<Vec<u8>>,
    cache: HashMap<IpAddr, Option<String>>,
}

/// Stub used when the `geoip` cargo feature is compiled out, so `App` can
/// hold the same type unconditionally.
#[cfg(not(feature = "geoip"))]
#[derive(Default)]
pub struct GeoResolver;

#[cfg(not(feature = "geoip"))]
impl GeoResolver {
    pub fn open(_path: &std::path::Path) -> anyhow::Result<Self> {
        Err(anyhow::anyhow!("built without the 'geoip' feature"))
    }

    pub fn country_code(&mut self, _ip: IpAddr) -> Option<String> {
        None
    }
}

#[cfg(feature = "geoip")]
impl GeoResolver {
    /// Open a GeoLite2-Country database; errors bubble up as `None` upstream.
    pub fn open(path: &std::path::Path) -> anyhow::Result<Self> {
        Ok(Self {
            reader: maxminddb::Reader::open_readfile(path)?,
            cache: HashMap::new(),
        })
    }

    /// ISO country code for an IP, cached; `None` when unknown/private.
    pub fn country_code(&mut self, ip: IpAddr) -> Option<String> {
        if let Some(hit) = self.cache.get(&ip) {
            return hit.clone();
        }
        let found: Option<String> = self
            .reader
            .lookup(ip)
            .ok()
            .and_then(|result| result.decode::<maxminddb::geoip2::Country>().ok().flatten())
            .and_then(|c| c.country.iso_code.map(|s| s.to_string()));
        self.cache.insert(ip, found.clone());
        found
    }
}

#[cfg(test)]
mod tests {
    use super::flag_emoji;

    #[test]
    fn iso_codes_become_flags() {
        assert_eq!(flag_emoji("TR").as_deref(), Some("\u{1F1F9}\u{1F1F7}"));
        assert_eq!(flag_emoji("de").as_deref(), Some("\u{1F1E9}\u{1F1EA}"));
        assert_eq!(flag_emoji("us").as_deref(), Some("\u{1F1FA}\u{1F1F8}"));
        assert_eq!(flag_emoji("T"), None);
        assert_eq!(flag_emoji("T1"), None);
        assert_eq!(flag_emoji(""), None);
    }

    #[test]
    #[cfg(feature = "geoip")]
    fn missing_database_fails_soft() {
        // A nonexistent path must produce an Err, never a panic; the app
        // turns this into "column hidden".
        assert!(
            super::GeoResolver::open(std::path::Path::new("definitely-not-a-real-db.mmdb"))
                .is_err()
        );
    }
}
