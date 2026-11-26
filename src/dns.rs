//! Reverse DNS resolution via the system resolver with a TTL cache and a
//! background worker thread so the UI never blocks on lookups.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};

/// Result state for one IP in the cache.
#[derive(Clone, Debug, PartialEq)]
pub enum DnsStatus {
    Pending,
    Resolved(String),
    Failed,
}

pub struct DnsCache {
    map: HashMap<IpAddr, (DnsStatus, std::time::Instant)>,
}

/// How long a successful lookup stays fresh.
const RESOLVED_TTL: std::time::Duration = std::time::Duration::from_secs(300);
/// How long a failed lookup is remembered before retrying.
const FAILED_TTL: std::time::Duration = std::time::Duration::from_secs(30);

impl Default for DnsCache {
    fn default() -> Self {
        Self::new()
    }
}

impl DnsCache {
    pub fn new() -> Self {
        Self {
            map: HashMap::new(),
        }
    }

    pub fn get(&self, ip: &IpAddr) -> Option<&DnsStatus> {
        self.map.get(ip).map(|(s, _)| s)
    }

    /// Entry considered fresh enough that no new lookup is needed.
    pub fn is_fresh(&self, ip: &IpAddr) -> bool {
        match self.map.get(ip) {
            Some((DnsStatus::Pending, _)) => true, // lookup already queued
            Some((DnsStatus::Resolved(_), t)) => t.elapsed() < RESOLVED_TTL,
            Some((DnsStatus::Failed, t)) => t.elapsed() < FAILED_TTL,
            None => false,
        }
    }

    pub fn mark_pending(&mut self, ip: IpAddr) {
        self.map
            .insert(ip, (DnsStatus::Pending, std::time::Instant::now()));
    }

    pub fn resolve(&mut self, ip: IpAddr, hostname: Option<String>) {
        let status = match hostname {
            Some(h) => DnsStatus::Resolved(h),
            None => DnsStatus::Failed,
        };
        self.map.insert(ip, (status, std::time::Instant::now()));
    }

    /// Hostname for display, when already resolved.
    pub fn hostname(&self, ip: &IpAddr) -> Option<String> {
        match self.get(ip) {
            Some(DnsStatus::Resolved(h)) => Some(h.clone()),
            _ => None,
        }
    }
}

pub type SharedDnsCache = Arc<Mutex<DnsCache>>;

/// Blocking reverse lookup. A failed lookup leaves the numeric IP in the UI.
pub fn reverse_lookup(ip: IpAddr) -> Option<String> {
    let name = dns_lookup::lookup_addr(&ip).ok()?;
    let trimmed = name.trim_end_matches('.');
    (!trimmed.is_empty() && trimmed.parse::<IpAddr>().is_err()).then(|| trimmed.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn cache_ttl_lifecycle() {
        let mut cache = DnsCache::new();
        let ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        assert!(!cache.is_fresh(&ip));

        cache.mark_pending(ip);
        assert!(cache.is_fresh(&ip));
        assert_eq!(cache.get(&ip), Some(&DnsStatus::Pending));

        cache.resolve(ip, Some("localhost".into()));
        assert_eq!(cache.hostname(&ip), Some("localhost".to_string()));

        cache.resolve(ip, None);
        assert_eq!(cache.get(&ip), Some(&DnsStatus::Failed));
        assert!(cache.hostname(&ip).is_none());
    }

    #[test]
    fn loopback_reverse_lookup_or_clean_failure() {
        // Depends on the hosts file, so accept both outcomes; it must not
        // panic and a success must be a sensible hostname.
        if let Some(h) = reverse_lookup(IpAddr::V4(Ipv4Addr::LOCALHOST)) {
            assert!(!h.trim().is_empty());
        }
    }

    #[test]
    fn ipv6_lookup_does_not_panic() {
        let _ = reverse_lookup(IpAddr::V6(Ipv6Addr::LOCALHOST));
    }
}
