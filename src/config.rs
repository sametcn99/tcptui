//! Persistent configuration stored at `%APPDATA%\tcptui\config.toml`.

use std::collections::HashMap;
use std::path::PathBuf;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::app::{ColumnId, DEFAULT_COLUMN_ORDER};

/// Partial TOML files fall back to `Default` per missing field.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct ViewConfig {
    pub refresh_interval_ms: u64,
    pub resolve_addresses: bool,
    pub show_tcp: bool,
    pub show_udp: bool,
    pub show_unconnected: bool,
    pub show_loopback: bool,
    pub theme: String,
}

impl Default for ViewConfig {
    fn default() -> Self {
        Self {
            refresh_interval_ms: 1000,
            resolve_addresses: false,
            show_tcp: true,
            show_udp: true,
            show_unconnected: true,
            show_loopback: true,
            theme: "dark".to_string(),
        }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ColumnsSerde {
    /// Column keys in display order; missing columns are appended.
    pub order: Vec<String>,
    /// Keys of hidden columns.
    pub hidden: Vec<String>,
    /// Per-column desired character width.
    pub width: HashMap<String, u16>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct EstatsConfig {
    pub enabled: bool,
}

impl Default for EstatsConfig {
    fn default() -> Self {
        Self { enabled: true }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub view: ViewConfig,
    #[serde(default)]
    pub columns: ColumnsSerde,
    #[serde(default)]
    pub estats: EstatsConfig,
}

/// `%APPDATA%\tcptui\config.toml`.
pub fn config_path() -> Option<PathBuf> {
    std::env::var_os("APPDATA").map(|base| {
        let mut p = PathBuf::from(base);
        p.push("tcptui");
        p.push("config.toml");
        p
    })
}

impl Config {
    /// Load the configuration, falling back to defaults when the file is
    /// missing or unparsable (first run, hand-edited mistakes, ...).
    pub fn load() -> Self {
        let Some(path) = config_path() else {
            return Self::default();
        };
        match std::fs::read_to_string(&path) {
            Ok(text) => toml::from_str(&text).unwrap_or_default(),
            Err(_) => Self::default(),
        }
    }

    /// Persist current settings, creating the directory if needed.
    pub fn save(&self) -> Result<()> {
        let path = config_path().context("APPDATA is not set; cannot resolve config path")?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("failed to create {}", parent.display()))?;
        }
        let text = toml::to_string_pretty(self).context("failed to serialize config")?;
        std::fs::write(&path, text)
            .with_context(|| format!("failed to write {}", path.display()))?;
        Ok(())
    }

    /// Convert the persisted column layout into the runtime representation.
    pub fn column_layout(
        &self,
    ) -> (
        Vec<ColumnId>,
        std::collections::HashSet<ColumnId>,
        HashMap<ColumnId, u16>,
    ) {
        let mut order: Vec<ColumnId> = self
            .columns
            .order
            .iter()
            .filter_map(|k| ColumnId::from_key(k))
            .collect();
        for id in DEFAULT_COLUMN_ORDER {
            if !order.contains(id) {
                order.push(*id);
            }
        }
        let hidden = self
            .columns
            .hidden
            .iter()
            .filter_map(|k| ColumnId::from_key(k))
            .collect();
        let width = self
            .columns
            .width
            .iter()
            .filter_map(|(k, w)| ColumnId::from_key(k).map(|id| (id, *w)))
            .collect();
        (order, hidden, width)
    }

    /// Store a runtime column layout back into the serde representation.
    pub fn set_column_layout(
        &mut self,
        order: &[ColumnId],
        hidden: &std::collections::HashSet<ColumnId>,
        width: &HashMap<ColumnId, u16>,
    ) {
        self.columns.order = order.iter().map(|c| c.key().to_string()).collect();
        self.columns.hidden = hidden.iter().map(|c| c.key().to_string()).collect();
        self.columns.width = width
            .iter()
            .map(|(c, w)| (c.key().to_string(), *w))
            .collect();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_round_trips_through_toml() {
        let mut cfg = Config::default();
        cfg.view.refresh_interval_ms = 2500;
        cfg.view.theme = "light".into();
        cfg.columns.order = vec!["pid".into(), "process".into()];
        cfg.columns.hidden = vec!["service".into()];
        cfg.columns.width.insert("process".into(), 24);
        cfg.estats.enabled = false;

        let text = toml::to_string_pretty(&cfg).unwrap();
        let back: Config = toml::from_str(&text).unwrap();
        assert_eq!(back.view.refresh_interval_ms, 2500);
        assert_eq!(back.view.theme, "light");
        assert_eq!(back.columns.hidden, vec!["service".to_string()]);
        assert_eq!(back.columns.width.get("process"), Some(&24));
        assert!(!back.estats.enabled);
    }

    #[test]
    fn missing_fields_fall_back_to_defaults() {
        let cfg: Config = toml::from_str("[view]\nrefresh_interval_ms = 500\n").unwrap();
        assert_eq!(cfg.view.refresh_interval_ms, 500);
        assert!(cfg.view.show_tcp); // serde default kicked in
        assert!(cfg.estats.enabled);
    }

    #[test]
    fn column_layout_mapping_is_stable() {
        let mut cfg = Config::default();
        let (order, hidden, width) = cfg.column_layout();
        assert_eq!(order.len(), DEFAULT_COLUMN_ORDER.len());
        assert!(hidden.is_empty());
        assert!(width.is_empty());

        let mut hidden2 = std::collections::HashSet::new();
        hidden2.insert(ColumnId::Service);
        let mut width2 = HashMap::new();
        width2.insert(ColumnId::Process, 20);
        cfg.set_column_layout(&order, &hidden2, &width2);

        let (order3, hidden3, width3) = cfg.column_layout();
        assert_eq!(order3, order);
        assert!(hidden3.contains(&ColumnId::Service));
        assert_eq!(width3.get(&ColumnId::Process), Some(&20));
    }
}
