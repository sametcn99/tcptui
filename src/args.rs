//! Command-line argument parsing for the `tcptui` binary.
//!
//! Kept dependency-free on purpose; the surface is small enough for a
//! hand-rolled parser that supports `--key value`, `--key=value` and
//! combined short flags.

use crate::config::ViewConfig;

pub const USAGE: &str = "\
tcptui - terminal UI clone of Sysinternals TCPView for Windows

USAGE:
    tcptui [OPTIONS]

OPTIONS:
        --interval <MS>     Snapshot refresh interval in milliseconds
                            (250..=60000, default 1000)
        --no-resolve        Start with hostname resolution disabled
        --filter <TEXT>     Apply a filter expression at startup; prefix
                            with `re:` to treat as a regular expression
        --tcp               Show TCP endpoints only
        --udp               Show UDP endpoints only
        --theme <NAME>      Color theme: dark (default) or light
    -h, --help              Print this help
    -V, --version           Print version

KEYS (inside the TUI):
    ?  help    /  filter    Ctrl+F search    s  sort    r  resolve addresses
    t  TCP     u  UDP       c  close connection    k  end process
    w  whois   e  export    F5 refresh       F6 watch process
";

#[derive(Clone, Debug, Default, PartialEq)]
pub struct CliOpts {
    pub interval_ms: Option<u64>,
    pub no_resolve: bool,
    pub filter: Option<String>,
    pub tcp_only: bool,
    pub udp_only: bool,
    pub theme: Option<String>,
    pub help: bool,
    pub version: bool,
}

#[derive(Debug, PartialEq)]
pub enum ParseOutcome {
    Run,
    Help,
    Version,
}

/// Parse `std::env::args()`. Unknown flags are reported as errors; a
/// standalone `-` or non-flag argument is ignored for future positional use.
pub fn parse(args: &[String]) -> Result<(CliOpts, ParseOutcome), String> {
    let mut opts = CliOpts::default();
    let mut i = 0;
    while i < args.len() {
        let arg = args[i].as_str();
        let mut value_for = |name: &str| -> Result<String, String> {
            i += 1;
            args.get(i)
                .cloned()
                .ok_or_else(|| format!("{name} expects a value"))
        };
        match arg {
            "-h" | "--help" => opts.help = true,
            "-V" | "--version" => opts.version = true,
            "--no-resolve" => opts.no_resolve = true,
            "--tcp" => opts.tcp_only = true,
            "--udp" => opts.udp_only = true,
            "--interval" => {
                let v = value_for("--interval")?;
                opts.interval_ms = Some(
                    v.parse()
                        .map_err(|_| format!("--interval expects a number, got {v}"))?,
                );
            }
            "--filter" => {
                let v = value_for("--filter")?;
                opts.filter = Some(v);
            }
            "--theme" => {
                let v = value_for("--theme")?;
                opts.theme = Some(v);
            }
            other => {
                if let Some(v) = other.strip_prefix("--interval=") {
                    opts.interval_ms = Some(
                        v.parse()
                            .map_err(|_| format!("--interval expects a number, got {v}"))?,
                    );
                } else if let Some(v) = other.strip_prefix("--filter=") {
                    opts.filter = Some(v.to_string());
                } else if let Some(v) = other.strip_prefix("--theme=") {
                    opts.theme = Some(v.to_string());
                } else if other.starts_with('-') && other != "-" {
                    return Err(format!("unknown option: {other}"));
                }
            }
        }
        i += 1;
    }

    if let Some(ms) = opts.interval_ms
        && !(250..=60000).contains(&ms)
    {
        return Err(format!(
            "--interval must be within 250..=60000 ms, got {ms}"
        ));
    }
    if opts.tcp_only && opts.udp_only {
        return Err("--tcp and --udp cannot be combined".to_string());
    }

    let outcome = if opts.help {
        ParseOutcome::Help
    } else if opts.version {
        ParseOutcome::Version
    } else {
        ParseOutcome::Run
    };
    Ok((opts, outcome))
}

/// Apply CLI overrides on top of the loaded config.
pub fn apply_overrides(opts: &CliOpts, view: &mut ViewConfig) {
    if let Some(ms) = opts.interval_ms {
        view.refresh_interval_ms = ms;
    }
    if opts.no_resolve {
        view.resolve_addresses = false;
    }
    if opts.tcp_only {
        view.show_tcp = true;
        view.show_udp = false;
    }
    if opts.udp_only {
        view.show_udp = true;
        view.show_tcp = false;
    }
    if let Some(theme) = &opts.theme {
        view.theme = theme.clone();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_ok(args: &[&str]) -> (CliOpts, ParseOutcome) {
        let owned: Vec<String> = args.iter().map(|s| s.to_string()).collect();
        parse(&owned).expect("should parse")
    }

    #[test]
    fn parses_long_options_with_values() {
        let (opts, outcome) = parse_ok(&[
            "--interval",
            "2000",
            "--filter",
            "chrome",
            "--theme",
            "light",
        ]);
        assert_eq!(outcome, ParseOutcome::Run);
        assert_eq!(opts.interval_ms, Some(2000));
        assert_eq!(opts.filter.as_deref(), Some("chrome"));
        assert_eq!(opts.theme.as_deref(), Some("light"));
    }

    #[test]
    fn parses_equals_form() {
        let (opts, _) = parse_ok(&["--interval=500", "--filter=svc"]);
        assert_eq!(opts.interval_ms, Some(500));
        assert_eq!(opts.filter.as_deref(), Some("svc"));
    }

    #[test]
    fn help_and_version_win() {
        assert_eq!(parse_ok(&["--help"]).1, ParseOutcome::Help);
        assert_eq!(parse_ok(&["-V"]).1, ParseOutcome::Version);
    }

    #[test]
    fn rejects_unknown_flags_and_bad_values() {
        let owned = vec!["--wat".to_string()];
        assert!(parse(&owned).is_err());

        let owned = vec!["--interval".to_string(), "abc".to_string()];
        assert!(parse(&owned).is_err());

        let owned = vec!["--interval".to_string(), "10".to_string()];
        assert!(parse(&owned).is_err()); // below minimum

        let owned = vec!["--tcp".to_string(), "--udp".to_string()];
        assert!(parse(&owned).is_err());
    }

    #[test]
    fn overrides_apply_on_config() {
        let mut view = ViewConfig::default();
        let opts = CliOpts {
            interval_ms: Some(5000),
            no_resolve: true,
            tcp_only: true,
            ..Default::default()
        };
        apply_overrides(&opts, &mut view);
        assert_eq!(view.refresh_interval_ms, 5000);
        assert!(!view.resolve_addresses);
        assert!(view.show_tcp);
        assert!(!view.show_udp);
    }
}
