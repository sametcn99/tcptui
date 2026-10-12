//! tcpvcon — the command-line companion of tcptui, mirroring the tool
//! that ships with Sysinternals TCPView.
//!
//! Usage: tcpvcon [-a] [-c] [-j] [-n] [process name or PID]
//!   -a  show all endpoints (default: established TCP connections only)
//!   -c  print output as CSV
//!   -j  print output as JSON
//!   -n  do not resolve addresses

use std::collections::HashMap;

use anyhow::Result;

use tcptui::model::{ConnectionRow, ProcessInfo, Protocol};
use tcptui::proc::ProcTable;

const USAGE: &str = "\
tcpvcon [-a] [-c] [-j] [-n] [process name or PID]

  -a   Show all endpoints (default is to show established TCP connections).
  -c   Print output as CSV.
  -j   Print output as JSON.
  -n   Don't resolve addresses.
  -h   Print this help.
  -V   Print version.

A process name (substring, case-insensitive) or a numeric PID can be given
to restrict the output to endpoints owned by that process.";

struct Cli {
    all: bool,
    csv: bool,
    json: bool,
    resolve: bool,
    filter: Option<String>,
    help: bool,
    version: bool,
}

fn parse_args(args: &[String]) -> Result<Cli> {
    let mut cli = Cli {
        all: false,
        csv: false,
        json: false,
        resolve: true,
        filter: None,
        help: false,
        version: false,
    };
    for arg in args {
        match arg.as_str() {
            "-a" => cli.all = true,
            "-c" => cli.csv = true,
            "-j" | "--json" => cli.json = true,
            "-n" => cli.resolve = false,
            "-h" | "--help" => cli.help = true,
            "-V" | "--version" => cli.version = true,
            other => {
                if other.starts_with('-') && other.len() > 1 {
                    anyhow::bail!("unknown option: {other}");
                }
                if cli.filter.is_some() {
                    anyhow::bail!("only one process name or PID may be given");
                }
                cli.filter = Some(other.to_string());
            }
        }
    }
    Ok(cli)
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let cli = match parse_args(&args) {
        Ok(cli) => cli,
        Err(e) => {
            eprintln!("tcpvcon: {e}");
            eprintln!("{USAGE}");
            std::process::exit(2);
        }
    };
    if cli.help {
        println!("{USAGE}");
        return;
    }
    if cli.version {
        println!("tcpvcon {}", env!("CARGO_PKG_VERSION"));
        return;
    }
    if let Err(e) = run(&cli) {
        eprintln!("tcpvcon: {e}");
        std::process::exit(1);
    }
}

fn run(cli: &Cli) -> Result<()> {
    tcptui::net::ensure_wsa()?;

    let mut rows = tcptui::net::collect_sockets()?;

    // Process names for every owning PID.
    let pids: Vec<u32> = {
        let mut set: Vec<u32> = rows.iter().map(|r| r.pid).collect();
        set.sort_unstable();
        set.dedup();
        set
    };
    let sys = ProcTable::new();
    let processes: HashMap<u32, ProcessInfo> = sys.snapshot_for(&pids);
    for row in &mut rows {
        if let Some(p) = processes.get(&row.pid) {
            row.process_name = Some(p.name.clone());
        }
    }

    // Positional filter: numeric PID or process-name substring.
    if let Some(f) = &cli.filter {
        if let Ok(pid) = f.parse::<u32>() {
            rows.retain(|r| r.pid == pid);
        } else {
            let needle = f.to_lowercase();
            rows.retain(|r| r.process_display().to_lowercase().contains(&needle));
        }
    }

    // Default (without -a): established TCP connections only, like tcpvcon.
    if !cli.all {
        rows.retain(|r| r.protocol == Protocol::Tcp && r.is_established());
    }

    // Sort like TCPView: process, then protocol, then local address.
    rows.sort_by(|a, b| {
        a.process_display()
            .cmp(&b.process_display())
            .then_with(|| a.protocol.cmp(&b.protocol))
            .then_with(|| a.local_port.cmp(&b.local_port))
    });

    // Resolve addresses when requested (blocking, like the original tool).
    let mut cache = tcptui::dns::DnsCache::new();
    let mut addr_text = |ip: std::net::IpAddr| -> String {
        if cli.resolve {
            if let Some(h) = cache.hostname(&ip) {
                return h;
            }
            let h = tcptui::dns::reverse_lookup(ip);
            cache.resolve(ip, h.clone());
            h.unwrap_or_else(|| ip.to_string())
        } else {
            ip.to_string()
        }
    };

    let headers = [
        "Process",
        "PID",
        "Protocol",
        "Local Address",
        "Local Port",
        "Remote Address",
        "Remote Port",
        "State",
    ];

    let mut out = String::new();
    if cli.json {
        let header_vec: Vec<String> = headers.iter().map(|h| h.to_string()).collect();
        let all_rows: Vec<Vec<String>> =
            rows.iter().map(|r| row_fields(r, &mut addr_text)).collect();
        out = tcptui::export::render(&header_vec, &all_rows, tcptui::export::ExportFormat::Json)?;
    } else if cli.csv {
        let mut w = csv::Writer::from_writer(vec![]);
        w.write_record(headers)?;
        for r in &rows {
            w.write_record(row_fields(r, &mut addr_text))?;
        }
        let bytes = w.into_inner()?;
        out = String::from_utf8_lossy(&bytes).into_owned();
    } else {
        // Fixed-width columns with a ruler, similar to netstat/tcpvcon output.
        let widths = [18, 6, 5, 30, 6, 30, 6, 13];
        let fmt_row = |cells: [&str; 8]| -> String {
            cells
                .iter()
                .zip(widths)
                .map(|(c, w)| format!("{c:<w$}"))
                .collect::<Vec<_>>()
                .join(" ")
                .trim_end()
                .to_string()
                + "\n"
        };
        out.push_str(&fmt_row([
            "Process",
            "PID",
            "Proto",
            "Local Address",
            "L-Port",
            "Remote Address",
            "R-Port",
            "State",
        ]));
        out.push_str(&fmt_row([
            "------------------",
            "------",
            "-----",
            "------------------------------",
            "------",
            "------------------------------",
            "------",
            "-------------",
        ]));
        for r in &rows {
            let fields = row_fields(r, &mut addr_text);
            let refs: [&str; 8] = [
                &fields[0], &fields[1], &fields[2], &fields[3], &fields[4], &fields[5], &fields[6],
                &fields[7],
            ];
            out.push_str(&fmt_row(refs));
        }
    }
    print!("{out}");
    Ok(())
}

fn row_fields(
    r: &ConnectionRow,
    addr_text: &mut dyn FnMut(std::net::IpAddr) -> String,
) -> Vec<String> {
    vec![
        r.process_display(),
        r.pid.to_string(),
        r.protocol.to_string(),
        addr_text(r.local_addr),
        r.local_port.to_string(),
        match r.remote_addr {
            Some(ip) => addr_text(ip),
            None => String::new(),
        },
        r.remote_port.map(|p| p.to_string()).unwrap_or_default(),
        r.state.map(|s| s.to_string()).unwrap_or_default(),
    ]
}
