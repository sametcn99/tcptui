//! tcptui binary: argument handling, terminal lifecycle and the main loop.

use std::io::{self, IsTerminal};

use anyhow::Result;
use crossterm::event::{
    self, DisableMouseCapture, EnableMouseCapture, Event, KeyboardEnhancementFlags,
    PopKeyboardEnhancementFlags, PushKeyboardEnhancementFlags,
};
use crossterm::execute;
use ratatui::{DefaultTerminal, try_init, try_restore};

use tcptui::app::{App, FilterKind};
use tcptui::args::{self, ParseOutcome};
use tcptui::config::Config;

fn main() {
    if let Err(e) = run() {
        // Keep the console window open after a fatal error so that
        // double-clicked launches can actually show the message.
        eprintln!("tcptui: {e}");
        if cfg!(windows) && io::stdin().is_terminal() {
            eprintln!("Press Enter to close...");
            let _ = io::stdin().read_line(&mut String::new());
        }
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let raw: Vec<String> = std::env::args().skip(1).collect();
    let (opts, outcome) = args::parse(&raw).unwrap_or_else(|e| {
        eprintln!("tcptui: {e}");
        eprintln!("{}", args::usage());
        std::process::exit(2);
    });
    match outcome {
        ParseOutcome::Help => {
            println!("{}", args::usage());
            return Ok(());
        }
        ParseOutcome::Version => {
            println!("tcptui {}", env!("CARGO_PKG_VERSION"));
            return Ok(());
        }
        ParseOutcome::Run => {}
    }

    if (opts.etw && !cfg!(windows)) || (opts.trace && tcptui::trace::SOURCE.is_none()) {
        eprintln!("tcptui: TCP tracing is unavailable with this flag on this build (see --help)");
        std::process::exit(2);
    }

    // The startup filter must parse cleanly before we enter the TUI.
    if let Some(text) = &opts.filter
        && let Err(e) = FilterKind::parse(text)
    {
        eprintln!("tcptui: invalid --filter: {e}");
        std::process::exit(2);
    }

    let mut config = Config::load();
    args::apply_overrides(&opts, &mut config.view);

    tcptui::net::initialize()?;

    // One-shot text render of a live frame (--dump-frame): no TUI.
    if let Some(file) = &opts.dump_frame {
        let (w, h) = opts.frame_size.unwrap_or((120, 30));
        match tcptui::app::dump_frame(std::path::Path::new(file), w, h, config) {
            Ok(()) => {
                println!("wrote {file} ({w}x{h})");
                return Ok(());
            }
            Err(e) => {
                eprintln!("tcptui: dump-frame failed: {e}");
                std::process::exit(1);
            }
        }
    }

    anyhow::ensure!(
        io::stdin().is_terminal() && io::stdout().is_terminal(),
        "the interactive UI needs a terminal; use tcpvcon or --dump-frame for redirected output"
    );
    let tracing = opts.trace || opts.etw || (cfg!(windows) && config.etw.enabled);
    let (session, receiver, trace_error) = if tracing {
        match tcptui::trace::start() {
            Ok((session, receiver)) => (Some(session), Some(receiver), None),
            Err(error) => (None, None, Some(error)),
        }
    } else {
        (None, None, None)
    };

    let mut app = App::new(config, receiver);
    app.trace_session = session;
    if let Some(error) = trace_error {
        let message = format!("TCP trace unavailable; using snapshots: {error}");
        app.log_event(message.clone());
        app.push_status(message);
    }
    if let Some(text) = opts.filter.clone() {
        app.filter_input.value = text;
        app.apply_filter_input();
    }

    // Kitty keyboard enhancements only exist on modern terminals; the
    // legacy Windows console rejects them outright.
    let enhanced = crossterm::terminal::supports_keyboard_enhancement().unwrap_or(false);

    let mut terminal = match try_init() {
        Ok(terminal) => terminal,
        Err(error) => {
            let _ = try_restore();
            return Err(error.into());
        }
    };
    let setup = if enhanced {
        execute!(
            io::stdout(),
            EnableMouseCapture,
            PushKeyboardEnhancementFlags(KeyboardEnhancementFlags::DISAMBIGUATE_ESCAPE_CODES)
        )
    } else {
        execute!(io::stdout(), EnableMouseCapture)
    };

    let result = setup
        .map_err(anyhow::Error::from)
        .and_then(|()| run_tui(&mut terminal, &mut app));
    let cleanup = if enhanced {
        execute!(
            io::stdout(),
            PopKeyboardEnhancementFlags,
            DisableMouseCapture
        )
    } else {
        execute!(io::stdout(), DisableMouseCapture)
    };
    let restored = try_restore();
    if result.is_ok() {
        app.save_config();
    }
    result
        .and(cleanup.map_err(Into::into))
        .and(restored.map_err(Into::into))
}

fn run_tui(terminal: &mut DefaultTerminal, app: &mut App) -> Result<()> {
    loop {
        app.poll_channels();
        terminal.draw(|f| tcptui::ui::draw(f, app))?;

        if event::poll(std::time::Duration::from_millis(100))? {
            // Drain everything already queued in this batch.
            loop {
                let ev: Event = event::read()?;
                let viewport = terminal.get_frame().area();
                tcptui::events::handle_event(app, ev, viewport);
                if !event::poll(std::time::Duration::ZERO)? {
                    break;
                }
            }
        }

        if app.should_quit {
            return Ok(());
        }
    }
}
