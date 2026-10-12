//! tcptui binary: argument handling, terminal lifecycle and the main loop.

use std::io;

use anyhow::Result;
use crossterm::event::{
    self, DisableMouseCapture, EnableMouseCapture, Event, KeyboardEnhancementFlags,
    PopKeyboardEnhancementFlags, PushKeyboardEnhancementFlags,
};
use crossterm::execute;
use ratatui::{DefaultTerminal, init, restore};

use tcptui::app::{App, FilterKind};
use tcptui::args::{self, ParseOutcome};
use tcptui::config::Config;

fn main() -> Result<()> {
    let raw: Vec<String> = std::env::args().skip(1).collect();
    let (opts, outcome) = args::parse(&raw).unwrap_or_else(|e| {
        eprintln!("tcptui: {e}");
        eprintln!("{}", args::USAGE);
        std::process::exit(2);
    });
    match outcome {
        ParseOutcome::Help => {
            println!("{}", args::USAGE);
            return Ok(());
        }
        ParseOutcome::Version => {
            println!("tcptui {}", env!("CARGO_PKG_VERSION"));
            return Ok(());
        }
        ParseOutcome::Run => {}
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

    tcptui::net::ensure_wsa()?;

    let mut app = App::new(config);
    if let Some(text) = opts.filter.clone() {
        app.filter_input.value = text;
        app.apply_filter_input();
    }

    let mut terminal = init();
    execute!(
        io::stdout(),
        EnableMouseCapture,
        PushKeyboardEnhancementFlags(KeyboardEnhancementFlags::DISAMBIGUATE_ESCAPE_CODES)
    )?;

    let result = run(&mut terminal, &mut app);

    execute!(
        io::stdout(),
        PopKeyboardEnhancementFlags,
        DisableMouseCapture
    )?;
    restore();
    app.save_config();

    result
}

fn run(terminal: &mut DefaultTerminal, app: &mut App) -> Result<()> {
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
