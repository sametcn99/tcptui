//! Top-level UI layout and mode dispatch.

pub mod popups;
pub mod status;
pub mod table;

use ratatui::Frame;
use ratatui::layout::{Constraint, Layout};

use crate::app::{App, Mode};

/// Render the whole interface for the current state.
pub fn draw(f: &mut Frame, app: &mut App) {
    let chunks = Layout::vertical([
        Constraint::Length(1), // title bar
        Constraint::Min(3),    // table
        Constraint::Length(2), // footer
    ])
    .split(f.area());

    status::draw_title_bar(f, app, chunks[0]);
    table::draw(f, app, chunks[1]);
    status::draw_footer(f, app, chunks[2]);

    if app.mode != Mode::Normal {
        popups::draw_popup(f, app, f.area());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::{App, Mode};
    use crate::config::Config;
    use crate::events::handle_event;
    use crate::model::{ConnectionRow, Protocol, Snapshot};
    use crossterm::event::{Event, KeyCode, KeyEvent, KeyEventKind};
    use ratatui::Terminal;
    use std::collections::HashMap;
    use std::net::{IpAddr, Ipv4Addr};

    fn synthetic_snapshot() -> Snapshot {
        let rows = vec![
            ConnectionRow::new(
                Protocol::Tcp,
                IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
                5001,
                Some(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))),
                Some(443),
                Some(netstat2::TcpState::Established),
                42,
            ),
            ConnectionRow::new(
                Protocol::Udp,
                IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
                5353,
                None,
                None,
                None,
                7,
            ),
        ];
        Snapshot {
            taken_at: chrono::Local::now(),
            rows,
            processes: HashMap::new(),
            services: HashMap::new(),
        }
    }

    fn press(app: &mut App, c: char) {
        let ev = Event::Key(KeyEvent {
            code: KeyCode::Char(c),
            modifiers: crossterm::event::KeyModifiers::NONE,
            kind: KeyEventKind::Press,
            state: crossterm::event::KeyEventState::NONE,
        });
        let area = ratatui::layout::Rect::new(0, 0, 120, 30);
        handle_event(app, ev, area);
    }

    #[test]
    fn renders_flat_grouped_and_popups_without_panicking() {
        let mut app = App::new(Config::default());
        app.apply_snapshot(synthetic_snapshot());

        let backend = ratatui::backend::TestBackend::new(120, 30);
        let mut terminal = Terminal::new(backend).unwrap();

        // Flat view
        terminal.draw(|f| draw(f, &mut app)).unwrap();
        let buffer = terminal.backend().buffer().clone();
        let text = buffer
            .content
            .iter()
            .map(|c| c.symbol())
            .collect::<String>();
        assert!(text.contains("ESTABLISHED"));

        // Grouped view
        press(&mut app, 'G');
        terminal.draw(|f| draw(f, &mut app)).unwrap();

        // Help popup
        press(&mut app, 'H');
        assert_eq!(app.mode, Mode::Help);
        terminal.draw(|f| draw(f, &mut app)).unwrap();
        press(&mut app, 'q');
        assert_eq!(app.mode, Mode::Normal);

        // Filter mode with typing
        press(&mut app, '/');
        assert_eq!(app.mode, Mode::Filtering);
        press(&mut app, 'u');
        press(&mut app, 'd');
        terminal.draw(|f| draw(f, &mut app)).unwrap();
        // Enter applies; UDP rows survive, TCP row is filtered out.
        let enter = Event::Key(KeyEvent {
            code: KeyCode::Enter,
            modifiers: crossterm::event::KeyModifiers::NONE,
            kind: KeyEventKind::Press,
            state: crossterm::event::KeyEventState::NONE,
        });
        handle_event(&mut app, enter, ratatui::layout::Rect::new(0, 0, 120, 30));
        assert!(app.filter.is_some());
        assert!(app.visible.iter().all(|r| r.protocol == Protocol::Udp));

        // Column setup popup
        press(&mut app, 'C');
        assert_eq!(app.mode, Mode::ColumnSetup);
        terminal.draw(|f| draw(f, &mut app)).unwrap();
        press(&mut app, 'q');

        // Export popup
        press(&mut app, 'e');
        assert_eq!(app.mode, Mode::Export);
        terminal.draw(|f| draw(f, &mut app)).unwrap();
        press(&mut app, 'q');

        // Stats + log + whois-loading states render too.
        press(&mut app, 'i');
        terminal.draw(|f| draw(f, &mut app)).unwrap();
        press(&mut app, 'i');
        press(&mut app, 'g');
        terminal.draw(|f| draw(f, &mut app)).unwrap();
        press(&mut app, 'q');

        // Bandwidth chart popup, both series.
        press(&mut app, 'B');
        assert_eq!(app.mode, Mode::Chart);
        terminal.draw(|f| draw(f, &mut app)).unwrap();
        let tab = crossterm::event::Event::Key(crossterm::event::KeyEvent {
            code: KeyCode::Tab,
            modifiers: crossterm::event::KeyModifiers::NONE,
            kind: KeyEventKind::Press,
            state: crossterm::event::KeyEventState::NONE,
        });
        handle_event(&mut app, tab, ratatui::layout::Rect::new(0, 0, 120, 30));
        terminal.draw(|f| draw(f, &mut app)).unwrap();
        press(&mut app, 'q');

        // Rules popup with an alert rule added through the input flow.
        press(&mut app, 'A');
        assert_eq!(app.mode, Mode::Rules);
        press(&mut app, 'a');
        press(&mut app, 'p');
        press(&mut app, 'r');
        press(&mut app, 'o');
        press(&mut app, 't');
        press(&mut app, 'o');
        press(&mut app, '=');
        press(&mut app, 't');
        press(&mut app, 'c');
        press(&mut app, 'p');
        let enter = Event::Key(KeyEvent {
            code: KeyCode::Enter,
            modifiers: crossterm::event::KeyModifiers::NONE,
            kind: KeyEventKind::Press,
            state: crossterm::event::KeyEventState::NONE,
        });
        handle_event(&mut app, enter, ratatui::layout::Rect::new(0, 0, 120, 30));
        assert_eq!(app.alerts.len(), 1);
        terminal.draw(|f| draw(f, &mut app)).unwrap();
        press(&mut app, 'q');

        // Profiles popup: save the current view and re-apply it.
        press(&mut app, 'P');
        assert_eq!(app.mode, Mode::Profiles);
        press(&mut app, 's');
        for c in ['m', 'y', 'v', 'i', 'e', 'w'] {
            press(&mut app, c);
        }
        let enter_again = Event::Key(KeyEvent {
            code: KeyCode::Enter,
            modifiers: crossterm::event::KeyModifiers::NONE,
            kind: KeyEventKind::Press,
            state: crossterm::event::KeyEventState::NONE,
        });
        handle_event(
            &mut app,
            enter_again,
            ratatui::layout::Rect::new(0, 0, 120, 30),
        );
        assert_eq!(app.profiles.len(), 1);
        terminal.draw(|f| draw(f, &mut app)).unwrap();
        press(&mut app, 'q');

        // Settings popup: flip a toggle and render.
        press(&mut app, 'M');
        assert_eq!(app.mode, Mode::Settings);
        press(&mut app, 'j');
        press(&mut app, 'j');
        press(&mut app, ' ');
        terminal.draw(|f| draw(f, &mut app)).unwrap();
        press(&mut app, 'q');
    }
}
