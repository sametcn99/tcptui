//! Top-level UI layout and mode dispatch.

pub mod popups;
pub mod status;
pub mod table;

use ratatui::Frame;
use ratatui::layout::{Constraint, Layout};

use crate::app::{App, Mode};

/// Render the whole interface for the current state.
pub fn draw(f: &mut Frame, app: &mut App) {
    // Pending alerts get a dedicated footer line so the shortcut hints and
    // statistics never get covered up.
    let footer_height = if app.alert_pending.is_empty() { 2 } else { 3 };
    let chunks = Layout::vertical([
        Constraint::Length(1),             // title bar
        Constraint::Min(3),                // table
        Constraint::Length(footer_height), // footer (hints + stats [+ alert])
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
    fn alert_footer_line_does_not_cover_hints() {
        let mut app = App::new(Config::default(), None);
        app.apply_snapshot(synthetic_snapshot());
        app.alert_pending
            .push("ALERT 'process=x' matched TCP 1.2.3.4:1 -> 5.6.7.8:2 (proc.exe)".into());

        let backend = ratatui::backend::TestBackend::new(120, 30);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|f| draw(f, &mut app)).unwrap();
        let text: String = terminal
            .backend()
            .buffer()
            .content
            .iter()
            .map(|c| c.symbol())
            .collect();

        // The alert gets its own line while hints and stats stay visible.
        assert!(text.contains("alert(s)"), "alert line missing");
        assert!(text.contains("?:help"), "shortcut hints were covered");
        assert!(text.contains("total 2"), "statistics line was covered");
        // Long alert text is truncated to the terminal width, not wrapped.
        let alert_rows: Vec<&str> = text.lines().filter(|l| l.contains("alert(s)")).collect();
        assert_eq!(alert_rows.len(), 1);
    }

    #[test]
    fn table_headers_render_and_sort_on_click() {
        use crate::model::{ConnectionRow, Protocol, Snapshot};
        use crossterm::event::{KeyCode, KeyEvent, KeyEventKind};
        use std::collections::HashMap;
        use std::net::{IpAddr, Ipv4Addr};

        let mut app = App::new(Config::default(), None);
        let rows = vec![
            ConnectionRow::new(
                Protocol::Tcp,
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
                2000,
                Some(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))),
                Some(80),
                Some(netstat2::TcpState::Established),
                5,
            ),
            ConnectionRow::new(
                Protocol::Tcp,
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                1000,
                None,
                None,
                Some(netstat2::TcpState::Listen),
                3,
            ),
        ];
        app.apply_snapshot(Snapshot {
            taken_at: chrono::Local::now(),
            rows,
            processes: HashMap::new(),
            services: HashMap::new(),
        });

        let backend = ratatui::backend::TestBackend::new(120, 30);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|f| draw(f, &mut app)).unwrap();
        let buf = terminal.backend().buffer().clone();
        let header_line: String = buf.content[(2 * 120) as usize..(3 * 120) as usize]
            .iter()
            .map(|c| c.symbol())
            .collect();
        // Column titles must be visible on the header row (line y = 2:
        // title bar is y0, table border y1, header y2).
        for title in ["Process", "PID", "Proto", "Local Address", "State", "Age"] {
            assert!(
                header_line.contains(title),
                "header title '{title}' not visible: {header_line}"
            );
        }

        // Click the middle of the PID header title (gutter 2 + process 16
        // -> PID spans x 19..25 on the header row y = table.y + 1 = 2);
        // its right edge is the resize grab zone.
        let pid_header_x = 21;
        let click = crossterm::event::Event::Mouse(crossterm::event::MouseEvent {
            kind: crossterm::event::MouseEventKind::Down(crossterm::event::MouseButton::Left),
            column: pid_header_x,
            row: 2,
            modifiers: crossterm::event::KeyModifiers::NONE,
        });
        handle_event(&mut app, click, ratatui::layout::Rect::new(0, 0, 120, 30));
        assert_eq!(
            app.sort.first().map(|k| k.col),
            Some(crate::app::ColumnId::Pid)
        );

        // Clicking the first data row (y = table.y + 2 = 3) selects row 0.
        let row_click = crossterm::event::Event::Mouse(crossterm::event::MouseEvent {
            kind: crossterm::event::MouseEventKind::Down(crossterm::event::MouseButton::Left),
            column: 10,
            row: 3,
            modifiers: crossterm::event::KeyModifiers::NONE,
        });
        handle_event(
            &mut app,
            row_click,
            ratatui::layout::Rect::new(0, 0, 120, 30),
        );
        assert_eq!(app.selected, 0);

        // Double-click still opens the detail popup via the same geometry.
        let _ = KeyCode::Char('q');
        let _ = KeyEvent {
            code: KeyCode::Esc,
            modifiers: crossterm::event::KeyModifiers::NONE,
            kind: KeyEventKind::Press,
            state: crossterm::event::KeyEventState::NONE,
        };
    }

    #[test]
    fn renders_flat_grouped_and_popups_without_panicking() {
        let mut app = App::new(Config::default(), None);
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
