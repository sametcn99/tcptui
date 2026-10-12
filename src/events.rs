//! Keyboard and mouse event handling: translates crossterm events into
//! `App` state transitions. No rendering happens here.

use crossterm::event::{Event, KeyCode, KeyEventKind, KeyModifiers, MouseEvent, MouseEventKind};
use ratatui::layout::Rect;

use crate::app::{App, DisplayNode, Mode};
use crate::export::ExportFormat;

/// Whether the click is a double click (400 ms, same position).
const DOUBLE_CLICK_WINDOW_MS: u128 = 400;

pub fn handle_event(app: &mut App, event: Event, viewport: Rect) {
    match event {
        Event::Key(key) if key.kind == KeyEventKind::Press => {
            handle_key(app, key.code, key.modifiers, viewport)
        }
        Event::Mouse(mouse) => handle_mouse(app, mouse),
        _ => {}
    }
}

fn handle_key(app: &mut App, code: KeyCode, mods: KeyModifiers, viewport: Rect) {
    let ctrl = mods.contains(KeyModifiers::CONTROL);
    let shift = mods.contains(KeyModifiers::SHIFT);

    match app.mode {
        Mode::Filtering => filter_mode_key(app, code, ctrl),
        Mode::Searching => search_mode_key(app, code, ctrl),
        Mode::Confirm => confirm_mode_key(app, code),
        Mode::ProcessDetail => {
            let mut scroll = app.detail_scroll;
            scrollable_popup_key(app, code, &mut scroll);
            app.detail_scroll = scroll;
        }
        Mode::Whois => {
            let mut scroll = app.whois.as_ref().map_or(0, |w| w.scroll);
            scrollable_popup_key(app, code, &mut scroll);
            if let Some(w) = app.whois.as_mut() {
                w.scroll = scroll;
            }
        }
        Mode::Help => {
            let mut scroll = app.help_scroll;
            scrollable_popup_key(app, code, &mut scroll);
            app.help_scroll = scroll;
        }
        Mode::ColumnSetup => column_setup_key(app, code),
        Mode::Export => export_key(app, code),
        Mode::Stats | Mode::Log => stats_log_key(app, code),
        Mode::Normal => normal_mode_key(app, code, ctrl, shift, viewport),
    }
}

// ---------------------------------------------------------------------------
// Normal mode
// ---------------------------------------------------------------------------

fn normal_mode_key(app: &mut App, code: KeyCode, ctrl: bool, shift: bool, viewport: Rect) {
    let page = (viewport.height.saturating_sub(4)) as usize;
    match (code, ctrl, shift) {
        (KeyCode::Char('q'), false, _) | (KeyCode::Esc, false, _) => {
            app.should_quit = true;
        }
        (KeyCode::Char('c'), true, false) => app.copy_current_row(),
        (KeyCode::Char('c'), true, true) => app.copy_table(),
        (KeyCode::Char('f'), true, _) => {
            app.mode = Mode::Searching;
            app.search_input.clear();
        }
        (code, _, _) => shared_normal_key(app, code, page),
    }
}

fn shared_normal_key(app: &mut App, code: KeyCode, page: usize) {
    match code {
        KeyCode::Up | KeyCode::Char('k') => app.move_selection(-1),
        KeyCode::Down | KeyCode::Char('j') => app.move_selection(1),
        KeyCode::Left | KeyCode::Char('h') => toggle_expand(app, false),
        KeyCode::Right | KeyCode::Char('l') => toggle_expand(app, true),
        KeyCode::PageUp => app.page_move(true, page),
        KeyCode::PageDown => app.page_move(false, page),
        KeyCode::Home => app.selected = 0,
        KeyCode::End => app.selected = app.display_len().saturating_sub(1),
        KeyCode::Char('/') => {
            app.mode = Mode::Filtering;
            app.filter_input.clear();
        }
        KeyCode::Char('n') => app.search_next(true),
        KeyCode::Char('N') => app.search_next(false),
        KeyCode::Char('s') => app.cycle_sort(),
        KeyCode::Char('S') => app.reverse_sort(),
        KeyCode::Char('t') => {
            app.toggles.show_tcp = !app.toggles.show_tcp;
            app.refresh_display();
        }
        KeyCode::Char('u') => {
            app.toggles.show_udp = !app.toggles.show_udp;
            app.refresh_display();
        }
        KeyCode::Char('r') => app.toggle_resolve(),
        KeyCode::Char('U') => {
            // Shift+U: toggle unconnected endpoints
            app.toggles.show_unconnected = !app.toggles.show_unconnected;
            app.refresh_display();
        }
        KeyCode::Char('L') => {
            // Shift+L: toggle loopback visibility
            app.toggles.show_loopback = !app.toggles.show_loopback;
            app.refresh_display();
        }
        KeyCode::Char('+') | KeyCode::Char('=') => app.step_interval(false),
        KeyCode::Char('-') | KeyCode::Char('_') => app.step_interval(true),
        KeyCode::F(5) => app.request_refresh(),
        KeyCode::F(6) => app.toggle_watch(),
        KeyCode::Char('G') => app.toggle_grouped(),
        KeyCode::Char('c') => app.begin_confirm_close(),
        KeyCode::Char('K') => app.begin_confirm_kill(),
        KeyCode::Char('w') => app.request_whois(),
        KeyCode::Char('e') => {
            app.mode = Mode::Export;
        }
        KeyCode::Char('C') => {
            app.mode = Mode::ColumnSetup;
        }
        KeyCode::Char('i') => {
            app.mode = Mode::Stats;
        }
        KeyCode::Char('H') | KeyCode::Char('?') => {
            app.mode = Mode::Help;
            app.help_scroll = 0;
        }
        KeyCode::Char('g') => {
            app.mode = Mode::Log;
            app.log_scroll = app.event_log.len().saturating_sub(1);
        }
        KeyCode::Char(' ') => app.toggle_mark(),
        KeyCode::Enter => app.begin_detail(),
        KeyCode::Char('x') => {
            // Clear marks / filter / search in one stroke.
            if !app.marked.is_empty() {
                app.marked.clear();
            } else if app.filter.is_some() {
                app.clear_filter();
            } else if app.search.is_some() {
                app.search = None;
                app.search_input.clear();
            }
        }
        _ => {}
    }
}

fn toggle_expand(app: &mut App, expand: bool) {
    if !app.grouped {
        return;
    }
    if let Some(DisplayNode::Group { pid, .. }) = app.display.get(app.selected) {
        let pid = *pid;
        if expand {
            app.expanded.insert(pid);
        } else {
            app.expanded.remove(&pid);
        }
        app.refresh_display();
    }
}

// ---------------------------------------------------------------------------
// Input-line modes (filter / search)
// ---------------------------------------------------------------------------

fn filter_mode_key(app: &mut App, code: KeyCode, ctrl: bool) {
    match code {
        KeyCode::Enter => app.apply_filter_input(),
        KeyCode::Esc => {
            app.filter_input.clear();
            app.mode = Mode::Normal;
        }
        KeyCode::Backspace => app.filter_input.backspace(),
        KeyCode::Char('u') if ctrl => app.filter_input.clear(),
        KeyCode::Char('c') if ctrl => app.filter_input.clear(),
        KeyCode::Char(c) => app.filter_input.push(c),
        _ => {}
    }
}

fn search_mode_key(app: &mut App, code: KeyCode, ctrl: bool) {
    match code {
        KeyCode::Enter => app.apply_search_input(),
        KeyCode::Esc => {
            app.search_input.clear();
            app.mode = Mode::Normal;
        }
        KeyCode::Backspace => app.search_input.backspace(),
        KeyCode::Char('u') if ctrl => app.search_input.clear(),
        KeyCode::Char('c') if ctrl => app.search_input.clear(),
        KeyCode::Char(c) => app.search_input.push(c),
        _ => {}
    }
}

// ---------------------------------------------------------------------------
// Confirm / scrollable popups
// ---------------------------------------------------------------------------

fn confirm_mode_key(app: &mut App, code: KeyCode) {
    match code {
        KeyCode::Enter | KeyCode::Char('y') | KeyCode::Char('Y') => app.execute_confirm(),
        KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc | KeyCode::Char('q') => {
            app.confirm = None;
            app.mode = Mode::Normal;
        }
        _ => {}
    }
}

/// Generic scrolling used by detail/whois/help popups.
fn scrollable_popup_key(app: &mut App, code: KeyCode, scroll: &mut u16) {
    match code {
        KeyCode::Esc | KeyCode::Char('q') | KeyCode::Enter => {
            app.close_popup();
        }
        KeyCode::Up | KeyCode::Char('k') => *scroll = scroll.saturating_sub(1),
        KeyCode::Down | KeyCode::Char('j') => *scroll = scroll.saturating_add(1),
        KeyCode::PageUp => *scroll = scroll.saturating_sub(10),
        KeyCode::PageDown => *scroll = scroll.saturating_add(10),
        KeyCode::Home => *scroll = 0,
        KeyCode::End => *scroll = u16::MAX / 4,
        _ => {}
    }
}

// ---------------------------------------------------------------------------
// Column setup / export / stats / log
// ---------------------------------------------------------------------------

fn column_setup_key(app: &mut App, code: KeyCode) {
    let len = app.column_order.len();
    match code {
        KeyCode::Esc | KeyCode::Char('q') => {
            app.mode = Mode::Normal;
            app.save_config();
        }
        KeyCode::Up | KeyCode::Char('k') => {
            app.column_cursor = app.column_cursor.saturating_sub(1);
        }
        KeyCode::Down | KeyCode::Char('j') => {
            app.column_cursor = (app.column_cursor + 1).min(len.saturating_sub(1));
        }
        KeyCode::Char(' ') => {
            if let Some(col) = app.column_order.get(app.column_cursor).copied()
                && !app.column_hidden.remove(&col)
            {
                app.column_hidden.insert(col);
            }
        }
        KeyCode::Left | KeyCode::Char('h') => {
            if app.column_cursor > 0 {
                let c = app.column_cursor;
                app.column_order.swap(c - 1, c);
                app.column_cursor -= 1;
            }
        }
        KeyCode::Right | KeyCode::Char('l') => {
            if app.column_cursor + 1 < len {
                let c = app.column_cursor;
                app.column_order.swap(c, c + 1);
                app.column_cursor += 1;
            }
        }
        KeyCode::Char('+') | KeyCode::Char('=') => adjust_width(app, 2),
        KeyCode::Char('-') => adjust_width(app, -2),
        KeyCode::Char('r') => {
            // Reset to defaults
            app.column_order = crate::app::DEFAULT_COLUMN_ORDER.to_vec();
            app.column_hidden.clear();
            app.column_width.clear();
            app.column_cursor = 0;
        }
        _ => {}
    }
}

fn adjust_width(app: &mut App, delta: i16) {
    if let Some(col) = app.column_order.get(app.column_cursor).copied() {
        let current = *app.column_width.get(&col).unwrap_or(&col.default_width()) as i16;
        let next = (current + delta).clamp(3, 80) as u16;
        app.column_width.insert(col, next);
    }
}

fn export_key(app: &mut App, code: KeyCode) {
    match code {
        KeyCode::Esc | KeyCode::Char('q') => app.mode = Mode::Normal,
        KeyCode::Char('c') => app.export_sel.fmt = ExportFormat::Csv,
        KeyCode::Char('t') => app.export_sel.fmt = ExportFormat::Tsv,
        KeyCode::Char('j') => app.export_sel.fmt = ExportFormat::Json,
        KeyCode::Char('x') => app.export_sel.fmt = ExportFormat::Txt,
        KeyCode::Tab | KeyCode::Char('a') | KeyCode::Char('v') => {
            app.export_sel.all = !app.export_sel.all;
        }
        KeyCode::Enter | KeyCode::Char('e') => app.do_export(),
        _ => {}
    }
}

fn stats_log_key(app: &mut App, code: KeyCode) {
    match code {
        KeyCode::Esc | KeyCode::Char('q') | KeyCode::Char('i') => {
            app.mode = Mode::Normal;
        }
        KeyCode::Up | KeyCode::Char('k') => {
            if app.mode == Mode::Log {
                app.log_scroll = app.log_scroll.saturating_sub(1);
            }
        }
        KeyCode::Down | KeyCode::Char('j') => {
            if app.mode == Mode::Log {
                let max = app.event_log.len();
                app.log_scroll = (app.log_scroll + 1).min(max);
            }
        }
        KeyCode::Char('c') if app.mode == Mode::Log => {
            let text: String = app
                .event_log
                .iter()
                .map(|e| format!("{}  {}", e.at.format("%Y-%m-%d %H:%M:%S"), e.message))
                .collect::<Vec<_>>()
                .join("\n");
            match crate::clipboard::copy_text(&text) {
                Ok(()) => app.push_status("Event log copied"),
                Err(e) => app.push_status(format!("Clipboard error: {e}")),
            }
        }
        _ => {}
    }
}

// ---------------------------------------------------------------------------
// Mouse
// ---------------------------------------------------------------------------

fn handle_mouse(app: &mut App, mouse: MouseEvent) {
    match mouse.kind {
        MouseEventKind::ScrollUp => {
            if app.mode == Mode::Normal {
                app.offset = app.offset.saturating_sub(3);
                app.selected = app.selected.min(app.offset);
            } else {
                popup_scroll(app, -3);
            }
        }
        MouseEventKind::ScrollDown => {
            if app.mode == Mode::Normal {
                app.offset += 3;
                app.selected = app.selected.max(app.offset);
            } else {
                popup_scroll(app, 3);
            }
        }
        MouseEventKind::Down(crossterm::event::MouseButton::Left) => {
            handle_left_click(app, mouse.column, mouse.row, mouse.modifiers);
        }
        _ => {}
    }
}

fn popup_scroll(app: &mut App, delta: i32) {
    match app.mode {
        Mode::Help => {
            app.help_scroll = (app.help_scroll as i32 + delta).max(0) as u16;
        }
        Mode::ProcessDetail => {
            app.detail_scroll = (app.detail_scroll as i32 + delta).max(0) as u16;
        }
        Mode::Whois => {
            if let Some(w) = app.whois.as_mut() {
                w.scroll = (w.scroll as i32 + delta).max(0) as u16;
            }
        }
        Mode::Log => {
            let max = app.event_log.len() as i32;
            app.log_scroll = ((app.log_scroll as i32 + delta).max(0) as usize).min(max as usize);
        }
        _ => {}
    }
}

fn handle_left_click(app: &mut App, x: u16, y: u16, mods: KeyModifiers) {
    // Clicks inside popups are ignored (no hit-testing inside popup content).
    if app.mode != Mode::Normal {
        return;
    }

    let area = app.table_area;
    if area.height == 0 {
        return;
    }

    let now = std::time::Instant::now();
    let double = app
        .last_click
        .map(|(t, cx, cy)| t.elapsed().as_millis() < DOUBLE_CLICK_WINDOW_MS && cx == x && cy == y)
        .unwrap_or(false);
    app.last_click = Some((now, x, y));

    if y == area.y {
        // Header: sort by the clicked column; Shift appends a sort key.
        for (hx, hw, col) in &app.header_cells {
            if x >= *hx && x < *hx + *hw {
                let col = *col;
                let additive = mods.contains(KeyModifiers::SHIFT);
                app.set_sort_column(col, additive);
                return;
            }
        }
        return;
    }

    if let Some(idx) = app.row_at_screen_y(y) {
        app.selected = idx;
        if double {
            app.begin_detail();
        }
    }
}

impl App {
    pub fn close_popup(&mut self) {
        match self.mode {
            Mode::Whois => self.whois = None,
            Mode::ProcessDetail => self.detail_pid = None,
            _ => {}
        }
        self.mode = Mode::Normal;
    }
}
