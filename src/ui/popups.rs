//! Popup overlays: help, confirmations, process detail, whois, column
//! setup, export chooser, statistics and the event log.

use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, List, ListItem, ListState, Paragraph, Wrap};

use crate::app::{App, Mode};
use crate::export::ExportFormat;

/// Centered rect with the given percentage of the screen.
fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let popup_layout = Layout::vertical([
        Constraint::Percentage((100 - percent_y) / 2),
        Constraint::Percentage(percent_y),
        Constraint::Percentage((100 - percent_y) / 2),
    ])
    .split(r);

    Layout::horizontal([
        Constraint::Percentage((100 - percent_x) / 2),
        Constraint::Percentage(percent_x),
        Constraint::Percentage((100 - percent_x) / 2),
    ])
    .split(popup_layout[1])[1]
}

pub fn draw_popup(f: &mut Frame, app: &App, area: Rect) {
    match app.mode {
        Mode::Help => draw_help(f, app, area),
        Mode::Confirm => draw_confirm(f, app, area),
        Mode::ProcessDetail => draw_detail(f, app, area),
        Mode::Whois => draw_whois(f, app, area),
        Mode::ColumnSetup => draw_column_setup(f, app, area),
        Mode::Export => draw_export(f, app, area),
        Mode::Stats => draw_stats(f, app, area),
        Mode::Log => draw_log(f, app, area),
        _ => {}
    }
}

fn popup_block(title: &str, app: &App) -> Block<'static> {
    Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(app.theme.accent))
        .title(Span::styled(
            format!(" {title} "),
            Style::default().add_modifier(Modifier::BOLD),
        ))
}

fn draw_help(f: &mut Frame, app: &App, area: Rect) {
    let rect = centered_rect(70, 85, area);
    let help = [
        ("Navigation", ""),
        ("Up/Down, j/k", "move selection"),
        ("PgUp/PgDn, Home/End", "scroll"),
        ("Space", "mark/unmark rows (batch actions)"),
        ("Enter", "process details (double-click too)"),
        ("Left/Right, h/l", "collapse/expand group (grouped view)"),
        ("", ""),
        ("View", ""),
        ("/", "filter (prefix re: for regex, Esc clears)"),
        ("Ctrl+F then n/N", "search, next/previous match"),
        ("s / S", "cycle sort column / reverse direction"),
        ("click header", "sort by column (Shift: add key)"),
        ("t / u", "toggle TCP / UDP visibility"),
        ("U", "toggle unconnected endpoints (listening, UDP)"),
        ("L", "toggle loopback visibility"),
        ("r", "toggle hostname resolution"),
        ("G", "toggle grouped-by-process view"),
        ("+ / -", "refresh interval faster/slower"),
        ("F5", "refresh now"),
        ("F6", "watch selected process"),
        ("C", "column setup (show/hide, width, order)"),
        ("i", "statistics"),
        ("g", "event log (opened/closed/user events)"),
        ("", ""),
        ("Actions", ""),
        ("c", "close selected/marked ESTABLISHED connection(s)"),
        ("K", "end process(es) of selected/marked rows"),
        ("w", "whois lookup of remote address"),
        ("e", "export table (CSV/TSV/JSON/TXT)"),
        ("Ctrl+C", "copy current row to clipboard"),
        ("Ctrl+Shift+C", "copy visible table (TSV)"),
        ("x", "clear marks/filter/search"),
        ("q / Esc", "quit (close popup first)"),
    ];
    let lines: Vec<Line> = help
        .iter()
        .map(|(k, v)| {
            if v.is_empty() {
                Line::from(Span::styled(
                    *k,
                    Style::default()
                        .fg(app.theme.accent)
                        .add_modifier(Modifier::BOLD),
                ))
            } else {
                Line::from(vec![
                    Span::styled(format!("{k:<24}"), Style::default().fg(app.theme.normal)),
                    Span::raw(v.to_string()),
                ])
            }
        })
        .collect();
    let paragraph = Paragraph::new(lines)
        .block(popup_block("Help — tcptui", app))
        .wrap(Wrap { trim: false })
        .scroll((app.help_scroll, 0));
    f.render_widget(Clear, rect);
    f.render_widget(paragraph, rect);
}

fn draw_confirm(f: &mut Frame, app: &App, area: Rect) {
    let rect = centered_rect(60, 40, area);
    let text = app
        .confirm
        .as_ref()
        .map(|c| c.describe())
        .unwrap_or_else(|| "Nothing to confirm".into());
    let lines: Vec<Line> = text
        .lines()
        .map(|l| {
            Line::from(Span::styled(
                l.to_string(),
                Style::default().fg(app.theme.normal),
            ))
        })
        .chain(std::iter::once(Line::from("")))
        .chain(std::iter::once(Line::from(Span::styled(
            "Enter: confirm    Esc/n: cancel",
            Style::default()
                .fg(app.theme.changed)
                .add_modifier(Modifier::BOLD),
        ))))
        .collect();
    let paragraph = Paragraph::new(lines)
        .block(popup_block("Confirm action", app))
        .wrap(Wrap { trim: true });
    f.render_widget(Clear, rect);
    f.render_widget(paragraph, rect);
}

fn draw_detail(f: &mut Frame, app: &App, area: Rect) {
    let rect = centered_rect(75, 80, area);
    let lines: Vec<Line> = app
        .detail_lines
        .iter()
        .map(|l| {
            Line::from(Span::styled(
                l.clone(),
                Style::default().fg(app.theme.normal),
            ))
        })
        .collect();
    let paragraph = Paragraph::new(lines)
        .block(popup_block(
            &format!("Process details — PID {}", app.detail_pid.unwrap_or(0)),
            app,
        ))
        .wrap(Wrap { trim: false })
        .scroll((app.detail_scroll, 0));
    f.render_widget(Clear, rect);
    f.render_widget(paragraph, rect);
}

fn draw_whois(f: &mut Frame, app: &App, area: Rect) {
    let rect = centered_rect(70, 80, area);
    let Some(state) = &app.whois else {
        return;
    };
    let body: Vec<Line> = if state.loading {
        vec![Line::from(Span::styled(
            format!("Querying whois for {} …", state.addr),
            Style::default().fg(app.theme.changed),
        ))]
    } else {
        state
            .text
            .as_deref()
            .unwrap_or("(no data)")
            .lines()
            .map(|l| {
                Line::from(Span::styled(
                    l.to_string(),
                    Style::default().fg(app.theme.normal),
                ))
            })
            .collect()
    };
    let paragraph = Paragraph::new(body)
        .block(popup_block(&format!("Whois — {}", state.addr), app))
        .wrap(Wrap { trim: false })
        .scroll((state.scroll, 0));
    f.render_widget(Clear, rect);
    f.render_widget(paragraph, rect);
}

fn draw_column_setup(f: &mut Frame, app: &App, area: Rect) {
    let rect = centered_rect(60, 70, area);
    let mut items: Vec<ListItem> = Vec::new();
    for (idx, col) in app.column_order.iter().enumerate() {
        let hidden = app.column_hidden.contains(col);
        let width = *app.column_width.get(col).unwrap_or(&col.default_width());
        let marker = if hidden { " [hidden]" } else { "" };
        let style = if idx == app.column_cursor {
            Style::default()
                .fg(app.theme.selected_fg)
                .bg(app.theme.selected_bg)
                .add_modifier(Modifier::BOLD)
        } else if hidden {
            Style::default().fg(app.theme.dim)
        } else {
            Style::default().fg(app.theme.normal)
        };
        items.push(ListItem::new(Line::from(Span::styled(
            format!("{:<16} w={:<3}{}", col.header(), width, marker),
            style,
        ))));
    }
    items.push(ListItem::new(Line::from("")));
    items.push(ListItem::new(Line::from(Span::styled(
        "Space:show/hide  ←/→:move  +/-:width  r:reset  Esc:close&save",
        Style::default().fg(app.theme.changed),
    ))));
    let list = List::new(items)
        .block(popup_block("Column setup", app))
        .highlight_style(Style::default().bg(app.theme.selected_bg));
    let mut state = ListState::default();
    state.select(Some(app.column_cursor));
    f.render_widget(Clear, rect);
    f.render_stateful_widget(list, rect, &mut state);
}

fn draw_export(f: &mut Frame, app: &App, area: Rect) {
    let rect = centered_rect(50, 30, area);
    let sel = app.export_sel;
    let fmt_line = |fmt: ExportFormat| -> String {
        let mark = if sel.fmt == fmt { "[x] " } else { "[ ] " };
        format!("{mark}{}", fmt.name().to_uppercase())
    };
    let lines = vec![
        Line::from(Span::styled(
            "Export format",
            Style::default()
                .fg(app.theme.accent)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(fmt_line(ExportFormat::Csv)),
        Line::from(fmt_line(ExportFormat::Tsv)),
        Line::from(fmt_line(ExportFormat::Json)),
        Line::from(fmt_line(ExportFormat::Txt)),
        Line::from(""),
        Line::from(format!(
            "Scope: {} (Tab toggles)",
            if sel.all {
                "all endpoints"
            } else {
                "visible rows"
            }
        )),
        Line::from(""),
        Line::from(Span::styled(
            "c/t/j/x:format  Tab:scope  Enter:export  Esc:cancel",
            Style::default().fg(app.theme.changed),
        )),
    ];
    let paragraph = Paragraph::new(lines).block(popup_block("Export", app));
    f.render_widget(Clear, rect);
    f.render_widget(paragraph, rect);
}

fn draw_stats(f: &mut Frame, app: &App, area: Rect) {
    let rect = centered_rect(55, 60, area);

    // Top processes by endpoint count.
    let mut by_proc: std::collections::BTreeMap<String, usize> = Default::default();
    for r in &app.rows {
        *by_proc.entry(r.process_display()).or_default() += 1;
    }
    let mut top: Vec<(String, usize)> = by_proc.into_iter().collect();
    top.sort_by_key(|(_, count)| std::cmp::Reverse(*count));

    let mut lines = vec![
        Line::from(Span::styled(
            "Endpoint statistics",
            Style::default()
                .fg(app.theme.accent)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from(format!("Total endpoints : {}", app.stats.total)),
        Line::from(format!("TCP             : {}", app.stats.tcp)),
        Line::from(format!("  ESTABLISHED   : {}", app.stats.established)),
        Line::from(format!("  LISTEN        : {}", app.stats.listening)),
        Line::from(format!("  TIME_WAIT     : {}", app.stats.time_wait)),
        Line::from(format!("  CLOSE_WAIT    : {}", app.stats.close_wait)),
        Line::from(format!("UDP             : {}", app.stats.udp)),
        Line::from(format!(
            "Uptime          : {}s ({} snapshots)",
            app.started.elapsed().as_secs(),
            app.snapshot_count
        )),
        Line::from(""),
        Line::from(Span::styled(
            "Top processes",
            Style::default()
                .fg(app.theme.accent)
                .add_modifier(Modifier::BOLD),
        )),
    ];
    for (name, count) in top.iter().take(10) {
        lines.push(Line::from(format!("{count:>4}  {name}")));
    }
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "Esc/i: close",
        Style::default().fg(app.theme.changed),
    )));
    let paragraph = Paragraph::new(lines)
        .block(popup_block("Statistics", app))
        .wrap(Wrap { trim: false });
    f.render_widget(Clear, rect);
    f.render_widget(paragraph, rect);
}

fn draw_log(f: &mut Frame, app: &App, area: Rect) {
    let rect = centered_rect(80, 80, area);
    let total = app.event_log.len();
    let height = rect.height.saturating_sub(2) as usize;
    // Keep the newest entries visible; respect manual scrolling.
    let max_scroll = total.saturating_sub(height);
    let scroll = app.log_scroll.min(max_scroll);
    let visible_slice: Vec<ListItem> = app
        .event_log
        .iter()
        .skip(scroll)
        .take(height)
        .map(|e| {
            let (color, msg) = if e.message.starts_with("OPEN") {
                (app.theme.new, e.message.clone())
            } else if e.message.starts_with("CLOSE") {
                (app.theme.deleted, e.message.clone())
            } else {
                (app.theme.changed, e.message.clone())
            };
            ListItem::new(Line::from(Span::styled(
                format!("{}  {}", e.at.format("%H:%M:%S"), msg),
                Style::default().fg(color),
            )))
        })
        .collect();
    let list = List::new(visible_slice).block(popup_block(
        &format!("Event log — {total} entries (c: copy, j/k: scroll, Esc: close)"),
        app,
    ));
    f.render_widget(Clear, rect);
    f.render_widget(list, rect);
}
