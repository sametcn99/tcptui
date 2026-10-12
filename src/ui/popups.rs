//! Popup overlays: help, confirmations, process detail, whois, column
//! setup, export chooser, statistics and the event log.

use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::symbols::Marker;
use ratatui::text::{Line, Span};
use ratatui::widgets::{
    Axis, Block, Borders, Chart, Clear, Dataset, GraphType, List, ListItem, ListState, Paragraph,
    Wrap,
};

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
        Mode::SortSetup => draw_sort_setup(f, app, area),
        Mode::Export => draw_export(f, app, area),
        Mode::Stats => draw_stats(f, app, area),
        Mode::Log => draw_log(f, app, area),
        Mode::Chart => draw_chart(f, app, area),
        Mode::Rules => draw_rules(f, app, area),
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
    let rect = centered_rect(70, 90, area);
    let help = [
        ("Navigation", ""),
        ("Up/Down, j/k", "move selection"),
        ("PgUp/PgDn, Home/End", "scroll"),
        ("Space", "mark/unmark rows (batch actions)"),
        ("Shift+Up/Down/PgUp/PgDn", "mark a range of rows"),
        ("Enter", "process details (double-click too)"),
        ("Left/Right, h/l", "collapse/expand group (grouped view)"),
        ("", ""),
        ("Monitoring", ""),
        ("B", "bandwidth chart (Tab: total/selected)"),
        ("A", "rules: alerts + coloring (Tab: sections)"),
        ("alerts", "fire when a NEW endpoint matches an expression"),
        ("colors", "Wireshark-style row colors by expression"),
        ("", ""),
        ("Filtering", ""),
        ("/", "filter prompt (Up/Down: history)"),
        ("1-8", "presets: 1 tcp  2 udp  3 established  4 listen"),
        ("", "5 loopback  6 non-loopback  7 new  8 clear"),
        ("Ctrl+F then n/N", "search, next/previous match"),
        ("", ""),
        ("Filter syntax", ""),
        (
            "process=chrome",
            "field filters; fields: process path pid proto",
        ),
        ("", "state laddr raddr addr lport rport port service"),
        ("", "tx rx change loopback connected"),
        ("state=established", "= == != > >= < <= :  (contains)"),
        ("tx>1MB", "byte units for tx/rx (kb/mb/gb)"),
        ("laddr=192.168.*", "wildcards * and ?"),
        ("process~=^chrome", "regex with =~ / !~"),
        ("a and (b or not c)", "boolean logic, parentheses; && || !"),
        ("chrome", "bare text still searches every field"),
        ("", ""),
        ("Sorting", ""),
        ("s / S", "cycle sort column / reverse direction"),
        ("o", "sort order editor (multi-key, directions)"),
        ("click header", "sort by column (Shift: add key)"),
        ("", ""),
        ("View", ""),
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

/// Multi-key sort order editor (`o`).
fn draw_sort_setup(f: &mut Frame, app: &App, area: Rect) {
    let rect = centered_rect(55, 65, area);
    let mut items: Vec<ListItem> = Vec::new();

    items.push(ListItem::new(Line::from(Span::styled(
        "Sort priority (top of the table applies first)",
        Style::default()
            .fg(app.theme.accent)
            .add_modifier(Modifier::BOLD),
    ))));
    items.push(ListItem::new(Line::from("")));

    for (idx, col) in app.sortable_columns().iter().enumerate() {
        let pos = app.sort.iter().position(|k| k.col == *col);
        let line = match pos {
            Some(p) => {
                let key = &app.sort[p];
                format!(
                    "{} {:<2} {:<16} {}",
                    p + 1,
                    if key.desc { '↓' } else { '↑' },
                    col.header(),
                    if p == 0 { "(primary)" } else { "" }
                )
            }
            None => format!("  ·  {:<16}", col.header()),
        };
        let style = if idx == app.sort_cursor {
            Style::default()
                .fg(app.theme.selected_fg)
                .bg(app.theme.selected_bg)
                .add_modifier(Modifier::BOLD)
        } else if pos.is_some() {
            Style::default().fg(app.theme.normal)
        } else {
            Style::default().fg(app.theme.dim)
        };
        items.push(ListItem::new(Line::from(Span::styled(line, style))));
    }

    items.push(ListItem::new(Line::from("")));
    items.push(ListItem::new(Line::from(Span::styled(
        "Space:toggle/add  x:remove  </>:priority  r:reset  Esc:close&save",
        Style::default().fg(app.theme.changed),
    ))));

    let list = List::new(items).block(popup_block("Sort order", app));
    f.render_widget(Clear, rect);
    f.render_widget(list, rect);
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

    // Top talkers by transferred bytes (EStats); hidden when unavailable.
    let mut traffic: std::collections::HashMap<String, (u64, u64)> = Default::default();
    for r in &app.visible {
        if let (Some(tx), Some(rx)) = (r.tx_bytes, r.rx_bytes) {
            let e = traffic.entry(r.process_display()).or_default();
            e.0 += tx;
            e.1 += rx;
        }
    }
    let mut talkers: Vec<(String, u64, u64)> = traffic
        .into_iter()
        .map(|(name, (tx, rx))| (name, tx, rx))
        .collect();
    talkers.sort_by_key(|(_, tx, rx)| std::cmp::Reverse(tx + rx));
    if !talkers.is_empty() && talkers.iter().any(|(_, tx, rx)| tx + rx > 0) {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            "Top processes by traffic",
            Style::default()
                .fg(app.theme.accent)
                .add_modifier(Modifier::BOLD),
        )));
        for (name, tx, rx) in talkers.iter().take(10) {
            lines.push(Line::from(format!(
                "↑{:<9} ↓{:<9} {}",
                crate::model::format_bytes(*tx),
                crate::model::format_bytes(*rx),
                name
            )));
        }
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

/// Bandwidth chart popup (`B`): rolling per-interval Tx/Rx deltas.
fn draw_chart(f: &mut Frame, app: &App, area: Rect) {
    use crate::app::BwView;
    use crate::model::format_bytes;

    let rect = centered_rect(80, 55, area);
    let series = match app.bw_view {
        BwView::Total => &app.bw_total,
        BwView::Selected => &app.bw_selected,
    };
    let tx_points: Vec<(f64, f64)> = series
        .iter()
        .enumerate()
        .map(|(i, (t, _))| (i as f64, *t as f64))
        .collect();
    let rx_points: Vec<(f64, f64)> = series
        .iter()
        .enumerate()
        .map(|(i, (_, r))| (i as f64, *r as f64))
        .collect();

    let peak = series.iter().map(|(t, r)| (*t).max(*r)).max().unwrap_or(0);
    let y_max = if peak == 0 {
        1024.0
    } else {
        peak as f64 * 1.15
    };
    let x_max = series.len().max(2) as f64;

    let tx: u64 = series.iter().map(|(t, _)| *t).sum();
    let rx: u64 = series.iter().map(|(_, r)| *r).sum();
    let n = series.len().max(1) as u64;

    let subject = match (
        app.bw_view,
        app.bw_selected_id
            .as_ref()
            .and_then(|id| app.rows.iter().find(|r| &r.id == id)),
    ) {
        (BwView::Selected, Some(row)) => {
            format!(
                "selected: {} {} -> {}",
                row.process_display(),
                row.local_display(),
                row.remote_display()
            )
        }
        (BwView::Selected, None) => "selected endpoint (gone)".to_string(),
        _ => "total system".to_string(),
    };
    let title = format!(
        "Bandwidth · {} · avg ↑{}/s ↓{}/s · Tab: switch series",
        subject,
        format_bytes(tx / n),
        format_bytes(rx / n),
    );

    let datasets = vec![
        Dataset::default()
            .name(format!("Tx {}", format_bytes(tx)))
            .marker(Marker::Braille)
            .graph_type(GraphType::Line)
            .style(Style::default().fg(app.theme.new))
            .data(&tx_points),
        Dataset::default()
            .name(format!("Rx {}", format_bytes(rx)))
            .marker(Marker::Braille)
            .graph_type(GraphType::Line)
            .style(Style::default().fg(app.theme.changed))
            .data(&rx_points),
    ];

    let x_labels = vec!["-2m".to_string(), "-1m".to_string(), "now".to_string()];
    let y_labels = vec![
        "0".to_string(),
        format_bytes((y_max / 2.0) as u64),
        format_bytes(peak.max(1)),
    ];

    let mut chart = Chart::new(datasets)
        .x_axis(
            Axis::default()
                .title("time")
                .bounds([0.0, x_max])
                .labels(x_labels),
        )
        .y_axis(
            Axis::default()
                .title("bytes/interval")
                .bounds([0.0, y_max])
                .labels(y_labels),
        );
    if !app.estats_enabled {
        chart = chart.block(
            popup_block(&title, app)
                .title(Span::styled(
                    "  [EStats disabled — enable in settings (M)]  ",
                    Style::default().fg(app.theme.deleted),
                ))
                .title_bottom(Span::styled(
                    "Esc: close    Tab: total/selected",
                    Style::default().fg(app.theme.changed),
                )),
        );
    } else {
        chart = chart.block(popup_block(&title, app).title_bottom(Span::styled(
            "Esc: close    Tab: total/selected",
            Style::default().fg(app.theme.changed),
        )));
    }
    f.render_widget(Clear, rect);
    f.render_widget(chart, rect);
}

/// Rules popup (`A`): alert rules and coloring rules in two tabs, with an
/// inline input for adding new rules.
fn draw_rules(f: &mut Frame, app: &App, area: Rect) {
    use crate::app::RulesTab;
    let rect = centered_rect(65, 70, area);

    let mut items: Vec<ListItem> = Vec::new();
    let (tab_name, other_name) = match app.rules_tab {
        RulesTab::Alerts => ("Alerts", "Colors"),
        RulesTab::Colors => ("Colors", "Alerts"),
    };
    items.push(ListItem::new(Line::from(vec![
        Span::styled(
            format!(" [{tab_name}] "),
            Style::default()
                .fg(app.theme.selected_fg)
                .bg(app.theme.accent)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            format!(" {other_name} "),
            Style::default().fg(app.theme.dim),
        ),
        Span::styled("  (Tab switches)", Style::default().fg(app.theme.dim)),
    ])));
    items.push(ListItem::new(Line::from("")));

    match app.rules_tab {
        RulesTab::Alerts => {
            if app.alerts.is_empty() {
                items.push(ListItem::new(Line::from(Span::styled(
                    "No alert rules. Press 'a' to add one.",
                    Style::default().fg(app.theme.dim),
                ))));
            }
            for (idx, a) in app.alerts.iter().enumerate() {
                let style = if idx == app.rules_cursor {
                    Style::default()
                        .fg(app.theme.selected_fg)
                        .bg(app.theme.selected_bg)
                        .add_modifier(Modifier::BOLD)
                } else if a.enabled {
                    Style::default().fg(app.theme.normal)
                } else {
                    Style::default().fg(app.theme.dim)
                };
                items.push(ListItem::new(Line::from(Span::styled(
                    format!(
                        "[{}] {}",
                        if a.enabled { "x" } else { " " },
                        a.kind.describe()
                    ),
                    style,
                ))));
            }
        }
        RulesTab::Colors => {
            if app.color_rules.is_empty() {
                items.push(ListItem::new(Line::from(Span::styled(
                    "No coloring rules. Press 'a' to add one.",
                    Style::default().fg(app.theme.dim),
                ))));
            }
            for (idx, c) in app.color_rules.iter().enumerate() {
                let style = if idx == app.rules_cursor {
                    Style::default()
                        .fg(app.theme.selected_fg)
                        .bg(app.theme.selected_bg)
                        .add_modifier(Modifier::BOLD)
                } else {
                    c.style
                };
                items.push(ListItem::new(Line::from(Span::styled(
                    format!(
                        "[{}] {}",
                        if c.enabled { "x" } else { " " },
                        c.kind.describe()
                    ),
                    style,
                ))));
            }
        }
    }

    items.push(ListItem::new(Line::from("")));
    if let Some(input) = &app.rules_input {
        let hint = match app.rules_tab {
            RulesTab::Alerts => "alert expression, e.g. process=python",
            RulesTab::Colors => "expr | fg=cyan bold, e.g. rport=443 | fg=cyan",
        };
        items.push(ListItem::new(Line::from(vec![
            Span::styled("add> ", Style::default().fg(app.theme.accent)),
            Span::raw(input.value.clone()),
            Span::styled("▏", Style::default().fg(app.theme.dim)),
        ])));
        items.push(ListItem::new(Line::from(Span::styled(
            format!("({hint} — Enter saves, Esc cancels)"),
            Style::default().fg(app.theme.dim),
        ))));
    } else {
        items.push(ListItem::new(Line::from(Span::styled(
            "a:add  Space:enable/disable  x:remove  Tab:switch  Esc:close&save",
            Style::default().fg(app.theme.changed),
        ))));
    }

    let list = List::new(items).block(popup_block("Rules", app));
    f.render_widget(Clear, rect);
    f.render_widget(list, rect);
}
