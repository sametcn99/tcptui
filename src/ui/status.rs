//! Title bar and two-line footer (status hints + statistics).

use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;

use crate::app::App;

pub fn draw_title_bar(f: &mut Frame, app: &App, area: Rect) {
    // Build the left part as plain text so the width math is trivial, then
    // render it as a single span next to the right-aligned info.
    let mut left_text = String::new();
    if !app.alert_pending.is_empty() {
        left_text.push_str(&format!("⚠{} ", app.alert_pending.len()));
    }
    if app.etw_session.is_some() {
        left_text.push_str("ETW ");
    }
    if let Some(watch) = app.watch_pid {
        left_text.push_str(&format!("WATCH {watch} "));
    }
    if let Some(filter) = &app.filter {
        left_text.push_str(&format!("FILTER:{} ", filter.describe()));
    }
    if app.grouped {
        left_text.push_str("GROUPED ");
    }
    left_text.push_str(&format!(
        "sort:{} ",
        app.sort
            .first()
            .map(|k| format!("{}{}", k.col.header(), if k.desc { '↓' } else { '↑' }))
            .unwrap_or_default()
    ));
    left_text.push_str(if app.toggles.resolve {
        "resolve:on "
    } else {
        "resolve:off "
    });
    if !app.toggles.show_unconnected {
        left_text.push_str("connected-only ");
    }
    if !app.toggles.show_loopback {
        left_text.push_str("no-loopback ");
    }

    let right = format!(
        "{}ms{}",
        app.refresh_interval.as_millis(),
        if app.admin { " ADMIN" } else { "" }
    );

    let used = left_text.chars().count() as u16;
    let space = area
        .width
        .saturating_sub(used + right.chars().count() as u16 + 9);
    left_text.push_str(&" ".repeat(space.max(1) as usize));

    let spans = vec![
        Span::styled(
            " tcptui ",
            Style::default()
                .fg(app.theme.selected_fg)
                .bg(app.theme.bar)
                .add_modifier(Modifier::BOLD),
        ),
        if app.alert_pending.is_empty() {
            Span::raw(left_text)
        } else {
            Span::styled(
                left_text,
                Style::default()
                    .fg(app.theme.deleted)
                    .add_modifier(Modifier::BOLD),
            )
        },
        Span::styled(right, Style::default().fg(app.theme.dim)),
    ];

    f.render_widget(
        Paragraph::new(Line::from(spans))
            .style(Style::default().bg(app.theme.bar).fg(app.theme.selected_fg)),
        area,
    );
}

pub fn draw_footer(f: &mut Frame, app: &App, area: Rect) {
    let top = match app.current_status() {
        Some(msg) => Line::from(Span::styled(
            format!(" {msg}"),
            Style::default().fg(app.theme.changed),
        )),
        None if !app.alert_pending.is_empty() => Line::from(Span::styled(
            format!(
                " ⚠ {} (x clears)",
                app.alert_pending.last().unwrap_or(&String::new())
            ),
            Style::default()
                .fg(app.theme.deleted)
                .add_modifier(Modifier::BOLD),
        )),
        None => Line::from(Span::styled(
            " ?:help  /:filter  1-8:presets  o:sort  B:chart  A:rules  c:close  K:kill  e:export  q:quit",
            Style::default().fg(app.theme.dim),
        )),
    };

    let estats = if app.estats_enabled {
        ""
    } else {
        " · estats:off"
    };
    let bottom_text = format!(
        " total {} · tcp {} (est {} lsn {} tw {} cw {}) · udp {} · shown {}{}",
        app.rows.len(),
        app.stats.tcp,
        app.stats.established,
        app.stats.listening,
        app.stats.time_wait,
        app.stats.close_wait,
        app.stats.udp,
        app.visible.len(),
        estats,
    );
    let bottom = Line::from(Span::styled(
        bottom_text,
        Style::default().fg(app.theme.dim),
    ));

    let mut lines = vec![top, bottom];
    if area.height >= 2 {
        f.render_widget(Paragraph::new(std::mem::take(&mut lines)), area);
    }
}
