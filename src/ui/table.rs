//! The main endpoint table (flat and grouped views).

use ratatui::Frame;
use ratatui::layout::{Constraint, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Cell, Paragraph, Row, Table};

use crate::app::{App, ColumnId, DisplayCtx, DisplayNode, Mode, cell_text};
use crate::model::Protocol;

/// The mark/indent gutter in front of the data columns.
const GUTTER: u16 = 2;

pub fn draw(f: &mut Frame, app: &mut App, area: Rect) {
    app.table_area = area;
    // Inner height minus the header row: border + header + border.
    let body_height = area.height.saturating_sub(3) as usize;
    app.ensure_visible(body_height);

    // Everything below reads `app` immutably while the DNS cache guard is
    // alive; mutable state is only touched before/after that scope.
    let (rows, constraints, header, header_cells, title) = {
        let dns_guard = app.dns_cache.lock().ok();
        let ctx = DisplayCtx {
            processes: &app.processes,
            dns: dns_guard.as_deref(),
            resolve: app.toggles.resolve,
        };

        let cols: Vec<ColumnId> = app
            .column_order
            .iter()
            .copied()
            .filter(|c| *c != ColumnId::Mark && !app.column_hidden.contains(c))
            .collect();

        let first_sort = app.sort.first().map(|k| k.col);
        let sort_desc = app.sort.first().map(|k| k.desc).unwrap_or(false);

        let mut constraints: Vec<Constraint> = vec![Constraint::Length(GUTTER)];
        // One header CELL per column so titles align with the grid; a single
        // cell would squeeze every title into the gutter width.
        let mut header_cells: Vec<Cell> = vec![Cell::from(Span::styled(
            "M",
            Style::default()
                .fg(app.theme.header)
                .add_modifier(Modifier::BOLD),
        ))];
        let mut positions: Vec<(u16, u16, ColumnId)> = Vec::with_capacity(cols.len());
        let mut x = area.x + 1 + GUTTER;

        for col in &cols {
            let configured = *app.column_width.get(col).unwrap_or(&col.default_width());
            let width = configured.max(col.header().len() as u16 + 2).min(60);
            constraints.push(Constraint::Length(width));
            let mut title_text = col.header().to_string();
            if Some(*col) == first_sort {
                title_text.push(if sort_desc { '↓' } else { '↑' });
            }
            let style = if Some(*col) == first_sort {
                Style::default()
                    .fg(app.theme.accent)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default()
                    .fg(app.theme.header)
                    .add_modifier(Modifier::BOLD)
            };
            header_cells.push(Cell::from(Span::styled(title_text, style)));
            positions.push((x, width, *col));
            x += width;
        }

        let title = format!(
            " {} endpoint(s){} ",
            app.visible.len(),
            if app.grouped {
                " · grouped by process"
            } else {
                ""
            }
        );

        let rows = build_rows(app, &ctx, &cols);
        (rows, constraints, Row::new(header_cells), positions, title)
    };

    app.header_cells = header_cells;

    let table = Table::new(rows, constraints).header(header).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(app.theme.popup_border))
            .title(title),
    );
    f.render_widget(table, area);

    // Overlay the filter/search prompt on the last line inside the block.
    if app.mode == Mode::Filtering || app.mode == Mode::Searching {
        let prompt = if app.mode == Mode::Filtering {
            "filter"
        } else {
            "search"
        };
        let mut spans = vec![
            Span::styled(format!("{prompt}> "), Style::default().fg(app.theme.accent)),
            Span::raw(app.filter_or_search_input().to_string()),
            Span::styled("▏", Style::default().fg(app.theme.dim)),
        ];
        // Live feedback: match count or parse error while typing a filter.
        if let Some(feedback) = app.filter_feedback() {
            spans.push(Span::raw("  "));
            spans.push(match feedback {
                Ok(n) => Span::styled(format!("{n} match(es)"), Style::default().fg(app.theme.new)),
                Err(e) => Span::styled(e, Style::default().fg(app.theme.deleted)),
            });
        }
        let input_area = Rect {
            x: area.x + 1,
            y: area.y + area.height.saturating_sub(1),
            width: area.width.saturating_sub(2),
            height: 1,
        };
        f.render_widget(Paragraph::new(Line::from(spans)), input_area);
    }
}

fn build_rows(app: &App, ctx: &DisplayCtx<'_>, cols: &[ColumnId]) -> Vec<Row<'static>> {
    let mut rows: Vec<Row> = Vec::with_capacity(64);
    let body_height = app.table_area.height.saturating_sub(3) as usize;
    let end = (app.offset + body_height).min(app.display.len());
    let search = app.search.as_ref();

    for idx in app.offset..end {
        let is_selected = idx == app.selected;
        match &app.display[idx] {
            DisplayNode::Group {
                pid,
                name,
                count,
                expanded,
            } => {
                let marker = if *expanded { "▼ " } else { "▶ " };
                let mut cells: Vec<Cell> = Vec::with_capacity(cols.len() + 1);
                cells.push(Cell::from(format!("{marker}{name} ({count})")));
                for col in cols {
                    let text = if *col == ColumnId::Pid {
                        pid.to_string()
                    } else {
                        String::new()
                    };
                    cells.push(Cell::from(text));
                }
                let style = Style::default()
                    .fg(app.theme.accent)
                    .add_modifier(Modifier::BOLD);
                rows.push(Row::new(cells).style(style));
            }
            DisplayNode::Conn(vi) => {
                let Some(row) = app.visible.get(*vi) else {
                    continue;
                };
                let style = if is_selected {
                    Style::default()
                        .fg(app.theme.selected_fg)
                        .bg(app.theme.selected_bg)
                        .add_modifier(Modifier::BOLD)
                } else {
                    app.row_style(row)
                };

                let marked = app.marked.contains(&row.id);
                let mut cells: Vec<Cell> = Vec::with_capacity(cols.len() + 1);
                cells.push(Cell::from(if marked { "* " } else { "  " }));

                for col in cols {
                    let mut text = cell_text(row, *col, ctx);
                    // UDP endpoints have no state text; keep the cell blank.
                    if *col == ColumnId::State && row.protocol == Protocol::Udp {
                        text.clear();
                    }
                    // The Country cell needs the GeoIP resolver, which lives
                    // behind a mutex on the app, not in the display ctx.
                    if *col == ColumnId::Country {
                        text = app.country_for(row);
                    }
                    let truncated = truncate(&text, 60);
                    if let Some(line) = highlight_search(&truncated, search, &app.theme) {
                        cells.push(Cell::from(line));
                    } else {
                        cells.push(Cell::from(truncated));
                    }
                }
                rows.push(Row::new(cells).style(style));
            }
        }
    }
    rows
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let cut: String = s.chars().take(max.saturating_sub(1)).collect();
        format!("{cut}…")
    }
}

/// Build a highlighted version of `text` for the active search: all matches
/// get a distinct background. Returns `None` when the search does not match.
fn highlight_search(
    text: &str,
    search: Option<&crate::app::FilterKind>,
    theme: &crate::app::Theme,
) -> Option<Line<'static>> {
    let search = search?;
    // Byte ranges of every match, at char boundaries.
    let ranges: Vec<(usize, usize)> = match search {
        crate::app::FilterKind::Plain(p) => {
            let needle = p.as_bytes();
            if needle.is_empty() {
                return None;
            }
            let hay = text.as_bytes();
            let mut out = Vec::new();
            let mut i = 0;
            while i + needle.len() <= hay.len() {
                if hay[i..i + needle.len()].eq_ignore_ascii_case(needle) {
                    out.push((i, i + needle.len()));
                    i += needle.len();
                } else {
                    i += 1;
                }
            }
            out
        }
        crate::app::FilterKind::Regex(re) => {
            re.find_iter(text).map(|m| (m.start(), m.end())).collect()
        }
        crate::app::FilterKind::Expr { .. } => return None,
    };
    if ranges.is_empty() {
        return None;
    }

    let hl = Style::default()
        .fg(theme.selected_fg)
        .bg(theme.changed)
        .add_modifier(Modifier::BOLD);
    let mut spans: Vec<Span> = Vec::new();
    let mut cursor = 0usize;
    for (start, end) in ranges {
        if start > cursor {
            spans.push(Span::raw(text[cursor..start].to_string()));
        }
        spans.push(Span::styled(text[start..end].to_string(), hl));
        cursor = end;
    }
    if cursor < text.len() {
        spans.push(Span::raw(text[cursor..].to_string()));
    }
    Some(Line::from(spans))
}

impl App {
    pub(crate) fn filter_or_search_input(&self) -> &str {
        if self.mode == Mode::Filtering {
            &self.filter_input.value
        } else {
            &self.search_input.value
        }
    }
}
