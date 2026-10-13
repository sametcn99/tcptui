import io

p = 'src/ui/table.rs'
s = io.open(p, encoding='utf-8').read()

old = '''    // Everything below reads `app` immutably while the DNS cache guard is
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
        (
            rows,
            constraints,
            Row::new(header_cells),
            positions,
            title,
        )
    };

    app.header_cells = header_cells;'''

new = '''    // Geometry first (immutable reads), then mutate scroll bounds, then the
    // render scope that borrows the DNS cache.
    let cols: Vec<ColumnId> = app
        .column_order
        .iter()
        .copied()
        .filter(|c| *c != ColumnId::Mark && !app.column_hidden.contains(c))
        .collect();
    let widths: Vec<u16> = cols
        .iter()
        .map(|c| {
            let configured = *app.column_width.get(c).unwrap_or(&c.default_width());
            configured.max(c.header().len() as u16 + 2).min(60)
        })
        .collect();
    let viewport = area.width.saturating_sub(2 + GUTTER);
    let total: u32 = widths.iter().map(|w| *w as u32).sum();
    app.h_max = (total as u16).saturating_sub(viewport);
    app.scroll_x = app.scroll_x.min(app.h_max);
    let (start, cut, count) = App::column_window(&widths, app.scroll_x, viewport);
    let vis_cols: Vec<ColumnId> = cols
        .iter()
        .skip(start)
        .take(count)
        .copied()
        .collect();
    let first_cut = if start < widths.len() { cut } else { 0 };

    let (rows, constraints, header, header_cells, title) = {
        let dns_guard = app.dns_cache.lock().ok();
        let ctx = DisplayCtx {
            processes: &app.processes,
            dns: dns_guard.as_deref(),
            resolve: app.toggles.resolve,
        };

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
        let mut positions: Vec<(u16, u16, ColumnId)> = Vec::with_capacity(vis_cols.len());
        let mut x = area.x + 1 + GUTTER;

        for (i, col) in vis_cols.iter().enumerate() {
            let full = widths[start + i];
            let eff = if i == 0 {
                full.saturating_sub(first_cut)
            } else {
                full
            };
            constraints.push(Constraint::Length(eff));
            let mut title_text = col.header().to_string();
            if Some(*col) == first_sort {
                title_text.push(if sort_desc { '↓' } else { '↑' });
            }
            if i == 0 && first_cut > 0 {
                title_text = skip_chars(&title_text, first_cut);
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
            positions.push((x, eff, *col));
            x += eff;
        }

        let scroll_hint = match (app.scroll_x > 0, app.scroll_x < app.h_max) {
            (true, true) => " ‹ · › ",
            (true, false) => " ‹ ",
            (false, true) => " › ",
            (false, false) => "",
        };
        let title = format!(
            " {} endpoint(s){}{} ",
            app.visible.len(),
            if app.grouped {
                " · grouped by process"
            } else {
                ""
            },
            scroll_hint,
        );

        let rows = build_rows(app, &ctx, &vis_cols, first_cut);
        (
            rows,
            constraints,
            Row::new(header_cells),
            positions,
            title,
        )
    };

    app.header_cells = header_cells;'''

assert old in s, 'table window anchor'
s = s.replace(old, new, 1)

# build_rows signature + first column cut
old = '''fn build_rows(app: &App, ctx: &DisplayCtx<'_>, cols: &[ColumnId]) -> Vec<Row<'static>> {'''
new = '''fn build_rows(
    app: &App,
    ctx: &DisplayCtx<'_>,
    cols: &[ColumnId],
    first_cut: u16,
) -> Vec<Row<'static>> {'''
assert old in s
s = s.replace(old, new, 1)

old = '''                for col in cols {
                    let mut text = cell_text(row, *col, ctx);'''
new = '''                for (i, col) in cols.iter().enumerate() {
                    let mut text = cell_text(row, *col, ctx);
                    if i == 0 && first_cut > 0 {
                        text = skip_chars(&text, first_cut);
                    }'''
assert old in s
s = s.replace(old, new, 1)

# helper
old = '''fn truncate(s: &str, max: usize) -> String {'''
new = '''/// Drop the first `n` characters (unicode safe).
fn skip_chars(s: &str, n: u16) -> String {
    s.chars().skip(n as usize).collect()
}

fn truncate(s: &str, max: usize) -> String {'''
assert old in s
s = s.replace(old, new, 1)

io.open(p, 'w', encoding='utf-8', newline='').write(s)
print('patch5 ok')
