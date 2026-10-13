import io

p = 'src/ui/popups.rs'
s = io.open(p, encoding='utf-8').read()

# dispatch: context menu
old = '''        Mode::Profiles => draw_profiles(f, app, area),
        Mode::Settings => draw_settings(f, app, area),
        Mode::Vt => draw_vt(f, app, area),
        _ => {}'''
new = '''        Mode::Profiles => draw_profiles(f, app, area),
        Mode::ContextMenu => draw_context_menu(f, app, area),
        Mode::Settings => draw_settings(f, app, area),
        Mode::Vt => draw_vt(f, app, area),
        _ => {}'''
assert old in s, 'dispatch'
s = s.replace(old, new, 1)

# settings rows (actual rustfmt layout)
old = '''    let geo_state = match (&app.geo, app.geoip_enabled) {
        (Some(_), _) => "on (database loaded)",
        (None, true) => "on (database missing)",
        (None, false) => "off",
    };'''
new = '''    let geo_state = match (&app.geo, app.geoip_enabled) {
        (Some(_), _) => format!("on — {}", app.geoip_path),
        (None, true) => format!("on (db missing) — {}", app.geoip_path),
        (None, false) => "off".to_string(),
    };'''
assert old in s, 'geo_state'
s = s.replace(old, new, 1)

old = '''        ("GeoIP country column", geo_state.to_string()),
    ];'''
new = '''        ("GeoIP country column", geo_state),
        ("Bell on alerts", on_off(app.bell_enabled)),
    ];'''
assert old in s, 'settings last row'
s = s.replace(old, new, 1)

# settings tail hints + input
old = '''    items.push(ListItem::new(Line::from(""));
    items.push(ListItem::new(Line::from(Span::styled(
        "Space/Enter:toggle  +/-:adjust  Esc:close&save",
        Style::default().fg(app.theme.changed),
    ))));

    let list = List::new(items).block(popup_block("Settings", app));'''
new = '''    items.push(ListItem::new(Line::from(""));
    if let Some(input) = &app.settings_input {
        items.push(ListItem::new(Line::from(vec![
            Span::styled("geoip path> ", Style::default().fg(app.theme.accent)),
            Span::raw(input.value.clone()),
            Span::styled("▏", Style::default().fg(app.theme.dim)),
        ])));
        items.push(ListItem::new(Line::from(Span::styled(
            "(Enter applies and tries to open the database, Esc cancels)",
            Style::default().fg(app.theme.dim),
        ))));
    } else {
        items.push(ListItem::new(Line::from(Span::styled(
            "Space/Enter:toggle  +/-:adjust  e:edit GeoIP path  Esc:close&save",
            Style::default().fg(app.theme.changed),
        ))));
    }

    let list = List::new(items).block(popup_block("Settings", app));'''
assert old in s, 'settings tail'
s = s.replace(old, new, 1)

# log popup: filtered entries
old = '''    let rect = centered_rect(80, 80, area);
    let total = app.event_log.len();
    let height = rect.height.saturating_sub(2) as usize;
    // Keep the newest entries visible; respect manual scrolling.
    let max_scroll = total.saturating_sub(height);
    let scroll = app.log_scroll.min(max_scroll);
    let visible_slice: Vec<ListItem> = app
        .event_log
        .iter()'''
new = '''    let rect = centered_rect(80, 80, area);
    let entries = app.filtered_log();
    let total = entries.len();
    let height = rect.height.saturating_sub(2) as usize;
    // Keep the newest entries visible; respect manual scrolling.
    let max_scroll = total.saturating_sub(height);
    let scroll = app.log_scroll.min(max_scroll);
    let visible_slice: Vec<ListItem> = entries
        .iter()'''
assert old in s, 'log head'
s = s.replace(old, new, 1)

old = '''    let list = List::new(visible_slice).block(popup_block(
        &format!("Event log — {total} entries (c: copy, j/k: scroll, Esc: close)"),
        app,
    ));
    f.render_widget(Clear, rect);
    f.render_widget(list, rect);
}'''
new = '''    let filter_desc = app
        .log_filter
        .as_deref()
        .map(|f| format!(" filter:{f}"))
        .unwrap_or_default();
    let mut items = visible_slice;
    if let Some(input) = &app.log_input {
        items.push(ListItem::new(Line::from(vec![
            Span::styled("filter> ", Style::default().fg(app.theme.accent)),
            Span::raw(input.value.clone()),
            Span::styled("▏", Style::default().fg(app.theme.dim)),
        ])));
    }
    let list = List::new(items).block(popup_block(
        &format!("Event log — {total} entries{filter_desc} (/ filter, E export, c copy)"),
        app,
    ));
    f.render_widget(Clear, rect);
    f.render_widget(list, rect);
}'''
assert old in s, 'log tail'
s = s.replace(old, new, 1)

# context menu popup
old = '''/// VirusTotal report popup (`V`).'''
new = '''/// Right-click context menu.
fn draw_context_menu(f: &mut Frame, app: &App, area: Rect) {
    let rect = centered_rect(35, 45, area);
    let mut items: Vec<ListItem> = Vec::new();
    for (idx, item) in app.ctx_menu.iter().enumerate() {
        let style = if idx == app.ctx_cursor {
            Style::default()
                .fg(app.theme.selected_fg)
                .bg(app.theme.selected_bg)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(app.theme.normal)
        };
        items.push(ListItem::new(Line::from(Span::styled(
            format!(" {}", item.label()),
            style,
        ))));
    }
    items.push(ListItem::new(Line::from("")));
    items.push(ListItem::new(Line::from(Span::styled(
        "Enter:run  Esc:close",
        Style::default().fg(app.theme.changed),
    ))));
    let list = List::new(items).block(popup_block("Actions", app));
    f.render_widget(Clear, rect);
    f.render_widget(list, rect);
}

/// VirusTotal report popup (`V`).'''
assert old in s, 'ctx menu'
s = s.replace(old, new, 1)

io.open(p, 'w', encoding='utf-8', newline='').write(s)
print('patch6 ok')
