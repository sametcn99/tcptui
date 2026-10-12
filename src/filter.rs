//! Structured filter expressions for category-based filtering.
//!
//! Grammar (case-insensitive keywords):
//!
//! ```text
//! expr    := or
//! or      := and ( ("or" | "||") and )*
//! and     := not ( ("and" | "&&") not )*
//! not     := ("not" | "!") not | primary
//! primary := "(" expr ")" | field op value | word
//! op      := "=" "==" "!=" ">" ">=" "<" "<=" ":" "=~" "!~"
//! ```
//!
//! A bare `word` matches any field (substring), preserving the classic
//! free-text search. `field op value` restricts the match to one category.
//! When the left side of an operator is not a known field and does not look
//! like an identifier (e.g. `127.0.0.1:443`), the text is treated as a bare
//! term so address:port searches keep working.

use std::collections::HashMap;
use std::fmt;

use crate::model::{ConnectionRow, ProcessInfo, Protocol, RowChange};

// ---------------------------------------------------------------------------
// Fields
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Field {
    Process,
    Path,
    Pid,
    Proto,
    State,
    LocalAddr,
    RemoteAddr,
    AnyAddr,
    LocalPort,
    RemotePort,
    AnyPort,
    Service,
    Tx,
    Rx,
    Change,
    Loopback,
    Connected,
}

impl Field {
    pub fn from_ident(s: &str) -> Option<Field> {
        let s = s.to_ascii_lowercase();
        Some(match s.as_str() {
            "process" | "proc" | "name" => Field::Process,
            "path" | "exe" => Field::Path,
            "pid" => Field::Pid,
            "proto" | "protocol" => Field::Proto,
            "state" => Field::State,
            "laddr" | "local_addr" | "localaddr" | "local_address" => Field::LocalAddr,
            "raddr" | "remote_addr" | "remoteaddr" | "remote_address" => Field::RemoteAddr,
            "addr" | "address" => Field::AnyAddr,
            "lport" | "local_port" | "localport" => Field::LocalPort,
            "rport" | "remote_port" | "remoteport" => Field::RemotePort,
            "port" => Field::AnyPort,
            "service" | "svc" => Field::Service,
            "tx" | "sent" => Field::Tx,
            "rx" | "received" => Field::Rx,
            "change" => Field::Change,
            "loopback" => Field::Loopback,
            "connected" => Field::Connected,
            _ => return None,
        })
    }

    pub fn is_numeric(self) -> bool {
        matches!(
            self,
            Field::Pid
                | Field::LocalPort
                | Field::RemotePort
                | Field::AnyPort
                | Field::Tx
                | Field::Rx
        )
    }

    pub fn is_bool(self) -> bool {
        matches!(self, Field::Loopback | Field::Connected)
    }

    /// Comma-separated list of accepted identifiers for error messages/docs.
    pub fn help() -> &'static str {
        "process|path|pid|proto|state|laddr|raddr|addr|lport|rport|port|service|tx|rx|change|loopback|connected"
    }
}

// ---------------------------------------------------------------------------
// Operators, values, AST
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Op {
    Eq,
    Ne,
    Gt,
    Ge,
    Lt,
    Le,
    Contains,
    Regex,
    NotRegex,
}

impl Op {
    fn symbol(self) -> &'static str {
        match self {
            Op::Eq => "=",
            Op::Ne => "!=",
            Op::Gt => ">",
            Op::Ge => ">=",
            Op::Lt => "<",
            Op::Le => "<=",
            Op::Contains => ":",
            Op::Regex => "=~",
            Op::NotRegex => "!~",
        }
    }
}

#[derive(Clone, Debug)]
pub enum Value {
    Num(u64),
    Str(String),
    Regex(regex::Regex),
}

/// The concrete value extracted from a row for one field.
#[derive(Clone, Debug)]
pub enum RowValue {
    Str(String),
    Num(u64),
    Bool(bool),
    /// Multiple candidate values (e.g. `addr` matches local or remote).
    Multi(Vec<RowValue>),
    Missing,
}

#[derive(Clone, Debug)]
pub struct Predicate {
    pub field: Field,
    pub op: Op,
    pub value: Value,
}

#[derive(Clone, Debug)]
pub enum Expr {
    And(Box<Expr>, Box<Expr>),
    Or(Box<Expr>, Box<Expr>),
    Not(Box<Expr>),
    Pred(Predicate),
    /// Free-text term matched against a haystack of all fields.
    Any(String),
}

impl fmt::Display for Expr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Expr::And(a, b) => write!(f, "({a} and {b})"),
            Expr::Or(a, b) => write!(f, "({a} or {b})"),
            Expr::Not(a) => write!(f, "not {a}"),
            Expr::Pred(p) => {
                let v = match &p.value {
                    Value::Num(n) => n.to_string(),
                    Value::Str(s) => s.clone(),
                    Value::Regex(r) => r.as_str().to_string(),
                };
                write!(f, "{}{}{}", field_ident(p.field), p.op.symbol(), v)
            }
            Expr::Any(t) => write!(f, "{t}"),
        }
    }
}

fn field_ident(field: Field) -> &'static str {
    match field {
        Field::Process => "process",
        Field::Path => "path",
        Field::Pid => "pid",
        Field::Proto => "proto",
        Field::State => "state",
        Field::LocalAddr => "laddr",
        Field::RemoteAddr => "raddr",
        Field::AnyAddr => "addr",
        Field::LocalPort => "lport",
        Field::RemotePort => "rport",
        Field::AnyPort => "port",
        Field::Service => "service",
        Field::Tx => "tx",
        Field::Rx => "rx",
        Field::Change => "change",
        Field::Loopback => "loopback",
        Field::Connected => "connected",
    }
}

// ---------------------------------------------------------------------------
// Tokenizer
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq)]
enum Tok {
    Word(String),
    Quoted(String),
    Op(&'static str),
    LParen,
    RParen,
}

fn looks_like_ident(s: &str) -> bool {
    let mut chars = s.chars();
    matches!(chars.next(), Some(c) if c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

fn tokenize(input: &str) -> Result<Vec<Tok>, String> {
    let mut out = Vec::new();
    let chars: Vec<char> = input.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c.is_whitespace() {
            i += 1;
            continue;
        }
        if c == '(' {
            out.push(Tok::LParen);
            i += 1;
            continue;
        }
        if c == ')' {
            out.push(Tok::RParen);
            i += 1;
            continue;
        }
        if c == '"' || c == '\'' {
            let quote = c;
            let mut s = String::new();
            i += 1;
            while i < chars.len() && chars[i] != quote {
                s.push(chars[i]);
                i += 1;
            }
            if i >= chars.len() {
                return Err(format!("unterminated string: missing closing {quote}"));
            }
            i += 1; // closing quote
            out.push(Tok::Quoted(s));
            continue;
        }
        // Multi-char operators first. Both `=~` and `~=` are accepted.
        let two: String = chars[i..(i + 2).min(chars.len())].iter().collect();
        let op = match two.as_str() {
            ">=" => Some(">="),
            "<=" => Some("<="),
            "!=" => Some("!="),
            "=~" | "~=" => Some("=~"),
            "!~" => Some("!~"),
            "==" => Some("=="),
            "&&" => Some("and"),
            "||" => Some("or"),
            _ => None,
        };
        if let Some(op) = op {
            out.push(Tok::Op(op));
            i += 2;
            continue;
        }
        if c == '=' || c == '>' || c == '<' || c == ':' || c == '!' {
            out.push(Tok::Op(match c {
                '=' => "=",
                '>' => ">",
                '<' => "<",
                ':' => ":",
                _ => "!",
            }));
            i += 1;
            continue;
        }
        // Word: runs until whitespace, paren, quote or operator start.
        let mut s = String::new();
        while i < chars.len() {
            let c = chars[i];
            if c.is_whitespace() || c == '(' || c == ')' || c == '"' || c == '\'' {
                break;
            }
            let two: String = chars[i..(i + 2).min(chars.len())].iter().collect();
            if matches!(
                two.as_str(),
                ">=" | "<=" | "!=" | "=~" | "~=" | "!~" | "==" | "&&" | "||"
            ) || "=><:~!".contains(c)
            {
                break;
            }
            s.push(c);
            i += 1;
        }
        if s.is_empty() {
            return Err(format!("unexpected character '{c}'"));
        }
        let lower = s.to_ascii_lowercase();
        out.push(match lower.as_str() {
            "and" => Tok::Op("and"),
            "or" => Tok::Op("or"),
            "not" => Tok::Op("not"),
            _ => Tok::Word(s),
        });
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Parser (recursive descent)
// ---------------------------------------------------------------------------

struct Parser {
    toks: Vec<Tok>,
    pos: usize,
}

impl Parser {
    fn peek(&self) -> Option<&Tok> {
        self.toks.get(self.pos)
    }

    fn next(&mut self) -> Option<Tok> {
        let t = self.toks.get(self.pos).cloned();
        if t.is_some() {
            self.pos += 1;
        }
        t
    }

    fn expect_op(&mut self, sym: &str) -> Result<(), String> {
        match self.next() {
            Some(Tok::Op(o)) if o == sym => Ok(()),
            Some(Tok::RParen) if sym == ")" => Ok(()),
            other => Err(format!("expected '{sym}', found {}", describe(&other))),
        }
    }

    fn parse_or(&mut self) -> Result<Expr, String> {
        let mut left = self.parse_and()?;
        while let Some(Tok::Op("or")) = self.peek() {
            self.pos += 1;
            let right = self.parse_and()?;
            left = Expr::Or(Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn parse_and(&mut self) -> Result<Expr, String> {
        let mut left = self.parse_not()?;
        while let Some(Tok::Op("and")) = self.peek() {
            self.pos += 1;
            let right = self.parse_not()?;
            left = Expr::And(Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn parse_not(&mut self) -> Result<Expr, String> {
        if let Some(Tok::Op("not")) | Some(Tok::Op("!")) = self.peek() {
            self.pos += 1;
            let inner = self.parse_not()?;
            return Ok(Expr::Not(Box::new(inner)));
        }
        self.parse_primary()
    }

    fn parse_primary(&mut self) -> Result<Expr, String> {
        match self.next() {
            Some(Tok::LParen) => {
                let e = self.parse_or()?;
                self.expect_op(")")?;
                // expect_op description prints ')' oddly; fine.
                Ok(e)
            }
            Some(Tok::RParen) => Err("unexpected ')'".to_string()),
            Some(Tok::Op(o)) => Err(format!("unexpected operator '{o}'")),
            Some(Tok::Quoted(s)) => Ok(Expr::Any(s)),
            Some(Tok::Word(w)) => {
                // Predicate if an operator follows and the word is a known field.
                if let Some(Tok::Op(_)) = self.peek() {
                    if let Some(field) = Field::from_ident(&w) {
                        let op_tok = self.next(); // the operator
                        let op_sym = match op_tok {
                            Some(Tok::Op(o)) => o,
                            _ => unreachable!("checked above"),
                        };
                        let op = match op_sym {
                            "=" | "==" => Op::Eq,
                            "!=" => Op::Ne,
                            ">" => Op::Gt,
                            ">=" => Op::Ge,
                            "<" => Op::Lt,
                            "<=" => Op::Le,
                            ":" => Op::Contains,
                            "=~" => Op::Regex,
                            "!~" => Op::NotRegex,
                            _ => return Err(format!("operator '{op_sym}' cannot follow a field")),
                        };
                        let value = self.parse_value(field, op)?;
                        return Ok(Expr::Pred(Predicate { field, op, value }));
                    }
                    if looks_like_ident(&w) {
                        return Err(format!(
                            "unknown field '{w}'. Valid fields: {}",
                            Field::help()
                        ));
                    }
                    // Not an identifier (e.g. `127.0.0.1:443`): degrade to
                    // free-text terms combined with AND, without the
                    // operator character gluing them together.
                    let op_tok = self.next();
                    let mut combined = Expr::Any(w);
                    if let Some(Tok::Op(_)) = op_tok
                        && let Some(v) = self.next()
                    {
                        let text = match v {
                            Tok::Word(s) | Tok::Quoted(s) => s,
                            Tok::Op(o) => o.to_string(),
                            _ => String::new(),
                        };
                        combined = Expr::And(Box::new(combined), Box::new(Expr::Any(text)));
                    }
                    return Ok(combined);
                }
                Ok(Expr::Any(w))
            }
            None => Err("unexpected end of filter".to_string()),
        }
    }

    fn parse_value(&mut self, field: Field, op: Op) -> Result<Value, String> {
        let tok = self
            .next()
            .ok_or_else(|| "filter ends after an operator; a value is required".to_string())?;
        let (text, quoted) = match tok {
            Tok::Word(w) => (w, false),
            Tok::Quoted(q) => (q, true),
            Tok::Op(o) => return Err(format!("expected a value after the operator, found '{o}'")),
            Tok::LParen | Tok::RParen => {
                return Err("expected a value after the operator".to_string());
            }
        };

        if field.is_bool() {
            if matches!(op, Op::Eq | Op::Ne) {
                return Ok(Value::Str(text));
            }
            return Err(format!(
                "field '{}' only supports = and !=",
                field_ident(field)
            ));
        }
        if matches!(op, Op::Regex | Op::NotRegex) {
            let re = regex::RegexBuilder::new(&text)
                .case_insensitive(true)
                .build()
                .map_err(|e| format!("invalid regex '{text}': {e}"))?;
            return Ok(Value::Regex(re));
        }
        if field.is_numeric() {
            if let Some(n) = parse_number_with_units(&text) {
                return Ok(Value::Num(n));
            }
            if quoted {
                return Err(format!("'{}' expects a number", field_ident(field)));
            }
            // Bare non-numeric value against a numeric field: fall back to a
            // free-text term so nothing is silently swallowed.
            return Ok(Value::Str(text));
        }
        Ok(Value::Str(text))
    }
}

fn describe(t: &Option<Tok>) -> String {
    match t {
        None => "end of filter".to_string(),
        Some(Tok::Word(w)) => format!("'{w}'"),
        Some(Tok::Quoted(q)) => format!("\"{q}\""),
        Some(Tok::Op(o)) => format!("'{o}'"),
        Some(Tok::LParen) => "'('".to_string(),
        Some(Tok::RParen) => "')'".to_string(),
    }
}

/// Parse `1024`, `10kb`, `1mb`, `2gb` (case-insensitive) into bytes/plain int.
fn parse_number_with_units(s: &str) -> Option<u64> {
    let s = s.trim();
    let lower = s.to_ascii_lowercase();
    let (digits, mult) =
        if let Some(rest) = lower.strip_suffix("kb").or_else(|| lower.strip_suffix('k')) {
            (rest, 1024u64)
        } else if let Some(rest) = lower.strip_suffix("mb").or_else(|| lower.strip_suffix('m')) {
            (rest, 1024 * 1024)
        } else if let Some(rest) = lower.strip_suffix("gb").or_else(|| lower.strip_suffix('g')) {
            (rest, 1024 * 1024 * 1024)
        } else {
            (s, 1)
        };
    digits.parse::<u64>().ok().map(|n| n.saturating_mul(mult))
}

// ---------------------------------------------------------------------------
// Matching
// ---------------------------------------------------------------------------

/// Everything a match needs from the environment.
pub struct MatchCtx<'a> {
    pub row: &'a ConnectionRow,
    pub processes: &'a HashMap<u32, ProcessInfo>,
}

/// Free-text haystack covering all searchable fields, including the
/// `ip:port` display forms so plain `127.0.0.1:443` searches work.
pub fn haystack(row: &ConnectionRow, processes: &HashMap<u32, ProcessInfo>) -> String {
    let mut parts: Vec<String> = vec![
        row.process_display(),
        row.pid.to_string(),
        row.protocol.to_string(),
        row.local_display(),
        row.local_addr.to_string(),
        row.local_port.to_string(),
    ];
    if let (Some(a), Some(p)) = (row.remote_addr, row.remote_port) {
        parts.push(format!("{a}:{p}"));
        parts.push(a.to_string());
        parts.push(p.to_string());
    }
    if let Some(s) = row.state {
        parts.push(s.to_string());
    }
    if let Some(s) = &row.service_name {
        parts.push(s.clone());
    }
    if let Some(exe) = processes.get(&row.pid).and_then(|p| p.exe.as_deref()) {
        parts.push(exe.to_string());
    }
    parts.join(" ")
}

fn field_row_value(ctx: &MatchCtx<'_>, field: Field) -> RowValue {
    let row = ctx.row;
    match field {
        Field::Process => RowValue::Str(row.process_display()),
        Field::Path => match ctx.processes.get(&row.pid).and_then(|p| p.exe.clone()) {
            Some(exe) => RowValue::Str(exe),
            None => RowValue::Missing,
        },
        Field::Pid => RowValue::Num(row.pid as u64),
        Field::Proto => RowValue::Str(
            match row.protocol {
                Protocol::Tcp => "tcp",
                Protocol::Udp => "udp",
            }
            .to_string(),
        ),
        Field::State => match row.state {
            Some(s) => RowValue::Str(s.to_string().to_ascii_lowercase()),
            None => RowValue::Missing,
        },
        Field::LocalAddr => RowValue::Str(row.local_addr.to_string()),
        Field::RemoteAddr => match row.remote_addr {
            Some(a) => RowValue::Str(a.to_string()),
            None => RowValue::Missing,
        },
        Field::AnyAddr => RowValue::Multi(vec![
            RowValue::Str(row.local_addr.to_string()),
            match row.remote_addr {
                Some(a) => RowValue::Str(a.to_string()),
                None => RowValue::Missing,
            },
        ]),
        Field::LocalPort => RowValue::Num(row.local_port as u64),
        Field::RemotePort => RowValue::Num(row.remote_port.unwrap_or(0) as u64),
        Field::AnyPort => RowValue::Multi(vec![
            RowValue::Num(row.local_port as u64),
            RowValue::Num(row.remote_port.unwrap_or(0) as u64),
        ]),
        Field::Service => match &row.service_name {
            Some(s) if !s.is_empty() => RowValue::Str(s.clone()),
            _ => RowValue::Missing,
        },
        Field::Tx => RowValue::Num(row.tx_bytes.unwrap_or(0)),
        Field::Rx => RowValue::Num(row.rx_bytes.unwrap_or(0)),
        Field::Change => RowValue::Str(
            match row.change {
                RowChange::New => "new",
                RowChange::Changed => "changed",
                RowChange::Deleted => "deleted",
                RowChange::Unchanged => "unchanged",
            }
            .to_string(),
        ),
        Field::Loopback => RowValue::Bool(row.is_loopback()),
        Field::Connected => RowValue::Bool(row.is_connected_tcp()),
    }
}

fn wildcard_match(pattern: &str, text: &str) -> bool {
    // Classic `*`/`?` glob, case-insensitive, via a tiny DP over chars.
    let p: Vec<char> = pattern.to_ascii_lowercase().chars().collect();
    let t: Vec<char> = text.to_ascii_lowercase().chars().collect();
    let mut dp = vec![vec![false; t.len() + 1]; p.len() + 1];
    dp[0][0] = true;
    for (i, pc) in p.iter().enumerate() {
        if *pc == '*' {
            dp[i + 1][0] = dp[i][0];
        }
        for (j, tc) in t.iter().enumerate() {
            dp[i + 1][j + 1] = match pc {
                '*' => dp[i][j + 1] || dp[i + 1][j],
                '?' => dp[i][j],
                c => dp[i][j] && *c == *tc,
            };
        }
    }
    dp[p.len()][t.len()]
}

fn match_str(op: Op, value: &Value, text: &str) -> bool {
    match value {
        Value::Str(pat) => match op {
            Op::Eq => {
                if pat.contains('*') || pat.contains('?') {
                    wildcard_match(pat, text)
                } else {
                    text.eq_ignore_ascii_case(pat)
                }
            }
            Op::Ne => {
                if pat.contains('*') || pat.contains('?') {
                    !wildcard_match(pat, text)
                } else {
                    !text.eq_ignore_ascii_case(pat)
                }
            }
            Op::Contains => text
                .to_ascii_lowercase()
                .contains(&pat.to_ascii_lowercase()),
            _ => false,
        },
        Value::Regex(re) => match op {
            Op::Regex => re.is_match(text),
            Op::NotRegex => !re.is_match(text),
            _ => false,
        },
        Value::Num(n) => match op {
            Op::Contains => text.contains(&n.to_string()),
            _ => false,
        },
    }
}

fn match_row_value(op: Op, value: &Value, rv: &RowValue) -> bool {
    match rv {
        RowValue::Missing => matches!(op, Op::Ne),
        RowValue::Str(s) => match_str(op, value, s),
        RowValue::Num(n) => match value {
            Value::Num(v) => match op {
                Op::Eq => n == v,
                Op::Ne => n != v,
                Op::Gt => n > v,
                Op::Ge => n >= v,
                Op::Lt => n < v,
                Op::Le => n <= v,
                _ => false,
            },
            Value::Str(pat) => match op {
                Op::Contains => n.to_string().contains(pat.as_str()),
                Op::Eq => wildcard_match(pat, &n.to_string()),
                _ => false,
            },
            Value::Regex(re) => match op {
                Op::Regex => re.is_match(&n.to_string()),
                Op::NotRegex => !re.is_match(&n.to_string()),
                _ => false,
            },
        },
        RowValue::Bool(b) => {
            if let Value::Str(pat) = value {
                let want = matches!(
                    pat.to_ascii_lowercase().as_str(),
                    "true" | "yes" | "1" | "on"
                );
                match op {
                    Op::Eq => *b == want,
                    Op::Ne => *b != want,
                    _ => false,
                }
            } else {
                false
            }
        }
        RowValue::Multi(list) => match op {
            Op::Ne => list.iter().all(|v| !match_row_value(Op::Eq, value, v)),
            _ => list.iter().any(|v| match_row_value(op, value, v)),
        },
    }
}

/// Evaluate an expression against a row.
pub fn matches(expr: &Expr, ctx: &MatchCtx<'_>) -> bool {
    match expr {
        Expr::And(a, b) => matches(a, ctx) && matches(b, ctx),
        Expr::Or(a, b) => matches(a, ctx) || matches(b, ctx),
        Expr::Not(a) => !matches(a, ctx),
        Expr::Any(t) => haystack(ctx.row, ctx.processes)
            .to_ascii_lowercase()
            .contains(&t.to_ascii_lowercase()),
        Expr::Pred(p) => {
            let rv = field_row_value(ctx, p.field);
            match_row_value(p.op, &p.value, &rv)
        }
    }
}

/// Does the input contain operator characters that route it to the
/// expression parser instead of plain-text search?
pub fn looks_structured(input: &str) -> bool {
    input.contains(['=', '<', '>', '~'])
        || input.contains(" and ")
        || input.contains(" or ")
        || input.contains(" not ")
        || input.starts_with("not ")
}

/// Parse a filter string into an expression.
pub fn parse(input: &str) -> Result<Expr, String> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err("empty filter".to_string());
    }
    let toks = tokenize(trimmed)?;
    let mut parser = Parser { toks, pos: 0 };
    let expr = parser.parse_or()?;
    if let Some(t) = parser.peek() {
        return Err(format!(
            "unexpected {} after the end of the filter",
            describe(&Some(t.clone()))
        ));
    }
    Ok(expr)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    fn row() -> ConnectionRow {
        let mut r = ConnectionRow::new(
            Protocol::Tcp,
            v4(192, 168, 1, 10),
            50001,
            Some(v4(142, 250, 4, 46)),
            Some(443),
            Some(netstat2::TcpState::Established),
            4242,
        );
        r.process_name = Some("chrome.exe".into());
        r.service_name = Some("Google Chrome".into());
        r.tx_bytes = Some(2 * 1024 * 1024);
        r.rx_bytes = Some(500 * 1024);
        r
    }

    fn m(expr: &Expr, r: &ConnectionRow) -> bool {
        matches(
            expr,
            &MatchCtx {
                row: r,
                processes: &HashMap::new(),
            },
        )
    }

    #[test]
    fn field_equality_and_aliases() {
        let e = parse("process=chrome.exe").unwrap();
        assert!(m(&e, &row()));

        let e = parse("proc=chrome").unwrap(); // alias + exact only
        assert!(!m(&e, &row()), "proc=chrome is exact, not substring");

        let e = parse("proto=tcp").unwrap();
        assert!(m(&e, &row()));

        let e = parse("state=ESTABLISHED").unwrap();
        assert!(m(&e, &row()));
    }

    #[test]
    fn contains_and_regex_operators() {
        let e = parse("process:chrome").unwrap();
        assert!(m(&e, &row()));

        let e = parse("process~=^chrome.*exe$").unwrap();
        assert!(m(&e, &row()));

        let e = parse("process!~firefox").unwrap();
        assert!(m(&e, &row()));
    }

    #[test]
    fn numeric_comparisons_and_ports() {
        let r = row();
        assert!(m(&parse("pid>1000").unwrap(), &r));
        assert!(m(&parse("pid<10000").unwrap(), &r));
        assert!(m(&parse("pid=4242").unwrap(), &r));
        assert!(!m(&parse("pid=1").unwrap(), &r));

        assert!(m(&parse("lport=50001").unwrap(), &r));
        assert!(m(&parse("rport=443").unwrap(), &r));
        assert!(
            m(&parse("port=443").unwrap(), &r),
            "port matches either side"
        );
        assert!(m(&parse("port=50001").unwrap(), &r));
        assert!(!m(&parse("port=8080").unwrap(), &r));
    }

    #[test]
    fn byte_units_for_tx_rx() {
        let r = row();
        assert!(m(&parse("tx>1mb").unwrap(), &r));
        assert!(m(&parse("tx>1MB").unwrap(), &r));
        assert!(!m(&parse("tx>3mb").unwrap(), &r));
        assert!(m(&parse("rx<1gb").unwrap(), &r));
        assert!(m(&parse("rx>=500kb").unwrap(), &r));
    }

    #[test]
    fn address_wildcards_and_any_addr() {
        let r = row();
        assert!(m(&parse("laddr=192.168.*").unwrap(), &r));
        assert!(m(&parse("raddr=142.250.*").unwrap(), &r));
        assert!(
            m(&parse("addr=142.250.4.46").unwrap(), &r),
            "addr matches either side"
        );
        assert!(m(&parse("addr=192.168.1.10").unwrap(), &r));
        assert!(!m(&parse("addr=10.*").unwrap(), &r));
    }

    #[test]
    fn boolean_fields() {
        let r = row();
        assert!(m(&parse("loopback=false").unwrap(), &r));
        assert!(!m(&parse("loopback=true").unwrap(), &r));
        assert!(m(&parse("connected=true").unwrap(), &r));

        let mut local = ConnectionRow::new(
            Protocol::Tcp,
            v4(127, 0, 0, 1),
            8080,
            Some(v4(127, 0, 0, 1)),
            Some(8081),
            Some(netstat2::TcpState::Established),
            1,
        );
        local.process_name = Some("app.exe".into());
        assert!(m(&parse("loopback=true").unwrap(), &local));
    }

    #[test]
    fn change_field() {
        let mut r = row();
        r.change = RowChange::New;
        assert!(m(&parse("change=new").unwrap(), &r));
        assert!(!m(&parse("change=deleted").unwrap(), &r));
    }

    #[test]
    fn boolean_logic_and_precedence() {
        let r = row();
        // and binds tighter than or.
        let e = parse("process=firefox or proto=tcp and port=443").unwrap();
        assert!(m(&e, &r));
        let e = parse("(process=firefox or proto=tcp) and port=8443").unwrap();
        assert!(!m(&e, &r));
        let e = parse("not (proto=udp or port=8443)").unwrap();
        assert!(m(&e, &r));
        let e = parse("process=chrome* && port=443").unwrap();
        assert!(m(&e, &r));
        let e = parse("proto=udp || process=chrome*").unwrap();
        assert!(m(&e, &r));
    }

    #[test]
    fn quoted_strings_allow_spaces() {
        let e = parse("process=\"google chrome\"").unwrap();
        assert!(
            !m(&e, &row()),
            "process name is chrome.exe, not the service"
        );
        let e = parse("service=\"google chrome\"").unwrap();
        assert!(m(&e, &row()));
    }

    #[test]
    fn plain_addr_with_port_stays_free_text() {
        // `127.0.0.1:443` must NOT be treated as a broken predicate: the
        // left side is not identifier-like, so it degrades to free text.
        let e = parse("127.0.0.1:443").unwrap();
        assert!(matches!(e, Expr::And(_, _) | Expr::Any(_)));

        let mut local = row();
        local.local_addr = v4(127, 0, 0, 1);
        local.id.local = std::net::SocketAddr::new(local.local_addr, 50001);
        local.remote_addr = Some(v4(127, 0, 0, 1));
        local.remote_port = Some(443);
        local.id.remote = Some(std::net::SocketAddr::new(v4(127, 0, 0, 1), 443));
        assert!(m(&parse("127.0.0.1:443").unwrap(), &local));
    }

    #[test]
    fn missing_values_fail_ne() {
        let mut r = row();
        r.remote_addr = None;
        r.remote_port = None;
        assert!(
            m(&parse("raddr!=8.8.8.8").unwrap(), &r),
            "no remote counts as not-equal"
        );
        assert!(!m(&parse("raddr=8.8.8.8").unwrap(), &r));
    }

    #[test]
    fn parse_errors_are_helpful() {
        assert!(
            parse("bogus=1")
                .unwrap_err()
                .contains("unknown field 'bogus'")
        );
        assert!(parse("pid>").unwrap_err().contains("value is required"));
        assert!(parse("(pid=1").unwrap_err().contains("')'"));
        assert!(parse("process=~[").unwrap_err().contains("invalid regex"));
        assert!(
            parse("\"unterminated")
                .unwrap_err()
                .contains("unterminated")
        );
    }

    #[test]
    fn routing_between_plain_and_structured() {
        assert!(!looks_structured("chrome"));
        assert!(!looks_structured("127.0.0.1"));
        assert!(looks_structured("pid=1"));
        assert!(looks_structured("a and b"));
        assert!(looks_structured("tx>1mb"));
    }

    #[test]
    fn display_round_trips_visually() {
        let e = parse("process:chrome and port=443").unwrap();
        let text = e.to_string();
        assert!(text.contains("port=443"));
    }
}
