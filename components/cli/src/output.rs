// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Everything this CLI puts on a terminal, and the one question it asks back.
//!
//! Every verb answers the same two ways, and that is decided here rather than
//! thirty times over: `-o json` prints the server's own object, whole and
//! unedited, and `-o table` prints columns a person reads and `awk` can cut
//! up. Three rules come with it, and they only hold because there is one
//! place left to hold them in:
//!
//! * the answer goes to stdout and nothing else does — notes, prompts and
//!   complaints are stderr, so a pipeline gets the value and a person still
//!   gets told what happened;
//! * an empty list is a note on stderr, never headers printed over nothing;
//! * no cell but the one in the last column may carry a raw space, because a
//!   space in a middle column shifts every `awk` field behind it.

use anyhow::{Context, Result, bail};
use bytes::Bytes;
use chrono::{DateTime, Utc};
use serde::Deserialize;
use serde::de::DeserializeOwned;

use crate::config::Target;
use crate::{GlobalArgs, OutputFormat};

/// The K8s-style list every controller endpoint serves. The agent's own REST
/// api predates that shape and answers with a bare array — see
/// [`table_of_array`].
#[derive(Deserialize)]
pub struct List<T> {
    pub items: Vec<T>,
}

/// What a command has to say once the server has answered.
pub enum View {
    /// One token on stdout — the id, the name, the state now in force — and
    /// optionally a caveat on stderr. stdout stays pipeable either way.
    Line(String, Option<&'static str>),
    Table(Table),
    /// Lines of somebody else's text — a guest's console, and nothing else so
    /// far. Its own variant rather than a `Line` with newlines in it because
    /// the two have opposite rules: a token is one word this CLI chose and is
    /// safe to put in a cell, and this is arbitrary bytes a guest emitted,
    /// which no table can hold and which must reach stdout unchanged.
    Text(String),
}

/// Columns, rows, and what to say when there are no rows.
pub struct Table {
    headers: &'static [&'static str],
    rows: Vec<Vec<String>>,
    empty_note: &'static str,
}

impl View {
    pub fn line(token: impl Into<String>) -> Self {
        Self::Line(token.into(), None)
    }

    /// A token plus something the operator has to know and cannot read off
    /// the token. The note is stderr, so stdout is still just the token.
    pub fn note(token: impl Into<String>, note: &'static str) -> Self {
        Self::Line(token.into(), Some(note))
    }

    pub fn text(body: impl Into<String>) -> Self {
        Self::Text(body.into())
    }

    pub fn table(
        headers: &'static [&'static str],
        rows: Vec<Vec<String>>,
        empty_note: &'static str,
    ) -> Self {
        Self::Table(Table {
            headers,
            rows,
            empty_note,
        })
    }

    fn print(self) {
        match self {
            Self::Line(token, note) => {
                println!("{token}");
                if let Some(note) = note {
                    eprintln!("{note}");
                }
            }
            Self::Table(table) => table.print(),
            // Printed as it stands. The server already ended it with a
            // newline per stream, and adding another would put a blank line
            // under every `vm logs`.
            Self::Text(body) => print!("{body}"),
        }
    }
}

impl Table {
    /// The rendered lines, header row first. Separate from printing them so
    /// the layout is testable without capturing stdout.
    fn render(&self) -> Vec<String> {
        let mut widths: Vec<usize> = self.headers.iter().map(|h| h.len()).collect();
        for row in &self.rows {
            for (i, cell) in row.iter().enumerate() {
                if i < widths.len() {
                    widths[i] = widths[i].max(cell.chars().count());
                }
            }
        }

        let line = |cells: &[String]| {
            let rendered: Vec<String> = cells
                .iter()
                .enumerate()
                .map(|(i, c)| {
                    let pad = widths.get(i).copied().unwrap_or(0);
                    format!("{c:<pad$}")
                })
                .collect();
            rendered.join("  ").trim_end().to_string()
        };

        let mut out = vec![line(
            &self
                .headers
                .iter()
                .map(|h| h.to_uppercase())
                .collect::<Vec<_>>(),
        )];
        out.extend(self.rows.iter().map(|row| line(row)));
        out
    }

    fn print(self) {
        if self.rows.is_empty() {
            eprintln!("{}", self.empty_note);
            return;
        }
        for line in self.render() {
            println!("{line}");
        }
    }
}

/// The one place a server's answer turns into output.
///
/// The table view is built lazily and only when it is asked for: a body the
/// table side cannot parse still comes out under `-o json`, which is exactly
/// where an operator looks when the table gave up.
pub fn emit(
    global: &GlobalArgs,
    body: &Bytes,
    view: impl FnOnce(&Bytes) -> Result<View>,
) -> Result<()> {
    match global.output {
        OutputFormat::Json => print_json(body),
        OutputFormat::Table => view(body)?.print(),
    }
    Ok(())
}

/// The common case: under `-o table` the answer is one token the caller
/// already holds, and under `-o json` it is still the whole object.
pub fn emit_line(global: &GlobalArgs, body: &Bytes, token: &str) -> Result<()> {
    emit(global, body, |_| Ok(View::line(token)))
}

/// [`emit_line`] plus a caveat on stderr.
pub fn emit_note(global: &GlobalArgs, body: &Bytes, token: &str, note: &'static str) -> Result<()> {
    emit(global, body, |_| Ok(View::note(token, note)))
}

/// A listing, from the `{"items": [...]}` every controller serves.
pub fn table_of<T: DeserializeOwned>(
    body: &Bytes,
    parsing: &'static str,
    headers: &'static [&'static str],
    empty_note: &'static str,
    row: impl Fn(T) -> Vec<String>,
) -> Result<View> {
    let list: List<T> = serde_json::from_slice(body).context(parsing)?;
    Ok(View::table(
        headers,
        list.items.into_iter().map(row).collect(),
        empty_note,
    ))
}

/// A listing from a bare array — the agent's REST api, which has no list
/// object around its items.
pub fn table_of_array<T: DeserializeOwned>(
    body: &Bytes,
    parsing: &'static str,
    headers: &'static [&'static str],
    empty_note: &'static str,
    row: impl Fn(T) -> Vec<String>,
) -> Result<View> {
    let items: Vec<T> = serde_json::from_slice(body).context(parsing)?;
    Ok(View::table(
        headers,
        items.into_iter().map(row).collect(),
        empty_note,
    ))
}

/// A fixed two-column table: what a single object says about itself.
pub fn fields(rows: Vec<Vec<String>>) -> View {
    View::table(&["field", "value"], rows, "nothing to report")
}

pub fn print_json(bytes: &Bytes) {
    match serde_json::from_slice::<serde_json::Value>(bytes) {
        Ok(v) => println!("{}", serde_json::to_string_pretty(&v).unwrap_or_default()),
        Err(_) => println!("{}", String::from_utf8_lossy(bytes)),
    }
}

/// The guard in front of every destructive verb.
///
/// One helper and one sentence, because the alternative is what this replaced:
/// a prompt on `vm destroy` and nothing at all on the seven `rm`s beside it,
/// one of which cascades. `--yes` is the way to mean it, and a pipe with no
/// tty is refused rather than answered for.
pub fn confirm_destructive(
    global: &GlobalArgs,
    target: &Target,
    kind: &str,
    name: &str,
) -> Result<()> {
    if global.yes {
        return Ok(());
    }
    let prompt = format!(
        "delete {kind} {name} on {} (profile {})?",
        target.endpoint, target.profile_name
    );
    if !ask(&prompt)? {
        bail!("aborted");
    }
    Ok(())
}

fn ask(prompt: &str) -> Result<bool> {
    use std::io::{BufRead, IsTerminal, Write};

    if !std::io::stdin().is_terminal() {
        bail!("{prompt} - refusing without a tty; pass --yes");
    }
    eprint!("{prompt} [y/N] ");
    std::io::stderr().flush()?;
    let mut line = String::new();
    std::io::stdin().lock().read_line(&mut line)?;
    Ok(matches!(line.trim(), "y" | "Y" | "yes"))
}

// --- cells ------------------------------------------------------------------
//
// How a scalar becomes a column. Shared by all three tiers, and none of them
// may produce a raw space: see the module header.

/// Drained is worth its own word: the node is up and reporting, the
/// scheduler just will not place anything new on it.
pub fn readiness(ready: bool, schedulable: bool) -> &'static str {
    match (ready, schedulable) {
        (false, _) => "no",
        (true, false) => "drained",
        (true, true) => "yes",
    }
}

pub fn age(ts: Option<DateTime<Utc>>, now: DateTime<Utc>) -> String {
    let Some(ts) = ts else {
        return "never".to_string();
    };
    let secs = now.signed_duration_since(ts).num_seconds().max(0);
    match secs {
        s if s < 60 => format!("{s}s"),
        s if s < 3600 => format!("{}m{}s", s / 60, s % 60),
        s => format!("{}h{}m", s / 3600, (s % 3600) / 60),
    }
}

/// How long until something, in the same shape `age` reads backwards.
pub fn age_until(ts: DateTime<Utc>, now: DateTime<Utc>) -> String {
    let secs = ts.signed_duration_since(now).num_seconds();
    if secs <= 0 {
        return "expired".to_string();
    }
    match secs {
        s if s < 3600 => format!("{}m", s / 60),
        s if s < 86_400 => format!("{}h", s / 3600),
        s => format!("{}d", s / 86_400),
    }
}

pub fn mem(mib: u64) -> String {
    match mib {
        0 => "-".to_string(),
        m if m >= 1024 => format!("{:.1}Gi", m as f64 / 1024.0),
        m => format!("{m}Mi"),
    }
}

/// Sizes are recorded as bytes and read by humans. Binary units, because that
/// is what every other size in this stack means.
pub fn size(n: u64) -> String {
    const UNITS: [(&str, u64); 3] = [("Gi", 1 << 30), ("Mi", 1 << 20), ("Ki", 1 << 10)];
    if n == 0 {
        return "-".to_string();
    }
    for (suffix, scale) in UNITS {
        if n >= scale {
            return format!("{:.1}{suffix}", n as f64 / scale as f64);
        }
    }
    format!("{n}B")
}

/// The column of last resort: a value the server did not fill in.
pub fn or_dash(value: Option<String>) -> String {
    value.unwrap_or_else(|| "-".to_string())
}

/// A list of names as one cell. Comma-joined rather than space-joined for the
/// reason the module header gives.
pub fn joined(values: &[String]) -> String {
    if values.is_empty() {
        return "-".to_string();
    }
    values.join(",")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(cells: &[&str]) -> Vec<String> {
        cells.iter().map(|c| c.to_string()).collect()
    }

    fn table(rows: Vec<Vec<String>>) -> Table {
        Table {
            headers: &["name", "phase", "note"],
            rows,
            empty_note: "nothing here",
        }
    }

    /// Headers shout, columns line up on the widest cell, and the last one is
    /// not padded — a trailing run of spaces is invisible to a person and
    /// noise to everything else.
    #[test]
    fn columns_line_up_and_the_last_one_is_not_padded() {
        let rendered = table(vec![
            row(&["alpha", "Running", ""]),
            row(&["a-much-longer-name", "Stopped", "drifted"]),
        ])
        .render();

        assert_eq!(
            rendered,
            vec![
                "NAME                PHASE    NOTE",
                "alpha               Running",
                "a-much-longer-name  Stopped  drifted",
            ]
        );
    }

    /// A short row must not make the next column start early: every field
    /// after a missing cell would shift, which is the whole reason the table
    /// is padded rather than tab-separated.
    #[test]
    fn a_row_shorter_than_the_header_still_lines_up() {
        let rendered = table(vec![row(&["alpha", "Running"])]).render();
        assert_eq!(rendered[1], "alpha  Running");
    }

    /// An empty listing prints a sentence on stderr, so a table with no rows
    /// renders as nothing at all rather than as a lone header.
    #[test]
    fn an_empty_listing_has_no_lines_to_print() {
        let t = table(Vec::new());
        assert!(t.rows.is_empty());
        assert_eq!(t.empty_note, "nothing here");
    }

    #[test]
    fn heartbeat_age_reads_at_a_glance() {
        let at = |secs: i64| DateTime::from_timestamp(1_800_000_000 + secs, 0).unwrap();
        assert_eq!(age(Some(at(0)), at(7)), "7s");
        assert_eq!(age(Some(at(0)), at(130)), "2m10s");
        assert_eq!(age(Some(at(0)), at(7300)), "2h1m");
        assert_eq!(age(None, at(0)), "never");
        // A controller clock slightly ahead must not print a negative age.
        assert_eq!(age(Some(at(5)), at(0)), "0s");
    }

    #[test]
    fn time_left_reads_at_a_glance_and_never_goes_negative() {
        let now = Utc::now();
        assert_eq!(age_until(now + chrono::Duration::minutes(30), now), "30m");
        assert_eq!(age_until(now + chrono::Duration::hours(5), now), "5h");
        assert_eq!(age_until(now + chrono::Duration::days(89), now), "89d");
        assert_eq!(age_until(now - chrono::Duration::days(1), now), "expired");
    }

    #[test]
    fn a_drained_node_is_not_simply_ready() {
        assert_eq!(readiness(true, true), "yes");
        assert_eq!(readiness(true, false), "drained");
        assert_eq!(readiness(false, true), "no");
    }

    #[test]
    fn memory_is_shown_in_the_unit_that_fits() {
        assert_eq!(mem(512), "512Mi");
        assert_eq!(mem(64512), "63.0Gi");
        assert_eq!(mem(0), "-");
    }

    #[test]
    fn sizes_are_shown_in_the_unit_that_fits() {
        assert_eq!(size(0), "-");
        assert_eq!(size(512), "512B");
        assert_eq!(size(2 * 1024 * 1024 * 1024), "2.0Gi");
        assert_eq!(size(64 * 1024 * 1024), "64.0Mi");
    }

    /// Every cell any of these produces has to survive `awk`.
    #[test]
    fn no_cell_helper_produces_a_raw_space() {
        let now = Utc::now();
        let cells = vec![
            age(Some(now), now),
            age(None, now),
            age_until(now + chrono::Duration::hours(2), now),
            age_until(now, now),
            mem(0),
            mem(2048),
            size(0),
            size(1 << 34),
            readiness(true, false).to_string(),
            or_dash(None),
            joined(&[]),
            joined(&["a".to_string(), "b".to_string()]),
        ];
        for cell in cells {
            assert!(!cell.contains(' '), "{cell:?} carries a raw space");
        }
    }

    /// Everything on the line that is not a comment. `//` inside a string
    /// literal is a url, not a comment, which is why this needs a scanner and
    /// not a `find`.
    fn code_only(line: &str) -> String {
        let mut out = String::new();
        let (mut in_string, mut escaped) = (false, false);
        let mut chars = line.chars().peekable();
        while let Some(c) = chars.next() {
            if in_string {
                out.push(c);
                if escaped {
                    escaped = false;
                } else if c == '\\' {
                    escaped = true;
                } else if c == '"' {
                    in_string = false;
                }
                continue;
            }
            if c == '/' && chars.peek() == Some(&'/') {
                break;
            }
            out.push(c);
            if c == '"' {
                in_string = true;
            }
        }
        out
    }

    /// The house rule, kept by a test rather than by everybody remembering
    /// it: a comment may carry an umlaut, a string literal may not. What is
    /// in a literal ends up in somebody's terminal, their journal and their
    /// grep, and an em-dash there is a character none of those three agree
    /// on.
    #[test]
    fn no_output_string_carries_a_non_ascii_character() {
        let sources = [
            ("agent.rs", include_str!("agent.rs")),
            ("client.rs", include_str!("client.rs")),
            ("cloud.rs", include_str!("cloud.rs")),
            ("cluster.rs", include_str!("cluster.rs")),
            ("config.rs", include_str!("config.rs")),
            ("login.rs", include_str!("login.rs")),
            ("main.rs", include_str!("main.rs")),
            ("output.rs", include_str!("output.rs")),
            ("vm.rs", include_str!("vm.rs")),
        ];
        for (name, src) in sources {
            for (i, line) in src.lines().enumerate() {
                let code = code_only(line);
                assert!(
                    code.is_ascii(),
                    "{name}:{}: non-ascii outside a comment: {code}",
                    i + 1
                );
            }
        }
    }
}
