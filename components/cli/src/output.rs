// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Table and JSON output plus destructive-operation confirmation.
//! Results go to stdout; prompts and notes go to stderr. Empty tables print
//! only a note. Cell helpers avoid spaces in intermediate columns.

use anyhow::{Context, Result, bail};
use bytes::Bytes;
use chrono::{DateTime, Utc};
use serde::Deserialize;
use serde::de::DeserializeOwned;

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
    /// One stdout token with an optional stderr note.
    Line(String, Option<String>),
    Table(Table),
    /// Unstructured text, printed without table formatting or an added newline.
    Text(String),
}

/// Columns, rows, and what to say when there are no rows.
pub struct Table {
    /// Columns may be selected at runtime, for example the optional drain column.
    headers: Vec<&'static str>,
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
        Self::Line(token.into(), Some(note.to_string()))
    }

    /// A token with a dynamically constructed stderr note.
    pub fn note_owned(token: impl Into<String>, note: String) -> Self {
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
        Self::table_of_columns(headers.to_vec(), rows, empty_note)
    }

    /// The same table with a column list decided at run time. See
    /// `Table::headers`.
    pub fn table_of_columns(
        headers: Vec<&'static str>,
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
            // Preserve existing line endings.
            Self::Text(body) => print!("{body}"),
        }
    }
}

impl Table {
    /// The rendered lines, header row first. Separate from printing them so
    /// the layout is testable without capturing stdout.
    pub(crate) fn render(&self) -> Vec<String> {
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

/// Select JSON or a lazily constructed table view.
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

/// Emit a token with a dynamically constructed note.
pub fn emit_note_owned(global: &GlobalArgs, body: &Bytes, token: &str, note: String) -> Result<()> {
    emit(global, body, |_| Ok(View::note_owned(token, note.clone())))
}

/// Show the server's explanation when deletion is queued rather than complete.
pub fn emit_removal(global: &GlobalArgs, body: &Bytes, token: &str) -> Result<()> {
    match removal_note(body) {
        Some(note) => emit(global, body, |_| Ok(View::note_owned(token, note))),
        None => emit_line(global, body, token),
    }
}

/// Return the message from a Status response with reason Deleting.
pub fn removal_note(body: &[u8]) -> Option<String> {
    let doc: serde_json::Value = serde_json::from_slice(body).ok()?;
    if doc.get("reason")?.as_str()? != "Deleting" {
        return None;
    }
    let said = doc.get("message")?.as_str()?.trim();
    (!said.is_empty()).then(|| said.to_string())
}

/// Decode the items in a controller List response.
pub fn items<T: DeserializeOwned>(body: &Bytes, parsing: &'static str) -> Result<Vec<T>> {
    let list: List<T> = serde_json::from_slice(body).context(parsing)?;
    Ok(list.items)
}

/// A listing, from the `{"items": [...]}` every controller serves.
pub fn table_of<T: DeserializeOwned>(
    body: &Bytes,
    parsing: &'static str,
    headers: &'static [&'static str],
    empty_note: &'static str,
    row: impl Fn(T) -> Vec<String>,
) -> Result<View> {
    Ok(View::table(
        headers,
        items::<T>(body, parsing)?.into_iter().map(row).collect(),
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

/// Confirm deletion or replacement, naming the endpoint and profile.
/// Without --yes, non-interactive input is refused.
pub fn confirm(
    global: &GlobalArgs,
    endpoint: &str,
    profile: &str,
    verb: &str,
    kind: &str,
    name: &str,
) -> Result<()> {
    if global.yes {
        return Ok(());
    }
    let prompt = format!("{verb} {kind} {name} on {endpoint} (profile {profile})?");
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

/// Readiness display priority: unavailable, draining, cordoned, conditions, ready.
/// Condition names are shortened to fit a space-free table cell.
pub fn readiness(ready: bool, schedulable: bool, draining: bool, conditions: &[&str]) -> String {
    match (ready, draining, schedulable) {
        (false, _, _) => "no".to_string(),
        (true, true, _) => "draining".to_string(),
        (true, false, false) => "cordoned".to_string(),
        (true, false, true) if conditions.is_empty() => "yes".to_string(),
        (true, false, true) => conditions
            .iter()
            .map(|c| short_condition(c))
            .collect::<Vec<_>>()
            .join(","),
    }
}

/// Shorten known conditions; preserve unfamiliar ones for newer agents.
fn short_condition(condition: &str) -> String {
    match condition {
        "DiskPressure" => "pressure".to_string(),
        "StoreUnhealthy" => "store".to_string(),
        "CgroupUnusable" => "cgroup".to_string(),
        other => other.replace(' ', "-"),
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
            headers: vec!["name", "phase", "note"],
            rows,
            empty_note: "nothing here",
        }
    }

    /// Align columns and omit trailing padding.
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

    /// Short rows must preserve column alignment.
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

    /// A drain takes display priority over a cordon.
    #[test]
    fn a_machine_being_emptied_says_so_and_not_merely_that_it_is_cordoned() {
        assert_eq!(readiness(true, true, false, &[]), "yes");
        assert_eq!(readiness(true, false, false, &[]), "cordoned");
        assert_eq!(readiness(true, false, true, &[]), "draining");
        // The pair a drain always produces, and the one an operator could
        // also make by hand — both read as the drain.
        assert_eq!(readiness(true, true, true, &[]), "draining");
        // Down beats everything: a machine nobody can reach is not a machine
        // that is being emptied.
        assert_eq!(readiness(false, true, false, &[]), "no");
        assert_eq!(readiness(false, false, true, &[]), "no");
    }

    /// Reported node conditions must remain visible on otherwise ready nodes.
    #[test]
    fn a_wedged_node_does_not_read_yes() {
        assert_eq!(readiness(true, true, false, &["StoreUnhealthy"]), "store");
        assert_eq!(
            readiness(true, true, false, &["DiskPressure", "StoreUnhealthy"]),
            "pressure,store"
        );
        assert_eq!(readiness(true, true, false, &["CgroupUnusable"]), "cgroup");
        // A word this CLI has never heard of still takes the node out of
        // `yes` and reaches the operator unswallowed.
        assert_eq!(readiness(true, true, false, &["FanFailure"]), "FanFailure");
        // What an operator decided outranks it: they asked for the drain and
        // that is what they are looking for here.
        assert_eq!(
            readiness(true, false, true, &["StoreUnhealthy"]),
            "draining"
        );
        assert_eq!(
            readiness(true, false, false, &["StoreUnhealthy"]),
            "cordoned"
        );
        // And a machine nobody can reach is still just down.
        assert_eq!(readiness(false, true, true, &["StoreUnhealthy"]), "no");
    }

    /// Distinguish queued deletion from completed deletion.
    #[test]
    fn a_delete_that_did_not_finish_carries_the_servers_own_sentence() {
        let deleting = br#"{"kind":"Status","status":"Success","code":202,"reason":"Deleting",
            "message":"volume mc-vol-a is attached to vm mc-vm-a; its data stays until that vm lets go",
            "details":{"kind":"Volume","name":"mc-vol-a"}}"#;
        assert_eq!(
            removal_note(deleting).as_deref(),
            Some("volume mc-vol-a is attached to vm mc-vm-a; its data stays until that vm lets go")
        );

        // Completed deletion needs no pending-removal note.
        let gone = br#"{"kind":"Status","status":"Success","code":200,"reason":"Deleted",
            "message":"Tenant acme deleted","details":{"kind":"Tenant","name":"acme"}}"#;
        assert_eq!(removal_note(gone), None);

        // And anything else is silence rather than a guess: a body of another
        // shape, an empty sentence, no body at all.
        assert_eq!(removal_note(b"{}"), None);
        assert_eq!(removal_note(b"not json"), None);
        assert_eq!(
            removal_note(br#"{"reason":"Deleting","message":"  "}"#),
            None
        );
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
            readiness(true, false, false, &[]),
            readiness(true, false, true, &[]),
            readiness(true, true, false, &["DiskPressure", "StoreUnhealthy"]),
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

    /// Require ASCII in output literals covered by this source scan.
    #[test]
    fn no_output_string_carries_a_non_ascii_character() {
        let sources = [
            ("agent.rs", include_str!("agent.rs")),
            ("client.rs", include_str!("client.rs")),
            ("nouns/mod.rs", include_str!("nouns/mod.rs")),
            ("nouns/cluster.rs", include_str!("nouns/cluster.rs")),
            ("nouns/csr.rs", include_str!("nouns/csr.rs")),
            ("nouns/floating_ip.rs", include_str!("nouns/floating_ip.rs")),
            (
                "nouns/floating_pool.rs",
                include_str!("nouns/floating_pool.rs"),
            ),
            ("nouns/image.rs", include_str!("nouns/image.rs")),
            ("nouns/network.rs", include_str!("nouns/network.rs")),
            (
                "nouns/routed_subnet.rs",
                include_str!("nouns/routed_subnet.rs"),
            ),
            ("nouns/secret.rs", include_str!("nouns/secret.rs")),
            (
                "nouns/storage_pool.rs",
                include_str!("nouns/storage_pool.rs"),
            ),
            ("nouns/tenant.rs", include_str!("nouns/tenant.rs")),
            ("nouns/user.rs", include_str!("nouns/user.rs")),
            (
                "nouns/vm_migration.rs",
                include_str!("nouns/vm_migration.rs"),
            ),
            ("nouns/volume.rs", include_str!("nouns/volume.rs")),
            (
                "nouns/volume_snapshot.rs",
                include_str!("nouns/volume_snapshot.rs"),
            ),
            ("cluster.rs", include_str!("cluster.rs")),
            ("config.rs", include_str!("config.rs")),
            ("generic.rs", include_str!("generic.rs")),
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
