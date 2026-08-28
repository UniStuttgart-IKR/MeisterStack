// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

// shared/common/src/attribution.rs

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AiModel {
    ClaudeOpus,
    ClaudeSonnet,
    ClaudeHaiku,
    ClaudeFable,
    ClaudeMythos,
    Gpt,
    Gemini,
}

impl AiModel {
    pub const ALL: &'static [(&'static str, Self)] = &[
        ("ClaudeOpus", Self::ClaudeOpus),
        ("ClaudeSonnet", Self::ClaudeSonnet),
        ("ClaudeHaiku", Self::ClaudeHaiku),
        ("ClaudeFable", Self::ClaudeFable),
        ("Gpt", Self::Gpt),
        ("Gemini", Self::Gemini),
    ];

    /// `parse` and not `from_str`: the std trait of that name returns a
    /// Result, and a method that looks like it but does not behave like it is
    /// the kind of thing that gets called by mistake. Same spelling as
    /// `VmPhase::parse` one crate over.
    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL
            .iter()
            .find(|(name, _)| *name == s)
            .map(|(_, m)| *m)
    }

    pub fn names() -> impl Iterator<Item = &'static str> {
        Self::ALL.iter().map(|(name, _)| *name)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum License {
    Mit,
    Apache2,
    CcBySa4,
    Unlicense,
    Gpl3,
    Gpl2,
}

impl License {
    pub const ALL: &'static [(&'static str, Self)] = &[
        ("MIT", Self::Mit),
        ("Apache2", Self::Apache2),
        ("CcBySa4", Self::CcBySa4),
        ("Unlicense", Self::Unlicense),
        ("Gpl3", Self::Gpl3),
        ("Gpl2", Self::Gpl2),
    ];

    /// See `AiModel::parse`.
    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL
            .iter()
            .find(|(name, _)| *name == s)
            .map(|(_, l)| *l)
    }

    pub fn names() -> impl Iterator<Item = &'static str> {
        Self::ALL.iter().map(|(name, _)| *name)
    }
}
