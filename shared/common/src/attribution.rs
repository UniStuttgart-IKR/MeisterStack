// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

// shared/common/src/attribution.rs

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
