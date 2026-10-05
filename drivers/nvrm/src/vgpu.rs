// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! What `vgpuprofile --select <type>` says about one type on this card.

use std::collections::HashMap;

/// One vGPU type as this card resolves it.
#[derive(Clone, Debug, PartialEq)]
pub struct VgpuType {
    pub vgpu_type: String,
    pub profile_mib: u64,
    pub fb_mib: u64,
    pub max_instance: u64,
    pub encoder_cap: u64,
    /// `vgpu_available_mib`: what the card offers all guests together. Profile
    /// sizes already carry their share of the card's carve-out, so this is the
    /// sum they are measured against (Leandro `Catalogue::admits`).
    pub available_mib: u64,
}

/// Parse the KEY=VALUE stdout of `vgpuprofile --select`.
pub(crate) fn parse_vgpu_select(stdout: &str) -> anyhow::Result<VgpuType> {
    let mut kv = HashMap::new();
    for line in stdout.lines() {
        if let Some((k, v)) = line.split_once('=') {
            kv.insert(k.trim(), v.trim());
        }
    }
    let get = |k: &str| -> anyhow::Result<&str> {
        kv.get(k).copied().ok_or_else(|| {
            anyhow::anyhow!("vgpuprofile output is missing {k}= (got: {:?})", kv.keys())
        })
    };
    let num = |k: &str| -> anyhow::Result<u64> {
        get(k)?
            .parse()
            .map_err(|e| anyhow::anyhow!("vgpuprofile {k}: {e}"))
    };
    Ok(VgpuType {
        vgpu_type: get("vgpu_type")?.to_string(),
        profile_mib: num("vgpu_profile_mib")?,
        fb_mib: num("vgpu_fb_mib")?,
        max_instance: num("vgpu_max_instance")?,
        encoder_cap: num("vgpu_encoder_cap")?,
        available_mib: num("vgpu_available_mib")?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A `vgpuprofile` that does not print the card size cannot be admitted against.
    #[test]
    fn select_output_without_the_card_size_is_refused() {
        let out = "vgpu_type=RTX2070-4Q\nvgpu_profile_mib=4096\nvgpu_fb_mib=2816\n\
                   vgpu_max_instance=2\nvgpu_encoder_cap=50\n";
        let said = parse_vgpu_select(out)
            .expect_err("unknown card size")
            .to_string();
        assert!(said.contains("vgpu_available_mib"), "{said}");
    }

    #[test]
    fn parses_vgpuprofile_select_output() {
        let out = "vgpu_type=RTX2070-4Q\nvgpu_profile_mib=4096\nvgpu_fb_mib=2816\n\
                   vgpu_max_instance=2\nvgpu_segments=11\nvgpu_segment_mib=256\n\
                   vgpu_encoder_cap=50\nvgpu_available_mib=8192\n";
        let v = parse_vgpu_select(out).expect("a complete answer");
        assert_eq!(
            v,
            VgpuType {
                vgpu_type: "RTX2070-4Q".into(),
                profile_mib: 4096,
                fb_mib: 2816,
                max_instance: 2,
                encoder_cap: 50,
                available_mib: 8192,
            }
        );
        assert!(parse_vgpu_select("prose only, no keys\n").is_err());
    }
}
