// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! What `vgpuprofile --select <type>` says about one type on this card.

use std::collections::HashMap;
use std::path::PathBuf;
use std::process::ExitStatus;

use crate::bounded::{Finished, RunError};

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

/// Why `vgpuprofile --select` did not resolve a type. Its `Display` is the
/// operator's, with what the helper said; [`ResolveError::for_tenant`] is
/// what whoever asked for the type may hear.
#[derive(Debug, thiserror::Error)]
pub(crate) enum ResolveError {
    #[error("running {}: {source}", .bin.display())]
    Run { bin: PathBuf, source: RunError },
    #[error("vgpuprofile --select {vtype} failed ({status}): {}", stderr_excerpt(.stderr))]
    Refused {
        vtype: String,
        status: ExitStatus,
        stderr: String,
    },
    #[error("vgpuprofile --select {vtype} answered something unreadable: {reason}")]
    Unreadable { vtype: String, reason: String },
    #[error("the task asking vgpuprofile ended early: {0}")]
    Task(String),
}

impl ResolveError {
    /// A fixed sentence for a request naming `vtype`: the types on offer
    /// when the card has no such type, nothing of the host otherwise.
    pub(crate) fn for_tenant(&self, vtype: &str) -> String {
        match self {
            ResolveError::Refused { stderr, .. } if stderr.contains(NO_SUCH_TYPE) => {
                match offered_types(stderr).as_slice() {
                    [] => format!("this node's card offers no vGPU type {vtype:?}"),
                    offered => format!(
                        "this node's card offers no vGPU type {vtype:?}; it offers {}",
                        offered.join(", ")
                    ),
                }
            }
            _ => format!(
                "vgpu_type {vtype:?} could not be resolved on this node; the agent's log \
                 says why"
            ),
        }
    }
}

/// What `vgpuprofile` says before its catalogue when the type is not on it.
const NO_SUCH_TYPE: &str = "no type or size";

/// The type names in the catalogue table `vgpuprofile` prints to stderr:
/// the first word of each row under the `type` header, up to the blank line
/// or note that ends it. Anything that does not look like a type name is
/// left out, so nothing else of the helper's output can pass for one.
fn offered_types(stderr: &str) -> Vec<String> {
    stderr
        .lines()
        .skip_while(|line| !line.trim_start().starts_with("type "))
        .skip(1)
        .take_while(|line| !line.trim().is_empty() && !line.trim_start().starts_with('('))
        .filter_map(|row| row.split_whitespace().next())
        .filter(|name| looks_like_a_type(name))
        .map(str::to_string)
        .collect()
}

fn looks_like_a_type(name: &str) -> bool {
    (1..=32).contains(&name.len())
        && name.contains('-')
        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
}

/// The type a successful `vgpuprofile --select` describes.
pub(crate) fn from_select(vtype: &str, out: &Finished) -> Result<VgpuType, ResolveError> {
    if !out.status.success() {
        return Err(ResolveError::Refused {
            vtype: vtype.to_string(),
            status: out.status,
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        });
    }
    parse_vgpu_select(&String::from_utf8_lossy(&out.stdout)).map_err(|e| ResolveError::Unreadable {
        vtype: vtype.to_string(),
        reason: format!("{e:#}"),
    })
}

/// The start of what the helper wrote to stderr, which is where its reason
/// is: a driver-version panic, or the types the card does offer.
fn stderr_excerpt(stderr: &str) -> String {
    const LIMIT: usize = 2048;
    let said = stderr.trim();
    if said.is_empty() {
        return "it wrote nothing to stderr".into();
    }
    match said.char_indices().nth(LIMIT) {
        Some((cut, _)) => format!("{}...", &said[..cut]),
        None => said.to_string(),
    }
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
pub(crate) mod tests {
    use super::*;

    /// What Leandro's `vgpuprofile --select 9Q` writes to stderr on an
    /// RTX 2070: the card's numbers first, then the catalogue.
    pub(crate) const SAID_FOR_9Q: &str = "\
vmmu segment size: 268435456 bytes = 256 MiB (asked the card)
fb total: 8192 MiB (TOTAL_RAM_SIZE), heap 7773 MiB (HEAP_SIZE), free now 7700 MiB
host reserve: 1024 MiB (LEA_VGPU_HOST_RESERVE_MIB)
board: \"GeForce RTX 2070\"
vgpuprofile: no type or size \"9Q\" on this card. It offers:
card RTX2070: 8192 MiB total, 6749 MiB usable heap, 419 MiB carved out by the card, 256 MiB VMMU segment
per-VM host overhead assumed: 256 MiB

type          max  profile   reserved   guest FB   segments   encoder%   all instances
RTX2070-1Q      6     1024        512        512          4         12          3072
RTX2070-2Q      3     2048        512       1536          8         25          4608
RTX2070-4Q      1     4096        768       3328         16         50          3328
";

    fn refused(stderr: &str) -> ResolveError {
        use std::os::unix::process::ExitStatusExt;
        ResolveError::Refused {
            vtype: "9Q".into(),
            status: ExitStatus::from_raw(1 << 8),
            stderr: stderr.into(),
        }
    }

    /// SEC-8: the tenant hears the type names and nothing of the host.
    #[test]
    fn a_tenant_hears_the_types_on_offer_and_nothing_else_of_the_host() {
        let said = refused(SAID_FOR_9Q).for_tenant("9Q");
        assert!(
            said.ends_with("it offers RTX2070-1Q, RTX2070-2Q, RTX2070-4Q"),
            "{said}"
        );
        for host_detail in ["board", "MiB", "reserve", "segment"] {
            assert!(!said.contains(host_detail), "{host_detail}: {said}");
        }
    }

    /// The operator's sentence keeps everything the helper said.
    #[test]
    fn the_operator_hears_what_vgpuprofile_said() {
        let said = refused(SAID_FOR_9Q).to_string();
        assert!(said.contains("board: \"GeForce RTX 2070\""), "{said}");
    }

    /// A failure that is not an unknown type tells the tenant only that.
    #[test]
    fn any_other_failure_tells_the_tenant_nothing_of_it() {
        let panic =
            "thread 'main' panicked: NVIDIA driver 570.86 is not the 575.51 this was built for";
        let said = refused(panic).for_tenant("4Q");
        assert!(said.contains("could not be resolved"), "{said}");
        assert!(!said.contains("570"), "{said}");
    }

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
