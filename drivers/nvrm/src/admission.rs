// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! The rules a backend is admitted by: what it counts as on the card, and why
//! it may not join the backends already counted.

use agent_api::device::{self, DeviceError, DeviceId};
use tracing::debug;

use crate::vgpu::VgpuType;

/// What one backend counts as for admission.
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub(crate) struct Claim {
    /// Admitted VRAM in MiB; see `NvrmParams::admitted_mib`.
    pub(crate) mib: u64,
    /// The type as `vgpuprofile` names it (`RTX2070-4Q`). A node may configure
    /// `4Q` or `rtx2070-4q` for the same type, and the instance limit must
    /// count all of them as one.
    pub(crate) vgpu_type: Option<String>,
    /// The card's `vgpu_available_mib`, known only for a vGPU-typed claim.
    pub(crate) card_mib: Option<u64>,
}

impl Claim {
    /// `mib` admitted, under the name and card size the card resolved, if any.
    pub(crate) fn new(mib: u64, vgpu: Option<&VgpuType>) -> Self {
        Self {
            mib,
            vgpu_type: vgpu.map(|v| v.vgpu_type.clone()),
            card_mib: vgpu.map(|v| v.available_mib),
        }
    }

    /// No cap, no profile size and no type: the backend may take the whole card.
    pub(crate) fn is_unbounded(&self) -> bool {
        self.mib == 0
    }
}

/// Refuse one more backend of a vGPU type the card already holds `max_instance` of.
pub(crate) fn refuse_instance_overflow(
    live: &[&Claim],
    vgpu: Option<&VgpuType>,
) -> device::Result<()> {
    let Some(vgpu) = vgpu else {
        return Ok(());
    };
    let same_type = live
        .iter()
        .filter(|c| c.vgpu_type.as_deref() == Some(vgpu.vgpu_type.as_str()))
        .count() as u64;
    if same_type >= vgpu.max_instance {
        return Err(DeviceError::InvalidSpec(format!(
            "vGPU type {} allows {} instance(s) on this card, {} already active",
            vgpu.vgpu_type, vgpu.max_instance, same_type
        )));
    }
    Ok(())
}

/// Once a vGPU type is on the card, every backend on it must fit beside the
/// others: the admitted sizes together may not exceed `vgpu_available_mib`.
/// Per-type instance counts alone let mixed types overbook the card, and a
/// backend without any VRAM limit could take what the profiles promise.
pub(crate) fn refuse_card_overcommit(
    live: &[&Claim],
    want: &Claim,
    id: &DeviceId,
) -> device::Result<()> {
    let Some(card) = card_size(live, want) else {
        return Ok(());
    };
    if want.is_unbounded() {
        return Err(DeviceError::InvalidSpec(format!(
            "device {id} sets no VRAM limit (no vgpu_type, vram_profile_mib or \
             vram_limit_mib), and this card carries vGPU-typed backends whose profiles it \
             could take; give it a profile or a cap"
        )));
    }
    if live.iter().any(|c| c.is_unbounded()) {
        return Err(DeviceError::InvalidSpec(format!(
            "a backend without a VRAM limit is running on this card, so it cannot promise \
             device {id} a vGPU profile beside it"
        )));
    }
    let used: u64 = live.iter().map(|c| c.mib).sum();
    if used.saturating_add(want.mib) > card {
        return Err(DeviceError::InvalidSpec(format!(
            "the card offers {card} MiB to guests: {used} MiB admitted + {} MiB requested \
             does not fit (device {id})",
            want.mib
        )));
    }
    Ok(())
}

/// The card's size from any vGPU-typed claim, or `None` when no vGPU type is
/// involved. Every type resolves against the same card, so they agree; the
/// smallest is taken should they not.
fn card_size(live: &[&Claim], want: &Claim) -> Option<u64> {
    live.iter()
        .copied()
        .chain([want])
        .filter_map(|c| c.card_mib)
        .min()
}

/// Refuse a backend that would take the live claims past the node's VRAM budget.
pub(crate) fn refuse_budget_overrun(
    live: &[&Claim],
    want: &Claim,
    budget: Option<u64>,
    id: &DeviceId,
) -> device::Result<()> {
    let used: u64 = live.iter().map(|c| c.mib).sum();
    let wants = want.mib;
    match budget {
        Some(budget) if used.saturating_add(wants) > budget => {
            Err(DeviceError::InvalidSpec(format!(
                "vram budget exceeded: {used} MiB active + {wants} MiB requested > \
                 {budget} MiB (device {id})"
            )))
        }
        Some(_) => Ok(()),
        None => {
            if used + wants > 0 {
                debug!(
                    used_mib = used,
                    requested_mib = wants,
                    "no vram budget configured, admitting without a hard check"
                );
            }
            Ok(())
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// `vgpu_available_mib` of the 8 GiB card the fixtures resolve against.
    pub(crate) const RTX2070_MIB: u64 = 8192;

    /// A resolved type as the card describes it, for admission tests.
    pub(crate) fn resolved(vgpu_type: &str, profile_mib: u64, max_instance: u64) -> VgpuType {
        VgpuType {
            vgpu_type: vgpu_type.into(),
            profile_mib,
            fb_mib: profile_mib - 512,
            max_instance,
            encoder_cap: 50,
            available_mib: RTX2070_MIB,
        }
    }

    pub(crate) fn typed(vgpu: &VgpuType) -> Claim {
        Claim::new(vgpu.profile_mib, Some(vgpu))
    }

    pub(crate) fn capped(mib: u64) -> Claim {
        Claim::new(mib, None)
    }

    fn unlimited() -> Claim {
        Claim::new(0, None)
    }

    fn device() -> DeviceId {
        DeviceId::new_v4()
    }

    /// IKR-B14, Leandro's `one_4q_admits_two_2q_and_nothing_more`: one 4Q
    /// and two 2Q fill the card, and a 1Q beside them is refused although
    /// no type has reached its own instance limit.
    #[test]
    fn mixed_vgpu_types_may_not_overbook_the_card() {
        let (q4, q2, q1) = (
            typed(&resolved("RTX2070-4Q", 4096, 2)),
            typed(&resolved("RTX2070-2Q", 2048, 4)),
            typed(&resolved("RTX2070-1Q", 1024, 8)),
        );
        refuse_card_overcommit(&[&q4, &q2], &q2, &device()).expect("4096 + 2048 + 2048 fits");
        let said = refuse_card_overcommit(&[&q4, &q2, &q2], &q1, &device())
            .expect_err("the card is full")
            .to_string();
        assert!(said.contains("8192 MiB"), "{said}");
    }

    /// A cap counts against the card like a profile once vGPU types share it.
    #[test]
    fn a_capped_backend_counts_against_the_card_beside_vgpu_types() {
        let q4 = typed(&resolved("RTX2070-4Q", 4096, 2));
        refuse_card_overcommit(&[&q4], &capped(4096), &device()).expect("exactly the card");
        refuse_card_overcommit(&[&q4], &capped(4097), &device()).expect_err("one MiB over");
    }

    /// A backend that may take the whole card cannot join vGPU-typed ones.
    #[test]
    fn an_unlimited_backend_is_refused_beside_vgpu_types() {
        let q2 = typed(&resolved("RTX2070-2Q", 2048, 4));
        let said = refuse_card_overcommit(&[&q2], &unlimited(), &device())
            .expect_err("it could take what the 2Q was promised")
            .to_string();
        assert!(said.contains("no VRAM limit"), "{said}");
    }

    /// And a vGPU type cannot promise its profile beside an unlimited backend.
    #[test]
    fn a_vgpu_type_is_refused_beside_an_unlimited_backend() {
        let q2 = typed(&resolved("RTX2070-2Q", 2048, 4));
        let said = refuse_card_overcommit(&[&unlimited()], &q2, &device())
            .expect_err("the running backend could take the profile")
            .to_string();
        assert!(said.contains("without a VRAM limit"), "{said}");
    }

    /// Without any vGPU type the card size is unknown; only the budget applies.
    #[test]
    fn without_a_vgpu_type_the_card_rule_does_not_apply() {
        refuse_card_overcommit(&[&capped(6000)], &capped(6000), &device())
            .expect("no card size to measure against");
        refuse_budget_overrun(&[&capped(6000)], &capped(6000), Some(8192), &device())
            .expect_err("but a budget still holds");
    }
}
