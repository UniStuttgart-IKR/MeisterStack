// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! The rules a backend is admitted by: what it counts as on the card, and why
//! it may not join the backends already counted.

use agent_api::device::{self, DeviceError, DeviceId};
use tracing::debug;

use crate::vgpu::VgpuType;

/// What one backend counts as for admission.
#[derive(Clone, Debug, PartialEq)]
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

/// A device an admission asks for, with the type its claim was resolved to.
pub(crate) struct Wanted {
    pub(crate) id: DeviceId,
    pub(crate) claim: Claim,
    pub(crate) vgpu: Option<VgpuType>,
}

/// Admit the wanted devices beside the held claims, one after the other, so
/// a VM's second device is measured against its first.
pub(crate) fn admit_all(
    held: Vec<Claim>,
    wanted: &[Wanted],
    budget: Option<u64>,
) -> device::Result<()> {
    let mut live = held;
    for want in wanted {
        let counted: Vec<&Claim> = live.iter().collect();
        refuse_instance_overflow(&counted, want.vgpu.as_ref())?;
        refuse_card_overcommit(&counted, &want.claim, &want.id)?;
        refuse_budget_overrun(&counted, &want.claim, budget, &want.id)?;
        live.push(want.claim.clone());
    }
    Ok(())
}

/// Refuse one more backend of a vGPU type the card already holds `max_instance` of.
fn refuse_instance_overflow(live: &[&Claim], vgpu: Option<&VgpuType>) -> device::Result<()> {
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

/// How a tenant or an operator gets a size of their own on a card that
/// carries vGPU types: as a type, which the card resolves with its share.
const A_SIZE_AS_A_TYPE: &str = "give it a vgpu_type; for a size of its own, vgpu_type = \"<N>M\" \
     resolves a profile with N MiB for the guest on this card";

/// Once a vGPU type is on the card, every backend on it must be vGPU-typed
/// and fit beside the others: the admitted sizes together may not exceed
/// `vgpu_available_mib`. A type's profile size carries its share of the
/// card's own carve-out; a cap or a bare profile size does not, so summed
/// against the card it would overbook it, and a backend without any limit
/// could take what the profiles promise. Per-type instance counts alone let
/// mixed types overbook the card.
fn refuse_card_overcommit(live: &[&Claim], want: &Claim, id: &DeviceId) -> device::Result<()> {
    let Some(card) = card_size(live, want) else {
        return Ok(());
    };
    if want.vgpu_type.is_none() {
        return Err(DeviceError::InvalidSpec(format!(
            "device {id} {}, and this card carries vGPU-typed backends: beside them only a \
             vGPU type can be measured against the card; {A_SIZE_AS_A_TYPE}",
            without_a_type(want)
        )));
    }
    if let Some(untyped) = live.iter().find(|c| c.vgpu_type.is_none()) {
        return Err(DeviceError::InvalidSpec(format!(
            "a backend that {} runs on this card, so it cannot promise device {id} a vGPU \
             profile beside it until that backend is gone",
            without_a_type(untyped)
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

fn without_a_type(claim: &Claim) -> &'static str {
    if claim.is_unbounded() {
        "sets no VRAM limit at all"
    } else {
        "has a cap or a profile size of its own and no vGPU type"
    }
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

/// Refuse a backend that would take the live claims past the node's VRAM
/// budget. A backend without a VRAM limit could take any amount of it, so
/// under a budget one is not admitted, and one already on record leaves
/// room for nothing beside it.
fn refuse_budget_overrun(
    live: &[&Claim],
    want: &Claim,
    budget: Option<u64>,
    id: &DeviceId,
) -> device::Result<()> {
    if let Some(budget) = budget {
        refuse_unbounded_under_budget(live, want, budget, id)?;
    }
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

fn refuse_unbounded_under_budget(
    live: &[&Claim],
    want: &Claim,
    budget: u64,
    id: &DeviceId,
) -> device::Result<()> {
    if want.is_unbounded() {
        return Err(DeviceError::InvalidSpec(format!(
            "device {id} sets no VRAM limit, and this node holds its nvrm devices to a \
             budget of {budget} MiB that such a backend could exceed alone; give the \
             node a default cap ([device.nvrm.defaults] vram_limit_mib) or the device a \
             profile that sets a limit or a vgpu_type"
        )));
    }
    if live.iter().any(|c| c.is_unbounded()) {
        return Err(DeviceError::InvalidSpec(format!(
            "an nvrm device on this node sets no VRAM limit, and under the budget of \
             {budget} MiB it counts as all of it; device {id} fits once that device has a \
             limit or is gone"
        )));
    }
    Ok(())
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

    /// A cap or a bare profile size does not carry its share of the card's
    /// carve-out, so beside vGPU types it is refused even where the sum fits,
    /// and the refusal says how to ask for a size as a type.
    #[test]
    fn a_capped_backend_is_refused_beside_vgpu_types() {
        let q4 = typed(&resolved("RTX2070-4Q", 4096, 2));
        let said = refuse_card_overcommit(&[&q4], &capped(1024), &device())
            .expect_err("1024 MiB would fit, uncounted carve-out and all")
            .to_string();
        assert!(said.contains("vgpu_type = \"<N>M\""), "{said}");
    }

    /// The other order: a vGPU type cannot join a card a capped backend is on.
    #[test]
    fn a_vgpu_type_is_refused_beside_a_capped_backend() {
        let q4 = typed(&resolved("RTX2070-4Q", 4096, 2));
        let said = refuse_card_overcommit(&[&capped(1024)], &q4, &device())
            .expect_err("the cap's share of the card is unknown")
            .to_string();
        assert!(said.contains("cap or a profile size"), "{said}");
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
        assert!(said.contains("no VRAM limit at all"), "{said}");
    }

    /// The devices of one admission count against each other as well as
    /// against what is held: two 8Q in one vm do not fit a card that has one.
    #[test]
    fn a_vms_second_device_is_measured_against_its_first() {
        let q8 = resolved("RTX2070-8Q", 8192, 1);
        let want = |vgpu: &VgpuType| Wanted {
            id: device(),
            claim: typed(vgpu),
            vgpu: Some(vgpu.clone()),
        };
        admit_all(Vec::new(), &[want(&q8)], None).expect("one 8Q fits");
        admit_all(Vec::new(), &[want(&q8), want(&q8)], None).expect_err("two do not");
    }

    /// Under a budget a backend without a VRAM limit is refused: it could
    /// take more than the whole budget alone. Without one it is admitted.
    #[test]
    fn under_a_budget_a_backend_without_a_limit_is_refused() {
        let said = refuse_budget_overrun(&[&capped(1024)], &unlimited(), Some(8192), &device())
            .expect_err("it could take the rest and more")
            .to_string();
        assert!(said.contains("sets no VRAM limit"), "{said}");
        assert!(said.contains("vram_limit_mib"), "and says what to set: {said}");
        refuse_budget_overrun(&[&capped(1024)], &unlimited(), None, &device())
            .expect("no budget to exceed");
    }

    /// The other order: a backend without a limit already on record counts
    /// as the whole budget, so a capped one does not fit beside it.
    #[test]
    fn under_a_budget_a_backend_without_a_limit_on_record_leaves_no_room() {
        let said = refuse_budget_overrun(&[&unlimited()], &capped(1024), Some(8192), &device())
            .expect_err("the budget is all taken")
            .to_string();
        assert!(said.contains("counts as all of it"), "{said}");
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
