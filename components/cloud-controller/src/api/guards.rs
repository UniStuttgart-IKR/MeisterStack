// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Who is calling, and what that lets them touch.
//!
//! `Grant` is the caller as the tenant-scoped handlers want it — an identity,
//! the role the directory gave it and the tenant from the same object — and
//! the four checks below are the questions a handler asks that are not about
//! its own object. Verbatim out of `mod.rs`, where they sat between the
//! router and the tests.

use super::*;

/// Who the guard says is calling, in the shape the tenant-scoped handlers
/// want it: an identity (or anonymous), the role the DIRECTORY gave it, and
/// the tenant from the same object.
///
/// Bundled rather than threaded as three parameters because they are one
/// fact and are never useful apart — and because a handler that took only two
/// of them would be a handler that had quietly stopped scoping.
#[derive(Clone, Debug)]
pub(super) struct Grant {
    caller: Caller,
    role: Option<Role>,
    tenant: Option<String>,
}

impl Grant {
    pub(super) fn new(
        caller: Caller,
        CallerRole(role): CallerRole,
        CallerTenant(tenant): CallerTenant,
    ) -> Self {
        Self {
            caller,
            role,
            tenant,
        }
    }

    /// May this caller do `verb` to an object in `scope`?
    ///
    /// The middleware has already said yes to the KIND of request; this is
    /// the half that needs the object, and it runs in every handler that
    /// touches one. Anonymous mode says yes to everything, here as it does
    /// everywhere else — that is the mode the lab has run in since M1.
    ///
    /// A refusal is 403 and not 404 in both directions, which is K8s' own
    /// answer and its own trade: a name's existence is inferable from the
    /// difference, and a 404 on a write would send an admin debugging the
    /// wrong thing. Listings still filter, so an inventory is never handed
    /// out wholesale — but a guessed name gets an honest "not yours".
    pub(super) fn allows(&self, scope: Scope<'_>, verb: Verb) -> Result<(), ApiError> {
        let Some(identity) = &self.caller.0 else {
            return Ok(());
        };
        if permits_object(identity, self.role, self.tenant.as_deref(), scope, verb) {
            return Ok(());
        }
        Err(forbidden(format!(
            "{} may not {verb:?} an object of tenant {}",
            identity.name,
            scope.tenant.unwrap_or("<none>")
        )))
    }

    /// Is this caller confined to one tenant? An admin, an operator, a system
    /// identity and anonymous are not, and get their objects exactly as they
    /// always did.
    ///
    /// The line is `Operator`, not `Member`: an operator's job is the estate,
    /// and an estate you can only see one tenant's share of is not one you
    /// can run. Below it — member and viewer — a listing is filtered to the
    /// caller's own tenant, which is what makes a viewer a viewer of its own
    /// room and not of the whole cloud.
    pub(super) fn confined_to(&self) -> Option<&str> {
        let identity = self.caller.0.as_ref()?;
        if identity.is_system() {
            return None;
        }
        match self.role {
            Some(role) if role < Role::Operator => self.tenant.as_deref(),
            _ => None,
        }
    }

    /// Which tenant's objects a listing shows, given what the client asked
    /// for with `?tenant=`.
    ///
    /// Two filters and one answer, because the two can disagree. A member is
    /// confined to its own tenant; a member ASKING for another's must see
    /// nothing — not its own objects, and not a 403 either. The refusal was
    /// already made once, by the confinement, and what is left is a filter:
    /// a filter that finds nothing says so with an empty list, which is what
    /// this endpoint has always answered somebody asking about a room they
    /// are not in.
    pub(super) fn listing(&self, asked: Option<&str>) -> TenantFilter {
        match (self.confined_to(), asked) {
            (None, None) => TenantFilter::All,
            (None, Some(t)) => TenantFilter::Only(t.to_string()),
            (Some(mine), None) => TenantFilter::Only(mine.to_string()),
            (Some(mine), Some(t)) if t == mine => TenantFilter::Only(mine.to_string()),
            (Some(_), Some(_)) => TenantFilter::Nothing,
        }
    }

    /// What a create means when the client named no tenant: a member's object
    /// is its own tenant's, and nobody else's create is changed at all.
    ///
    /// The injection is here rather than in the client because the client is
    /// where a value can be left out, and an object created without an owner
    /// is an object no member can ever see again.
    pub(super) fn tenant_for_create(&self, named: Option<String>) -> Option<String> {
        named
            .filter(|t| !t.is_empty())
            .or_else(|| self.confined_to().map(str::to_string))
    }
}

/// What a listing keeps, once the caller's confinement and the caller's
/// question have been reconciled. See `Grant::listing`.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum TenantFilter {
    All,
    Only(String),
    Nothing,
}

impl TenantFilter {
    /// Does an object belonging to this tenant stay in the listing?
    pub(super) fn keeps(&self, tenant: Option<&str>) -> bool {
        match self {
            TenantFilter::All => true,
            TenantFilter::Only(mine) => tenant == Some(mine.as_str()),
            TenantFilter::Nothing => false,
        }
    }
}

/// That VM exists and belongs to this tenant.
pub(super) async fn check_vm_of_tenant(
    st: &ApiState,
    vm: &str,
    tenant: &str,
) -> Result<(), ApiError> {
    match st.store.get::<Vm>(vm).await {
        Ok(found) if found.spec.tenant.as_deref() == Some(tenant) => Ok(()),
        Ok(_) => Err(invalid(format!(
            "vm {vm:?} does not belong to tenant {tenant}"
        ))),
        Err(StoreError::NotFound(_)) => Err(invalid(format!("no vm {vm:?} in this cloud"))),
        Err(e) => Err(e.into()),
    }
}

// --- shared checks ---------------------------------------------------------

/// `system:` is the stack's own namespace and is not for people.
///
/// Not cosmetic. `Identity::is_system` reads the prefix off the certificate's
/// common name, and the signer writes the user object's name into that common
/// name — so a user called `system:anything` would be issued a certificate
/// that skips the directory lookup and every authorization check with it.
/// Creating one takes an admin, which makes this a way to keep access rather
/// than to gain it; that is exactly the kind of door worth not leaving open.
/// Kubernetes reserves the same prefix for the same reason.
pub(super) fn check_user_name(name: &str) -> Result<(), ApiError> {
    if name.starts_with(controller_api::auth::SYSTEM_PREFIX) {
        return Err(invalid(format!(
            "{:?} is reserved: names beginning {:?} are the stack's own identities (nodes, \
             controllers) and are not issued to people",
            name,
            controller_api::auth::SYSTEM_PREFIX
        )));
    }
    Ok(())
}

/// The fields a client does not get to write, whatever its body said.
pub(super) fn keep_server_owned(
    body: &mut controller_api::Metadata,
    current: &controller_api::Metadata,
) {
    body.uid = current.uid.clone();
    body.creation_timestamp = current.creation_timestamp;
    body.deletion_timestamp = current.deletion_timestamp;
    body.finalizers = current.finalizers.clone();
}

pub(super) async fn check_tenant(st: &ApiState, tenant: &str) -> Result<(), ApiError> {
    if tenant.is_empty() {
        return Err(invalid("spec.tenant must name a tenant"));
    }
    match st.store.get::<Tenant>(tenant).await {
        Ok(_) => Ok(()),
        Err(StoreError::NotFound(_)) => Err(invalid(format!(
            "no tenant {tenant:?}; create it first (meister tenant create)"
        ))),
        Err(e) => Err(e.into()),
    }
}
