// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Tenant-scoped authorization, listing filters, and shared admission checks.

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

    /// Check object-level authorization after middleware checks the resource verb.
    /// Anonymous mode allows all requests. Denials return 403, which reveals that
    /// a guessed object name exists; listing handlers separately filter inventory.
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

    /// Members and viewers are confined to their tenant's inventory.
    /// Administrators, operators, system identities and anonymous callers are not.
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

    /// Intersect an optional tenant query with the caller's allowed inventory.
    /// A confined caller requesting another tenant receives an empty list.
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

/// Reserve the `system:` prefix for stack identities.
/// Certificate common names come from user names, and this prefix bypasses
/// person-directory authorization. Allowing it would let an administrator
/// create a credential that survives removal from the directory.
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
