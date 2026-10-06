// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Deletes that remove the object that was judged, never whatever its name names by the time
//! of the delete. Two replicas of one tier, or a name recreated between a listing and its
//! delete, must not cost the new object (R3-F02, R2-2). Both tiers finish deletes here.

use tracing::{debug, warn};

use crate::object::Resource;
use crate::store::{EtcdStore, Result, StoreError};

/// Retry bound for a guarded delete after concurrent writes; the same bound `mutate` uses.
const FINISH_DELETE_ATTEMPTS: usize = 8;

/// Delete `checked` by the revision it was judged at, never by name alone.
///
/// `concluded` is asked of the exact revision the delete names. On a conflict the object is
/// re-read and the delete retried only if it is still the same uid and the verdict still
/// holds; anything else ends it. `true` means this call removed the object.
pub async fn finish_delete<T: Resource>(
    store: &EtcdStore,
    checked: &T,
    concluded: impl Fn(&T) -> bool,
) -> Result<bool> {
    let name = checked.metadata().name.clone();
    let uid = checked.metadata().uid.clone();
    let mut current = checked.clone();
    for _ in 0..FINISH_DELETE_ATTEMPTS {
        if !concluded(&current) {
            return Ok(false);
        }
        match store
            .delete_if::<T>(&name, &current.metadata().resource_version)
            .await
        {
            Ok(()) => return Ok(true),
            Err(StoreError::Conflict(_)) => {}
            Err(e) => return Err(e),
        }
        match store.get::<T>(&name).await {
            Ok(fresh) if fresh.metadata().uid == uid => current = fresh,
            Ok(_) => {
                debug!(resource = T::RESOURCE, name = %name,
                       "recreated under the same name while its delete was finishing; left alone");
                return Ok(false);
            }
            Err(StoreError::NotFound(_)) => return Ok(false),
            Err(e) => return Err(e),
        }
    }
    warn!(resource = T::RESOURCE, name = %name,
          "finishing a delete kept losing to concurrent writes; the next pass tries again");
    Ok(false)
}

/// Take back an object this call created, by its uid and revision: the rollback of a create
/// that lost a race. Unlike a reconcile delete it has no next pass, so the created object still
/// standing after [`finish_delete`] gave up is an error and never a quiet `false`. Gone, or
/// another object under the name by now, is a rollback done.
pub async fn take_back_created<T: Resource>(store: &EtcdStore, created: &T) -> Result<()> {
    if finish_delete(store, created, |_| true).await? {
        return Ok(());
    }
    let name = &created.metadata().name;
    match store.get::<T>(name).await {
        Err(StoreError::NotFound(_)) => Ok(()),
        Ok(current) if current.metadata().uid != created.metadata().uid => Ok(()),
        Ok(_) => Err(StoreError::Conflict(format!(
            "{}/{name} kept changing while it was taken back and is still there",
            T::RESOURCE
        ))),
        Err(e) => Err(e),
    }
}

/// Take `finalizer` off the object `checked` names, judged again on the revision being written.
///
/// Under `checked`'s uid, so a name recreated since the listing is refused, and only while
/// `still` holds for the fresh revision. The written revision comes back for
/// [`finish_release`]; `None` means the object moved on (recreated, gone, no longer
/// releasable, or written by others on every retry) and the next pass decides again.
pub async fn take_finalizer<T: Resource>(
    store: &EtcdStore,
    checked: &T,
    finalizer: &str,
    still: impl Fn(&T) -> bool,
) -> Result<Option<T>> {
    let meta = checked.metadata();
    let mut applied = false;
    let written = store
        .mutate_if::<T, _>(&meta.name, &meta.uid, |obj| {
            applied = still(obj);
            if applied {
                obj.metadata_mut().finalizers.retain(|f| f != finalizer);
            }
        })
        .await;
    match written {
        Ok(obj) if applied => Ok(Some(obj)),
        Ok(_) | Err(StoreError::Conflict(_)) | Err(StoreError::NotFound(_)) => Ok(None),
        Err(e) => Err(e),
    }
}

/// Delete the revision [`take_finalizer`] wrote, while `still` holds and nobody has put
/// `finalizer` back. `true` means this call removed the object.
pub async fn finish_release<T: Resource>(
    store: &EtcdStore,
    written: &T,
    finalizer: &str,
    still: impl Fn(&T) -> bool,
) -> Result<bool> {
    finish_delete(store, written, |obj| {
        still(obj) && !obj.metadata().finalizers.iter().any(|f| f == finalizer)
    })
    .await
}

/// [`take_finalizer`], then [`finish_release`] on the revision that write produced: a finalizer
/// release as one step, for callers with nothing to do between the two.
pub async fn release_and_delete<T: Resource>(
    store: &EtcdStore,
    checked: &T,
    finalizer: &str,
    still: impl Fn(&T) -> bool,
) -> Result<bool> {
    let Some(written) = take_finalizer(store, checked, finalizer, &still).await? else {
        return Ok(false);
    };
    finish_release(store, &written, finalizer, still).await
}
