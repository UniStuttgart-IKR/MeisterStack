// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! The one verb about a base image this node answers to: being told one was
//! deleted.
//!
//! Everything else about an image is this node looking, never being told —
//! `images::Cache::ensure` and `verify_path` are both driven by this node's
//! own records, with no command behind either of them. `DropImage` is the
//! first exception, and Astra finding S02, 2026-09-23 (rest b) is why it
//! exists: nothing else on this road tells a node an image is gone.

use super::*;

impl Agent {
    /// An image was deleted at the cloud; let go of whatever this node
    /// fetched for it.
    ///
    /// Idempotent for a uid this node never fetched: `Cache::drop_uid` reads
    /// the cache directory for entries under the uid and finds none, and a
    /// catalogue link that does not point at this uid is left exactly as it
    /// is. Always `Ok`, the same shape `handle_forget_volume` answers with,
    /// for the same reason — there is no state this node can be in that makes
    /// "an image was deleted" a refusal.
    pub(super) async fn handle_drop_image(&self, d: proto::DropImage) -> anyhow::Result<()> {
        self.images.drop_uid(&d.name, &d.uid).await;
        Ok(())
    }
}
