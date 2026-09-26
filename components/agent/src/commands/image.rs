// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Remove cached content for a deleted catalogue image. Image population and
//! availability checks are otherwise driven by local records and inventory.

use super::*;

impl Agent {
    /// Best-effort cache cleanup for the named image UID. A catalogue link
    /// pointing to another UID is retained. Cleanup errors are handled by the cache;
    /// this command always acknowledges the request.
    pub(super) async fn handle_drop_image(&self, d: proto::DropImage) -> anyhow::Result<()> {
        self.images.drop_uid(&d.name, &d.uid).await;
        Ok(())
    }
}
