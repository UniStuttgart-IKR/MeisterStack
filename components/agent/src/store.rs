// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

use std::path::Path;

use agent_api::VmId;
use anyhow::Context;
use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition};

use crate::types::VmRecord;
use tracing::error;

const VMS: TableDefinition<&str, &[u8]> = TableDefinition::new("vms");

pub struct Store {
    db: Database,
}

impl Store {
    pub fn open(path: &Path) -> anyhow::Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating db directory {}", parent.display()))?;
        }

        let db = Database::create(path)
            .with_context(|| format!("opening agent db {}", path.display()))?;

        // Create DB if not already existing
        let tx = db.begin_write().context("initializing vms table")?;
        tx.open_table(VMS).context("initializing vms table")?;
        tx.commit().context("initializing vms table")?;

        Ok(Self { db })
    }

    pub fn put(&self, id: &VmId, record: &VmRecord) -> anyhow::Result<()> {
        let bytes = serde_json::to_vec(record).context("serializing vm record")?;
        let id_str = id.to_string();

        let tx = self.db.begin_write().context("begin write")?;
        {
            let mut table = tx.open_table(VMS).context("open vms table")?;
            table
                .insert(id_str.as_str(), bytes.as_slice())
                .with_context(|| format!("storing record for vm {id_str}"))?;
        }
        tx.commit().context("commit")?;
        Ok(())
    }

    /// Read, change, write back — inside ONE redb write transaction.
    ///
    /// The reason this exists rather than a get/put pair at the call site:
    /// every interesting caller reads a record, awaits something (a probe of
    /// the VMM's socket, a driver call), and writes back. The record it holds
    /// by then is a snapshot, and stamping the whole thing back drops whatever
    /// landed in between — a Stop from the controller, most of all. redb
    /// serialises write transactions, so a read taken inside one cannot be
    /// stale by the time the same transaction commits.
    ///
    /// `Ok(None)` if the record is gone; the closure is then not called.
    pub fn mutate(
        &self,
        id: &VmId,
        apply: impl FnOnce(&mut VmRecord),
    ) -> anyhow::Result<Option<VmRecord>> {
        let id_str = id.to_string();
        let tx = self.db.begin_write().context("begin write")?;
        let updated = {
            let mut table = tx.open_table(VMS).context("open vms table")?;
            let current = table
                .get(id_str.as_str())
                .context("reading record")?
                .map(|guard| {
                    serde_json::from_slice::<VmRecord>(guard.value())
                        .with_context(|| format!("corrupt record for vm {id_str}"))
                })
                .transpose()?;
            match current {
                None => None,
                Some(mut record) => {
                    apply(&mut record);
                    let bytes = serde_json::to_vec(&record).context("serializing vm record")?;
                    table
                        .insert(id_str.as_str(), bytes.as_slice())
                        .with_context(|| format!("storing record for vm {id_str}"))?;
                    Some(record)
                }
            }
        };
        tx.commit().context("commit")?;
        Ok(updated)
    }

    pub fn get(&self, id: &VmId) -> anyhow::Result<Option<VmRecord>> {
        let id_str = id.to_string();
        let tx = self.db.begin_read().context("begin read")?;
        let table = tx.open_table(VMS).context("open vms table")?;

        match table.get(id_str.as_str()).context("reading record")? {
            Some(guard) => {
                let record: VmRecord = serde_json::from_slice(guard.value())
                    .with_context(|| format!("corrupt record for vm {id_str}"))?;
                Ok(Some(record))
            }
            None => Ok(None),
        }
    }

    pub fn list(&self) -> anyhow::Result<Vec<(VmId, VmRecord)>> {
        let tx = self.db.begin_read().context("begin read")?;
        let table = tx.open_table(VMS).context("open vms table")?;

        let mut out = Vec::new();
        for item in table.iter().context("iterating vms table")? {
            let (key, value) = item.context("reading table entry")?;

            let id: VmId = match key.value().parse() {
                Ok(id) => id,
                Err(e) => {
                    // excludes corrupt data, for example outdated structs in the db
                    // to debug data use the non-serde list_raw()
                    error!(key = ?key.value(), error = %format!("{e:#}"), "corrupt key, skipping");
                    continue;
                }
            };

            let record: VmRecord = match serde_json::from_slice(value.value()) {
                Ok(r) => r,
                Err(e) => {
                    error!(vm_id = %id, error = %format!("{e:#}"), "corrupt record, skipping");
                    continue;
                }
            };

            out.push((id, record));
        }
        Ok(out)
    }

    pub fn delete(&self, id: &VmId) -> anyhow::Result<()> {
        let id_str = id.to_string();
        let tx = self.db.begin_write().context("begin write")?;
        {
            let mut table = tx.open_table(VMS).context("open vms table")?;
            table
                .remove(id_str.as_str())
                .with_context(|| format!("deleting record for vm {id_str}"))?;
        }
        tx.commit().context("commit")?;
        Ok(())
    }

    pub fn get_raw(&self, id: &VmId) -> anyhow::Result<Option<Vec<u8>>> {
        let id_str = id.to_string();
        let tx = self.db.begin_read().context("begin read")?;
        let table = tx.open_table(VMS).context("open vms table")?;
        Ok(table
            .get(id_str.as_str())
            .context("reading record")?
            .map(|g| g.value().to_vec()))
    }

    pub fn list_raw(&self) -> anyhow::Result<Vec<(String, Vec<u8>)>> {
        let tx = self.db.begin_read().context("begin read")?;
        let table = tx.open_table(VMS).context("open vms table")?;
        let mut out = Vec::new();
        for item in table.iter().context("iterating vms table")? {
            let (key, value) = item.context("reading table entry")?;
            out.push((key.value().to_string(), value.value().to_vec()));
        }
        Ok(out)
    }
}
