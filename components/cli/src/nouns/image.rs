// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! `Image`: the object, its row, `image get` and the sugar verbs.

use super::*;

#[derive(Deserialize)]
pub(super) struct Image {
    metadata: Meta,
    spec: ImageSpec,
    #[serde(default)]
    status: ImageStatus,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct ImageSpec {
    source: String,
    #[serde(default)]
    url: Option<String>,
    #[serde(default)]
    format: Option<String>,
    #[serde(default)]
    size_bytes: u64,
    #[serde(default)]
    tenant: Option<String>,
    #[serde(default)]
    public: bool,
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub(super) struct ImageStatus {
    /// Pending / Ready / Failed. A path image is Ready the moment it is
    /// registered; a fetchable one waits for a node to say.
    #[serde(default)]
    phase: Option<String>,
    /// What each node said, behind that one word. Empty on an image nobody
    /// has reported on and on every cluster older than the field — which is
    /// not the same as "no node has it", so the column says nothing rather
    /// than zero.
    #[serde(default)]
    nodes: Vec<ImageNodeState>,
}

#[derive(Deserialize, Default, Clone)]
pub(super) struct ImageNodeState {
    #[serde(default)]
    phase: String,
}

impl ImageStatus {
    /// `3/5` — how many of the nodes that have spoken have the bytes.
    ///
    /// A ratio and not a percentage, because the denominator is the fact an
    /// operator wants: "3 of 5" during a rollout is a wait, and "3 of 5" that
    /// has not moved in ten minutes is two nodes to go and look at.
    fn fetched(&self) -> Option<String> {
        if self.nodes.is_empty() {
            return None;
        }
        let ready = self.nodes.iter().filter(|n| n.phase == "Ready").count();
        Some(format!("{ready}/{}", self.nodes.len()))
    }
}

/// Who owns it and who may read it are two facts, so they are two columns.
/// One column saying `tenant (public)` put a raw space in the middle of the
/// table and shifted every field behind it.
/// `image get` — the flattened object, plus the one line nobody could derive
/// from it at a glance.
///
/// `status.nodes[]` is the honest shape and it is a list; what an operator
/// asks of a catalogue is "is it there yet", and counting a list by eye is
/// not an answer. So the sentence is synthesised beside the fields, from the
/// same document, and it is the last row because it is the summary.
pub async fn image_get(ctx: &Ctx<'_>, name: &str) -> Result<()> {
    let body = ctx.client.get(&ctx.path("images", Some(name))?).await?;
    output::emit(ctx.global, &body, |body| {
        let object: serde_json::Value =
            serde_json::from_slice(body).context("parsing the object")?;
        let mut rows = crate::generic::flatten(&object);
        if let Ok(image) = serde_json::from_value::<Image>(object)
            && !image.status.nodes.is_empty()
        {
            let ready = image
                .status
                .nodes
                .iter()
                .filter(|n| n.phase == "Ready")
                .count();
            rows.push(vec![
                "status.nodes".to_string(),
                format!("{ready} of {} nodes fetched", image.status.nodes.len()),
            ]);
        }
        Ok(output::fields(rows))
    })
}

pub(super) fn image_row(img: Image) -> Vec<String> {
    vec![
        img.metadata.name,
        or_dash(img.spec.tenant),
        if img.spec.public { "public" } else { "private" }.to_string(),
        or_dash(img.spec.format),
        size(img.spec.size_bytes),
        or_dash(img.status.phase.clone()),
        // The detail behind that one word: a Failed union is one node that
        // could not read the bytes, and a Ready one still says nothing about
        // how far a rollout got.
        or_dash(img.status.fetched()),
        // For a fetchable image the url is where the bytes come from and the
        // name is where they land; showing the url is what an operator wants
        // to check.
        img.spec.url.unwrap_or(img.spec.source),
    ]
}

pub async fn image(ctx: &Ctx<'_>, cmd: &ImageCmd) -> Result<()> {
    let ImageCmd::Create {
        name,
        source,
        from_url,
        sha256,
        format,
        size,
        public,
    } = cmd
    else {
        // See the note in `tenant`.
        unreachable!("dispatched generically")
    };
    // `source` is what a node looks the image up as, and for a fetched one
    // that is the catalogue name itself: the bytes land under it. So one of
    // the two has to be given and only one can be, which clap already
    // enforces — this turns it into the field the server takes.
    let source = match (source, from_url) {
        (Some(path), _) => path.clone(),
        (None, Some(_)) => name.clone(),
        (None, None) => bail!(
            "say where the image is with --source <path>, or where to fetch it from with \
             --from-url <url> --sha256 <hex>"
        ),
    };
    let mut object = json!({
        "apiVersion": "meister.io/v1",
        "kind": "Image",
        "metadata": { "name": name },
        "spec": {
            "source": source,
            "format": format,
            "sizeBytes": size.unwrap_or(0),
            "public": public,
        },
    });
    // Omitted rather than sent as null: an absent key and a key saying
    // "nothing" are different requests, and the second would make every path
    // image look like a fetchable one whose url somebody forgot.
    if let Some(url) = from_url {
        object["spec"]["url"] = json!(url);
    }
    if let Some(sha256) = sha256 {
        object["spec"]["sha256"] = json!(sha256);
    }
    if let Some(tenant) = ctx.global.tenant.as_deref() {
        object["spec"]["tenant"] = json!(tenant);
    }
    let body = ctx.post("images", object).await?;
    output::emit_line(ctx.global, &body, name)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Who owns an image and who may read it are two facts. They used to
    /// share one column as `tenant (public)`, and that raw space in a middle
    /// column moved every `awk` field behind it.
    #[test]
    fn an_images_owner_and_its_scope_are_two_space_free_columns() {
        let img: Image = serde_json::from_str(
            r#"{"metadata":{"name":"debian-13"},
                "spec":{"source":"/srv/images/debian 13.raw","tenant":"ops","public":true,
                        "format":"raw","sizeBytes":2147483648},
                "status":{}}"#,
        )
        .unwrap();
        let row = image_row(img);
        assert_eq!(row[1], "ops");
        assert_eq!(row[2], "public");
        assert_eq!(row[4], "2.0Gi");
        assert_eq!(
            row[5], "-",
            "no phase on an object written before they existed"
        );
        // The only cell an operator can put a space in is the last one.
        for cell in &row[..row.len() - 1] {
            assert!(!cell.contains(' '), "{cell:?} carries a raw space");
        }
        assert_eq!(row[row.len() - 1], "/srv/images/debian 13.raw");
    }

    /// A public image with no tenant still says both things.
    #[test]
    fn a_public_image_without_an_owner_says_so_in_both_columns() {
        let img: Image = serde_json::from_str(
            r#"{"metadata":{"name":"base"},"spec":{"source":"/srv/base.raw","public":true},
                "status":{}}"#,
        )
        .unwrap();
        let row = image_row(img);
        assert_eq!(row[1], "-");
        assert_eq!(row[2], "public");
    }

    /// The detail behind one word. `status.phase` is the UNION over the
    /// nodes, so a Failed image is one node that could not read the bytes and
    /// a Ready one still says nothing about how far a rollout got — which is
    /// what the entry asks: "is it there yet".
    ///
    /// Empty is not zero. A cluster older than the field says nothing about
    /// its nodes, and printing `0/0` would be this CLI inventing a fact.
    #[test]
    fn an_image_says_how_many_nodes_have_the_bytes() {
        let status = |nodes: serde_json::Value| -> ImageStatus {
            serde_json::from_value(serde_json::json!({"phase": "Ready", "nodes": nodes})).unwrap()
        };
        assert_eq!(
            status(serde_json::json!([
                {"name": "a", "phase": "Ready"},
                {"name": "b", "phase": "Failed", "message": "checksum"},
                {"name": "c", "phase": "Ready"}
            ]))
            .fetched()
            .as_deref(),
            Some("2/3")
        );
        assert_eq!(status(serde_json::json!([])).fetched(), None, "not zero");
    }
}
