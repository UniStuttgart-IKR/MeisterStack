// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Rendezvous hashing (HRW) over a list of endpoints.
//!
//! Every dialling party sorts the endpoints by `hash(id, endpoint)` and works
//! down that order. Nothing is negotiated and nothing is stored: the order is
//! a pure function of the dialler's own name, so agents spread themselves over
//! the controller replicas — and cluster-controllers over the cloud replicas —
//! without a registry, each picks the same favourite after every restart, and
//! losing a replica moves only the diallers that were on it: the relative
//! order of the survivors cannot change, which is exactly what HRW buys over
//! hashing modulo the number of replicas.
//!
//! No `#[generated]` attribution here, and it is not an oversight: the macro
//! crate depends on this one, so this one cannot depend on the macro crate.
//! For the record, this file was written by Claude Opus 5 like the rest of the
//! HA work — the attribution simply has to live in prose.

/// FNV-1a by hand, and that is the point: `DefaultHasher` is seeded per
/// process, so the same agent would draw a different order after every
/// restart and the spread would be neither reproducible nor testable.
fn fnv1a(bytes: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in bytes {
        h ^= *b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

/// Finalizer (MurmurHash3's fmix64), and it is not decoration. FNV-1a folds
/// the last byte in as `(h ^ b) * prime`, so inputs that differ only at the
/// end differ only in the low bits of the product — and endpoints that differ
/// only in a port digit are exactly that case. Sorting on the raw value put
/// half the nodes on one replica (the test below is what caught it); mixing
/// the bits back over the whole word is what makes the spread a spread.
fn mix(mut h: u64) -> u64 {
    h ^= h >> 33;
    h = h.wrapping_mul(0xff51_afd7_ed55_8ccd);
    h ^= h >> 33;
    h = h.wrapping_mul(0xc4ce_b9fe_1a85_ec53);
    h ^= h >> 33;
    h
}

/// `hash(id ++ endpoint)` — the id being a node id one tier down and a
/// cluster name one tier up. The separator is a byte no hostname or URL
/// carries, so that ("ab", "c") and ("a", "bc") cannot score alike.
fn score(id: &str, endpoint: &str) -> u64 {
    let mut buf = Vec::with_capacity(id.len() + 1 + endpoint.len());
    buf.extend_from_slice(id.as_bytes());
    buf.push(0xff);
    buf.extend_from_slice(endpoint.as_bytes());
    mix(fnv1a(&buf))
}

/// The endpoints this id prefers, best first — the argmax of the HRW score
/// leads, the rest is the failover order behind it. A tie (a collision, or the
/// same endpoint configured twice) falls back to the endpoint string so the
/// order stays total and reproducible.
pub fn preference_order(id: &str, endpoints: &[String]) -> Vec<String> {
    let mut scored: Vec<(u64, &String)> = endpoints.iter().map(|e| (score(id, e), e)).collect();
    scored.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.cmp(b.1)));
    scored.into_iter().map(|(_, e)| e.clone()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn eps(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    fn three() -> Vec<String> {
        eps(&[
            "http://127.0.0.1:50051",
            "http://127.0.0.1:50052",
            "http://127.0.0.1:50053",
        ])
    }

    /// The published FNV-1a-64 vectors. If this ever fails, the hash was
    /// swapped for something process-seeded and every agent would reshuffle
    /// its controllers on restart.
    #[test]
    fn the_hash_is_the_published_fnv1a() {
        assert_eq!(fnv1a(b""), 0xcbf2_9ce4_8422_2325);
        assert_eq!(fnv1a(b"a"), 0xaf63_dc4c_8601_ec8c);
        assert_eq!(fnv1a(b"foobar"), 0x8594_4171_f739_67e8);
    }

    #[test]
    fn the_same_input_gives_the_same_order() {
        let first = preference_order("manacor", &three());
        for _ in 0..4 {
            assert_eq!(preference_order("manacor", &three()), first);
        }
        // and it really is a permutation of what was configured
        let mut sorted = first.clone();
        sorted.sort();
        assert_eq!(sorted, three());
    }

    /// Different nodes must not all pile onto the same replica. Three
    /// endpoints, three thousand nodes: a fair coin would give a third each,
    /// and anything inside ±20% of that is a spread, not a favourite.
    #[test]
    fn many_nodes_spread_over_the_endpoints() {
        let endpoints = three();
        let mut counts = std::collections::BTreeMap::new();
        for i in 0..3000 {
            let first = preference_order(&format!("node-{i}"), &endpoints)[0].clone();
            *counts.entry(first).or_insert(0usize) += 1;
        }
        assert_eq!(counts.len(), 3, "every endpoint must win somewhere");
        for (endpoint, n) in &counts {
            assert!((800..=1200).contains(n), "{endpoint} took {n} of 3000");
        }
    }

    /// The HRW property, and the reason for it: dropping a replica must move
    /// its own agents and nobody else's. Anything hashing to "index modulo
    /// count" fails this and reshuffles the whole cluster.
    #[test]
    fn removing_an_endpoint_only_moves_the_nodes_that_were_on_it() {
        let all = three();
        let gone = &all[1];
        let rest: Vec<String> = all.iter().filter(|e| *e != gone).cloned().collect();
        for i in 0..500 {
            let node = format!("node-{i}");
            let before = preference_order(&node, &all);
            let after = preference_order(&node, &rest);
            if &before[0] == gone {
                // it had to move, and to the next one it already preferred
                assert_eq!(after[0], before[1]);
            } else {
                assert_eq!(
                    after[0], before[0],
                    "{node} moved although its endpoint stayed"
                );
            }
        }
    }
}
