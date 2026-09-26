// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! IPv4 range parsing shared by allocation and network enforcement.
//!
//! CIDRs, individual addresses and inclusive address ranges must describe the
//! same set in controller allocation and agent anti-spoofing rules. Allocation
//! excludes network and broadcast addresses for CIDRs wider than /31; containment
//! checks still include those addresses.

use std::fmt;
use std::net::Ipv4Addr;
use std::str::FromStr;

/// An inclusive IPv4 range parsed from a CIDR, one address or `start-end`.
/// A pool may contain several ranges for noncontiguous allocations.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Ipv4Range {
    start: u32,
    end: u32,
    // CIDR network and broadcast addresses are excluded from allocation for
    // prefixes shorter than /31. Containment checks still include them.
    edges_reserved: bool,
}

/// What went wrong with a range somebody wrote down. Its own error rather
/// than a string because both tiers turn it into their own kind of refusal —
/// a 422 at the API, a start-up failure at the node.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RangeError {
    Empty,
    Malformed(String),
    /// `a-b` with b below a. Worth its own variant: it is the one mistake
    /// that parses as two valid addresses and still means nothing.
    Inverted(String),
    PrefixTooLong(String),
}

impl fmt::Display for RangeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RangeError::Empty => write!(f, "an address range cannot be empty"),
            RangeError::Malformed(s) => write!(
                f,
                "{s:?} is not an address range; write a cidr (10.255.0.0/16), \
                 a single address (203.0.113.7) or a range (203.0.113.8-203.0.113.11)"
            ),
            RangeError::Inverted(s) => {
                write!(f, "{s:?} ends before it starts")
            }
            RangeError::PrefixTooLong(s) => {
                write!(f, "{s:?} has a prefix length above 32")
            }
        }
    }
}

impl std::error::Error for RangeError {}

impl Ipv4Range {
    /// Every address in the range, guard included.
    pub fn contains(&self, addr: Ipv4Addr) -> bool {
        let n = u32::from(addr);
        n >= self.start && n <= self.end
    }

    /// Do these two share an address? The whole of Part B's overlap check,
    /// and the whole of the "a routed subnet may not overlap a floating pool"
    /// rule, in one comparison.
    pub fn overlaps(&self, other: &Ipv4Range) -> bool {
        self.start <= other.end && other.start <= self.end
    }

    pub fn first(&self) -> Ipv4Addr {
        Ipv4Addr::from(self.start)
    }

    pub fn last(&self) -> Ipv4Addr {
        Ipv4Addr::from(self.end)
    }

    /// How many addresses the range covers, guard included.
    pub fn len(&self) -> u64 {
        u64::from(self.end - self.start) + 1
    }

    pub fn is_empty(&self) -> bool {
        false
    }

    /// Allocatable addresses exclude network/broadcast endpoints for CIDRs
    /// wider than /31. Single addresses, /31, /32 and explicit ranges use
    /// their entire specified set.
    pub fn allocatable(&self) -> impl Iterator<Item = Ipv4Addr> {
        let (from, to) = if self.edges_reserved {
            (self.start + 1, self.end - 1)
        } else {
            (self.start, self.end)
        };
        (from..=to).map(Ipv4Addr::from)
    }

    /// Check the allocator set, excluding CIDR endpoints where applicable.
    /// `contains` instead checks the full range used for packet guarding.
    pub fn is_allocatable(&self, addr: Ipv4Addr) -> bool {
        if !self.contains(addr) {
            return false;
        }
        let n = u32::from(addr);
        !self.edges_reserved || (n != self.start && n != self.end)
    }

    /// The element as nftables spells it inside a set. `a-b` and a bare
    /// address are both valid interval elements, so one spelling covers all
    /// three input forms and the node never has to re-derive a prefix length.
    pub fn to_nft(&self) -> String {
        self.to_string()
    }

    /// Canonical CIDR for a prefix-shaped range, otherwise None. Masking
    /// input host bits gives equivalent routed-subnet requests one spelling.
    pub fn to_cidr(&self) -> Option<String> {
        let size = u64::from(self.end - self.start) + 1;
        if !size.is_power_of_two() {
            return None;
        }
        // Aligned, or it is a run of addresses that happens to be a power of
        // two long rather than a prefix.
        if u64::from(self.start) % size != 0 {
            return None;
        }
        Some(format!("{}/{}", self.first(), 32 - size.trailing_zeros()))
    }
}

impl fmt::Display for Ipv4Range {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.start == self.end {
            write!(f, "{}", self.first())
        } else {
            write!(f, "{}-{}", self.first(), self.last())
        }
    }
}

impl FromStr for Ipv4Range {
    type Err = RangeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let text = s.trim();
        if text.is_empty() {
            return Err(RangeError::Empty);
        }
        if let Some((a, b)) = text.split_once('-') {
            let start = parse_addr(a, text)?;
            let end = parse_addr(b, text)?;
            if u32::from(end) < u32::from(start) {
                return Err(RangeError::Inverted(text.to_string()));
            }
            return Ok(Ipv4Range {
                start: start.into(),
                end: end.into(),
                edges_reserved: false,
            });
        }
        if let Some((addr, prefix)) = text.split_once('/') {
            let addr = parse_addr(addr, text)?;
            let prefix: u32 = prefix
                .trim()
                .parse()
                .map_err(|_| RangeError::Malformed(text.to_string()))?;
            if prefix > 32 {
                return Err(RangeError::PrefixTooLong(text.to_string()));
            }
            // The mask, written so that /0 does not shift a u32 by 32 — which
            // is undefined in C and a panic in debug Rust.
            let mask: u32 = if prefix == 0 {
                0
            } else {
                u32::MAX << (32 - prefix)
            };
            let base = u32::from(addr) & mask;
            return Ok(Ipv4Range {
                start: base,
                end: base | !mask,
                // /31 and /32 have no network and no broadcast address; RFC
                // 3021 says so for /31 and a /32 is one address.
                edges_reserved: prefix <= 30,
            });
        }
        let addr = parse_addr(text, text)?;
        Ok(Ipv4Range {
            start: addr.into(),
            end: addr.into(),
            edges_reserved: false,
        })
    }
}

fn parse_addr(part: &str, whole: &str) -> Result<Ipv4Addr, RangeError> {
    part.trim()
        .parse::<Ipv4Addr>()
        .map_err(|_| RangeError::Malformed(whole.to_string()))
}

/// Address space composed of configured ranges, retained in input form
/// for display and nftables rendering rather than merged.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Ipv4Ranges(Vec<Ipv4Range>);

impl Ipv4Ranges {
    /// Parse each entry, saying which one was wrong. A pool with one bad
    /// entry is a bad pool: taking the rest would guard less than the
    /// operator asked for and nobody would see it.
    pub fn parse(entries: &[String]) -> Result<Self, RangeError> {
        entries
            .iter()
            .map(|e| e.parse())
            .collect::<Result<Vec<_>, _>>()
            .map(Ipv4Ranges)
    }

    pub fn ranges(&self) -> &[Ipv4Range] {
        &self.0
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn contains(&self, addr: Ipv4Addr) -> bool {
        self.0.iter().any(|r| r.contains(addr))
    }

    pub fn overlaps(&self, other: &Ipv4Ranges) -> bool {
        self.0.iter().any(|a| other.0.iter().any(|b| a.overlaps(b)))
    }

    pub fn overlaps_range(&self, other: &Ipv4Range) -> bool {
        self.0.iter().any(|a| a.overlaps(other))
    }

    /// How many addresses in total, guard included.
    pub fn len(&self) -> u64 {
        self.0.iter().map(Ipv4Range::len).sum()
    }

    /// Return the first free address in configured entry order. Scanning gaps
    /// allows released addresses to be reused instead of exhausting a counter.
    pub fn first_free(&self, taken: &std::collections::BTreeSet<Ipv4Addr>) -> Option<Ipv4Addr> {
        self.0
            .iter()
            .flat_map(Ipv4Range::allocatable)
            .find(|a| !taken.contains(a))
    }

    /// An address is allocatable if any entry permits it. An explicit
    /// single-address entry can include another entry's network endpoint.
    pub fn is_allocatable(&self, addr: Ipv4Addr) -> bool {
        self.0.iter().any(|r| r.is_allocatable(addr))
    }

    /// The set elements for an nftables `{ … }` literal, comma-separated.
    pub fn to_nft(&self) -> String {
        self.0
            .iter()
            .map(Ipv4Range::to_nft)
            .collect::<Vec<_>>()
            .join(", ")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    fn r(s: &str) -> Ipv4Range {
        s.parse().unwrap_or_else(|e| panic!("{s:?}: {e}"))
    }

    fn ip(s: &str) -> Ipv4Addr {
        s.parse().unwrap()
    }

    /// The three spellings an operator uses, and what each one covers.
    #[test]
    fn a_range_is_a_cidr_a_single_address_or_two_addresses() {
        let cidr = r("10.255.0.0/16");
        assert_eq!(
            (cidr.first(), cidr.last()),
            (ip("10.255.0.0"), ip("10.255.255.255"))
        );
        assert_eq!(cidr.len(), 65_536);

        let one = r("203.0.113.7");
        assert_eq!(
            (one.first(), one.last()),
            (ip("203.0.113.7"), ip("203.0.113.7"))
        );
        assert_eq!(one.len(), 1);
        assert_eq!(r("203.0.113.7/32"), one, "a /32 is the same statement");

        let span = r("203.0.113.8-203.0.113.11");
        assert_eq!(span.len(), 4);
        assert!(span.contains(ip("203.0.113.10")));
        assert!(!span.contains(ip("203.0.113.12")));
    }

    /// CIDR input host bits are masked to the network base.
    #[test]
    fn a_cidr_is_masked_to_its_own_base() {
        assert_eq!(r("10.255.0.5/16"), r("10.255.0.0/16"));
        assert_eq!(r("0.0.0.0/0").len(), 1 << 32);
        assert_eq!(r("255.255.255.255/32").len(), 1);
    }

    /// Allocation skips the network and the broadcast address of a real
    /// subnet — and only there. Somebody who wrote down four addresses meant
    /// four addresses.
    #[test]
    fn allocation_leaves_the_edges_of_a_subnet_alone_and_nothing_else() {
        let usable: Vec<_> = r("192.0.2.0/29").allocatable().collect();
        assert_eq!(usable.len(), 6, "8 addresses, 6 hosts");
        assert_eq!(usable[0], ip("192.0.2.1"));
        assert_eq!(usable[5], ip("192.0.2.6"));

        // ... while the guard still covers all eight.
        assert!(r("192.0.2.0/29").contains(ip("192.0.2.0")));
        assert!(r("192.0.2.0/29").contains(ip("192.0.2.7")));

        // /31 and /32 have no edges to reserve (RFC 3021), and a written-out
        // range is used whole.
        assert_eq!(r("192.0.2.8/31").allocatable().count(), 2);
        assert_eq!(r("192.0.2.9/32").allocatable().count(), 1);
        assert_eq!(r("192.0.2.0-192.0.2.7").allocatable().count(), 8);
    }

    /// Requested-address validation and first-free scanning use the same set.
    #[test]
    fn one_address_is_asked_the_same_question_the_scan_asks() {
        let subnet = r("192.0.2.0/29");
        assert!(subnet.is_allocatable(ip("192.0.2.1")));
        assert!(subnet.is_allocatable(ip("192.0.2.6")));
        assert!(!subnet.is_allocatable(ip("192.0.2.0")), "network address");
        assert!(!subnet.is_allocatable(ip("192.0.2.7")), "broadcast address");
        assert!(!subnet.is_allocatable(ip("192.0.2.8")), "outside");
        // and it agrees with the scan, address for address
        for n in 0..8u8 {
            let addr = ip(&format!("192.0.2.{n}"));
            assert_eq!(
                subnet.is_allocatable(addr),
                subnet.allocatable().any(|a| a == addr),
                "{addr}"
            );
        }

        // A written-out range has no edges to reserve, so all of it counts.
        assert!(r("192.0.2.0-192.0.2.7").is_allocatable(ip("192.0.2.0")));
        assert!(r("192.0.2.9/32").is_allocatable(ip("192.0.2.9")));

        // Across a pool's entries: any entry that can hand it out is enough,
        // which is what makes an operator's single-address entry next to a
        // CIDR mean the address they wrote.
        let pool = Ipv4Ranges::parse(&["192.0.2.0/29".into(), "192.0.2.0".into()]).unwrap();
        assert!(pool.is_allocatable(ip("192.0.2.0")));
        assert!(
            !Ipv4Ranges::parse(&["192.0.2.0/29".into()])
                .unwrap()
                .is_allocatable(ip("192.0.2.0"))
        );
    }

    /// The canonical spelling a routed subnet is stored in — and the honest
    /// `None` for a run of addresses that is not a prefix at all.
    #[test]
    fn a_prefix_can_say_so_and_a_bare_run_cannot() {
        assert_eq!(r("10.7.1.7/24").to_cidr().as_deref(), Some("10.7.1.0/24"));
        assert_eq!(
            r("203.0.113.7").to_cidr().as_deref(),
            Some("203.0.113.7/32")
        );
        assert_eq!(r("0.0.0.0/0").to_cidr().as_deref(), Some("0.0.0.0/0"));
        assert_eq!(
            r("10.0.0.1-10.0.0.2").to_cidr(),
            None,
            "two addresses, not aligned"
        );
        assert_eq!(
            r("10.0.0.0-10.0.0.2").to_cidr(),
            None,
            "three addresses, not a power of two"
        );
        assert_eq!(
            r("10.0.0.0-10.0.0.1").to_cidr().as_deref(),
            Some("10.0.0.0/31")
        );
    }

    #[test]
    fn overlap_is_symmetric_and_touching_counts() {
        let a = r("10.0.0.0/24");
        assert!(a.overlaps(&r("10.0.0.255")), "the last address is in it");
        assert!(r("10.0.0.255").overlaps(&a));
        assert!(
            a.overlaps(&r("10.0.0.0/16")),
            "a range inside a bigger one overlaps"
        );
        assert!(
            !a.overlaps(&r("10.0.1.0/24")),
            "adjacent is not overlapping"
        );
    }

    /// Every way of writing nonsense, refused by name — these messages end up
    /// in an operator's terminal as the reason a pool was refused.
    #[test]
    fn a_range_nobody_could_mean_is_refused_in_words() {
        assert_eq!("".parse::<Ipv4Range>(), Err(RangeError::Empty));
        assert!(matches!(
            "10.0.0.1-10.0.0.0".parse::<Ipv4Range>(),
            Err(RangeError::Inverted(_))
        ));
        assert!(matches!(
            "10.0.0.0/33".parse::<Ipv4Range>(),
            Err(RangeError::PrefixTooLong(_))
        ));
        for bad in ["10.0.0", "not-an-address", "10.0.0.0/x", "10.0.0.0-", "::1"] {
            assert!(bad.parse::<Ipv4Range>().is_err(), "{bad:?} parsed");
        }
        let msg = "10.0.0".parse::<Ipv4Range>().unwrap_err().to_string();
        assert!(
            msg.contains("10.255.0.0/16"),
            "the message shows the shapes: {msg}"
        );
    }

    /// A pool of four scattered public addresses — the shape a hoster's
    /// allocation actually has — reads as one address space.
    #[test]
    fn scattered_addresses_are_one_pool() {
        let pool = Ipv4Ranges::parse(&[
            "203.0.113.7".into(),
            "203.0.113.9".into(),
            "198.51.100.16-198.51.100.17".into(),
        ])
        .unwrap();
        assert_eq!(pool.len(), 4);
        assert!(pool.contains(ip("198.51.100.17")));
        assert!(!pool.contains(ip("203.0.113.8")), "the gap is not ours");

        let mut taken = BTreeSet::new();
        assert_eq!(pool.first_free(&taken), Some(ip("203.0.113.7")));
        taken.insert(ip("203.0.113.7"));
        assert_eq!(pool.first_free(&taken), Some(ip("203.0.113.9")));
        taken.insert(ip("203.0.113.9"));
        taken.insert(ip("198.51.100.16"));
        assert_eq!(pool.first_free(&taken), Some(ip("198.51.100.17")));
        taken.insert(ip("198.51.100.17"));
        assert_eq!(pool.first_free(&taken), None, "an exhausted pool says so");
    }

    /// A gap scan and not a high-water mark: an address given back has to be
    /// given out again, or a pool of four public addresses dies after four
    /// releases.
    #[test]
    fn a_released_address_is_handed_out_again() {
        let pool = Ipv4Ranges::parse(&["192.0.2.0/29".into()]).unwrap();
        let mut taken: BTreeSet<Ipv4Addr> = ["192.0.2.1", "192.0.2.2", "192.0.2.3"]
            .iter()
            .map(|s| ip(s))
            .collect();
        assert_eq!(pool.first_free(&taken), Some(ip("192.0.2.4")));
        taken.remove(&ip("192.0.2.2"));
        assert_eq!(
            pool.first_free(&taken),
            Some(ip("192.0.2.2")),
            "the gap comes back"
        );
    }

    /// One bad entry is a bad pool: taking the rest would guard less than the
    /// operator asked for, and nobody would see which line was dropped.
    #[test]
    fn one_unparseable_entry_refuses_the_whole_list() {
        let err = Ipv4Ranges::parse(&["10.0.0.0/24".into(), "oops".into()]).unwrap_err();
        assert!(err.to_string().contains("oops"), "{err}");
    }

    /// What the node writes into an nftables set. Both spellings are valid
    /// interval elements, so the driver never has to re-derive a prefix.
    #[test]
    fn the_nft_spelling_is_one_element_per_range() {
        let ranges = Ipv4Ranges::parse(&["10.255.0.0/16".into(), "203.0.113.7".into()]).unwrap();
        assert_eq!(ranges.to_nft(), "10.255.0.0-10.255.255.255, 203.0.113.7");
    }

    #[test]
    fn two_lists_overlap_when_any_two_of_their_ranges_do() {
        let pool = Ipv4Ranges::parse(&["10.255.0.0/16".into(), "203.0.113.0/24".into()]).unwrap();
        let clean = Ipv4Ranges::parse(&["10.7.0.0/16".into()]).unwrap();
        let dirty = Ipv4Ranges::parse(&["10.7.0.0/16".into(), "203.0.113.128/25".into()]).unwrap();
        assert!(!pool.overlaps(&clean));
        assert!(pool.overlaps(&dirty));
        assert!(dirty.overlaps(&pool), "and it is symmetric");
        assert!(pool.overlaps_range(&r("203.0.113.9")));
    }
}
