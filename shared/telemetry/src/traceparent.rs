// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! The W3C `traceparent` header, as a value this stack can carry by hand.
//!
//! Propagation here is explicit rather than ambient, and that is the design
//! decision worth stating: nothing in this control plane is a call stack. A
//! `POST /vms` writes an object and returns; the reconciler that acts on it
//! wakes up later, in another task, possibly in another process, possibly
//! after a restart. There is no context to inherit — so the context travels
//! as data, on the object and on the command, exactly like the spec does.
//!
//! The upshot is that the chain works with or without an OTLP exporter. With
//! one, `attach_parent` turns the string back into a real parent and Jaeger
//! shows one trace; without one, the same string is a `trace_id` field on the
//! span, and the fmt logs of all three components carry the same id.
//!
//! Format (W3C Trace Context, version 00):
//!   00-<32 hex trace-id>-<16 hex span-id>-<2 hex flags>

use std::fmt;

/// A parsed `traceparent`. Only version 00 is understood; anything else is
/// rejected rather than guessed at, because a version we cannot read is a
/// context we cannot honestly claim to be continuing.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct TraceParent {
    pub trace_id: [u8; 16],
    pub span_id: [u8; 8],
    /// Bit 0 is `sampled`. Carried through untouched: whether this trace is
    /// recorded was decided at the edge, and every hop after it is bound by
    /// that decision or the trace comes out with holes in it.
    pub flags: u8,
}

/// The sampled bit, which is the only flag the spec defines today.
pub const FLAG_SAMPLED: u8 = 0x01;

impl TraceParent {
    /// A fresh root context. Sampled, because a trace nobody asked to record
    /// is a trace nobody can look at, and this stack's volume does not need
    /// head sampling.
    pub fn root() -> Self {
        let a = uuid::Uuid::new_v4().into_bytes();
        let b = uuid::Uuid::new_v4().into_bytes();
        Self {
            trace_id: a,
            span_id: b[..8].try_into().expect("uuid is 16 bytes"),
            flags: FLAG_SAMPLED,
        }
    }

    /// The same trace, a new span. What a component sends onwards after doing
    /// something of its own: the trace id is the thread that ties the hops
    /// together, the span id says which hop.
    pub fn child(&self) -> Self {
        let b = uuid::Uuid::new_v4().into_bytes();
        Self {
            trace_id: self.trace_id,
            span_id: b[..8].try_into().expect("uuid is 16 bytes"),
            flags: self.flags,
        }
    }

    pub fn trace_id_hex(&self) -> String {
        hex(&self.trace_id)
    }

    pub fn span_id_hex(&self) -> String {
        hex(&self.span_id)
    }

    pub fn sampled(&self) -> bool {
        self.flags & FLAG_SAMPLED != 0
    }

    /// Parse a header value. `None` for anything malformed — an unreadable
    /// context is treated as no context, which starts a new trace rather than
    /// silently attaching this work to whatever the bytes happened to decode
    /// to.
    pub fn parse(s: &str) -> Option<Self> {
        let mut parts = s.trim().split('-');
        let (version, trace, span, flags) =
            (parts.next()?, parts.next()?, parts.next()?, parts.next()?);
        if parts.next().is_some() || version != "00" {
            return None;
        }
        if trace.len() != 32 || span.len() != 16 || flags.len() != 2 {
            return None;
        }
        let trace_id: [u8; 16] = unhex(trace)?.try_into().ok()?;
        let span_id: [u8; 8] = unhex(span)?.try_into().ok()?;
        // All-zero ids are invalid per the spec, and they are what a
        // half-initialised sender emits — accepting them would merge every
        // such request into one enormous trace.
        if trace_id == [0; 16] || span_id == [0; 8] {
            return None;
        }
        Some(Self {
            trace_id,
            span_id,
            flags: unhex(flags)?[0],
        })
    }

    /// Parse, or start a fresh trace. The one call an edge makes.
    pub fn parse_or_root(header: Option<&str>) -> Self {
        header.and_then(Self::parse).unwrap_or_else(Self::root)
    }
}

impl fmt::Display for TraceParent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "00-{}-{}-{:02x}",
            hex(&self.trace_id),
            hex(&self.span_id),
            self.flags
        )
    }
}

/// Debug prints the header form: a traceparent in a log line is only useful
/// if it is the string you can paste into a trace viewer.
impl fmt::Debug for TraceParent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self}")
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Hex-decode, over BYTES rather than chars.
///
/// The length checks in `parse` are byte lengths, so a header field can be the
/// right number of bytes and still hold a multi-byte character — and slicing
/// `&s[i..i + 2]` through the middle of one panics. The input is a remote
/// header, so that panic is reachable from outside; refusing anything
/// non-ASCII up front is both the fix and the truth about the format (a
/// traceparent is hex digits).
fn unhex(s: &str) -> Option<Vec<u8>> {
    let bytes = s.as_bytes();
    if !bytes.len().is_multiple_of(2) || !s.is_ascii() {
        return None;
    }
    bytes
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";

    /// The example from the W3C spec, both ways.
    #[test]
    fn the_spec_example_round_trips() {
        let tp = TraceParent::parse(SAMPLE).expect("the spec's own example parses");
        assert_eq!(tp.trace_id_hex(), "4bf92f3577b34da6a3ce929d0e0e4736");
        assert_eq!(tp.span_id_hex(), "00f067aa0ba902b7");
        assert!(tp.sampled());
        assert_eq!(tp.to_string(), SAMPLE);
    }

    /// A child keeps the trace and the sampling decision and changes only the
    /// span — the trace id is the thread that ties the hops together, and a
    /// hop that re-decided sampling would put a hole in the trace.
    #[test]
    fn a_child_keeps_the_trace_and_the_sampling_decision() {
        let parent = TraceParent::parse(SAMPLE).unwrap();
        let child = parent.child();
        assert_eq!(child.trace_id, parent.trace_id);
        assert_eq!(child.flags, parent.flags);
        assert_ne!(child.span_id, parent.span_id);
    }

    #[test]
    fn a_root_is_sampled_and_fresh_every_time() {
        let a = TraceParent::root();
        let b = TraceParent::root();
        assert!(a.sampled());
        assert_ne!(a.trace_id, b.trace_id);
        assert_eq!(a.to_string().len(), SAMPLE.len());
        assert_eq!(TraceParent::parse(&a.to_string()), Some(a));
    }

    /// Anything we cannot read is no context at all: a new trace rather than
    /// work silently attached to whatever the bytes decoded to.
    #[test]
    fn malformed_headers_are_no_context_rather_than_a_wrong_one() {
        for bad in [
            "",
            "garbage",
            // future version: readable shape, unreadable meaning
            "01-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
            // short trace id
            "00-4bf92f3577b34da6-00f067aa0ba902b7-01",
            // non-hex
            "00-zzf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
            // trailing field
            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01-extra",
            // all-zero ids: what a half-initialised sender emits, and
            // accepting them would merge every such request into one trace
            "00-00000000000000000000000000000000-00f067aa0ba902b7-01",
            "00-4bf92f3577b34da6a3ce929d0e0e4736-0000000000000000-01",
        ] {
            assert_eq!(TraceParent::parse(bad), None, "{bad:?}");
        }
        // and the edge helper turns each of them into a fresh trace
        assert!(TraceParent::parse_or_root(Some("garbage")).sampled());
        assert!(TraceParent::parse_or_root(None).sampled());
    }

    /// The length checks count BYTES, so a field can be the right length and
    /// still hold a multi-byte character — and hex-decoding it by byte index
    /// used to slice through the middle of one and panic. This header comes off
    /// the wire, so that panic was reachable from outside.
    #[test]
    fn a_header_with_multibyte_characters_is_refused_and_does_not_panic() {
        // 3-byte euro sign + 29 ascii = 32 BYTES, the length a trace id needs.
        let trace = format!("\u{20ac}{}", "0".repeat(29));
        assert_eq!(trace.len(), 32, "the point of the case is the byte length");
        assert_eq!(
            TraceParent::parse(&format!("00-{trace}-00f067aa0ba902b7-01")),
            None
        );
        // ... and the same trick in each of the other two fields.
        let span = format!("\u{20ac}{}", "0".repeat(13));
        assert_eq!(span.len(), 16);
        assert_eq!(
            TraceParent::parse(&format!("00-4bf92f3577b34da6a3ce929d0e0e4736-{span}-01")),
            None
        );
        assert_eq!(
            TraceParent::parse("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-\u{e9}"),
            None
        );
    }

    /// An unsampled context stays unsampled all the way down: the decision was
    /// made at the edge and every hop after it is bound by it.
    #[test]
    fn an_unsampled_context_is_carried_through_unchanged() {
        let tp =
            TraceParent::parse("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-00").unwrap();
        assert!(!tp.sampled());
        assert!(!tp.child().sampled());
        assert!(tp.to_string().ends_with("-00"));
    }

    /// A header a real client sends has whitespace around it often enough to
    /// be worth not tripping over.
    #[test]
    fn surrounding_whitespace_is_not_a_malformed_header() {
        assert_eq!(
            TraceParent::parse(&format!("  {SAMPLE}\n")),
            TraceParent::parse(SAMPLE)
        );
    }
}
