// Bazel's `Manifest`: what an action's sandbox should contain, and nothing more. It names its
// input tree by digest but does not carry it -- see `tree::resolve`. Fields decode on first access:
// scalars are slices of the frame, maps are built once and kept.

use crate::wire::{parse_map_entry, string, Reader, Writer};
use std::cell::OnceCell;
use std::collections::BTreeMap;

/// Declared outputs, both maps from one pass over field 5.
#[derive(Default, Debug, PartialEq)]
pub struct Outputs {
    /// In-sandbox path -> `"dir"` or `"file"`. Under path mapping this key is the MAPPED path.
    pub kinds: BTreeMap<String, String>,
    /// Output key -> where `collect` must actually put it, when path mapping moved it.
    pub dests: BTreeMap<String, String>,
}

pub struct Manifest<'a> {
    bytes: &'a [u8],
    outputs: OnceCell<Outputs>,
    writable_dirs: OnceCell<BTreeMap<String, String>>,
}

impl<'a> Manifest<'a> {
    pub fn new(bytes: &'a [u8]) -> Manifest<'a> {
        Manifest { bytes, outputs: OnceCell::new(), writable_dirs: OnceCell::new() }
    }

    /// Encode a `Manifest` frame from REAPI v2 `Action` / `Command` / `Platform` fields so a
    /// REAPI v2 `Execution.Execute` call drives the exact same `Backend::create` / `collect` /
    /// `destroy` interface.
    pub fn encode(
        mnemonic: &str,
        exec_root: &str,
        input_root_digest: &str,
        outputs: &[(String, String, String)],
        writable_dirs: &[String],
    ) -> Vec<u8> {
        let mut w = Writer::default();
        if !mnemonic.is_empty() {
            w.str(1, mnemonic);
        }
        if !exec_root.is_empty() {
            w.str(2, exec_root);
        }
        if !input_root_digest.is_empty() {
            let mut dg = Writer::default();
            dg.str(1, input_root_digest);
            w.msg(4, &dg.out);
        }
        for (path, kind, dest) in outputs {
            let mut out_val = Writer::default();
            out_val.str(1, kind);
            if !dest.is_empty() {
                out_val.str(2, dest);
            }
            let mut entry = Writer::default();
            entry.str(1, path);
            entry.msg(2, &out_val.out);
            w.msg(5, &entry.out);
        }
        for dir in writable_dirs {
            let mut entry = Writer::default();
            entry.str(1, dir);
            entry.msg(2, b"");
            w.msg(6, &entry.out);
        }
        w.out
    }

    /// The action mnemonic (field 1).
    pub fn mnemonic(&self) -> Option<&'a str> {
        text(field(self.bytes, 1)?)
    }

    /// The directory containing the workspace exec root (field 2). Anchors the default content
    /// location: a leaf with no captured `Push.content` entry lives at `exec_root/<tree path>`.
    pub fn exec_root(&self) -> Option<&'a str> {
        text(field(self.bytes, 2)?)
    }

    /// `input_root_digest` (field 4), the identity of the whole input tree. Empty when unset --
    /// a manifest with no tree, not an error.
    pub fn input_root_digest(&self) -> &'a str {
        field(self.bytes, 4).and_then(|d| field(d, 1)).and_then(text).unwrap_or_default()
    }

    /// Declared outputs (field 5), parsed once.
    pub fn outputs(&self) -> &Outputs {
        self.outputs.get_or_init(|| {
            let mut out = Outputs::default();
            each(self.bytes, 5, |entry| {
                if let Some((key, kind, dest)) = output_entry(entry) {
                    if !dest.is_empty() {
                        out.dests.insert(key.clone(), dest);
                    }
                    out.kinds.insert(key, kind);
                }
            });
            out
        })
    }

    /// Directories the action may write into (field 6), parsed once.
    pub fn writable_dirs(&self) -> &BTreeMap<String, String> {
        self.writable_dirs.get_or_init(|| {
            let mut map = BTreeMap::new();
            each(self.bytes, 6, |entry| {
                if let Some((k, v)) = parse_map_entry(entry) {
                    map.insert(k, v);
                }
            });
            map
        })
    }

    /// The lexicographically first declared output -- the action-identity anchor for slot binding.
    /// Unlike the input root digest it survives an edit to the action's inputs.
    pub fn first_output(&self) -> Option<&str> {
        self.outputs().kinds.keys().next().map(String::as_str)
    }
}

/// The payload of the first length-delimited `want` field in `bytes`.
fn field(bytes: &[u8], want: u64) -> Option<&[u8]> {
    let mut r = Reader::new(bytes);
    while let Some((f, wire)) = r.next_key() {
        if (f, wire) == (want, 2) {
            return r.len_slice();
        }
        r.skip(wire);
    }
    None
}

/// Visit every length-delimited occurrence of `want` -- a repeated or map field.
fn each(bytes: &[u8], want: u64, mut visit: impl FnMut(&[u8])) {
    let mut r = Reader::new(bytes);
    while let Some((f, wire)) = r.next_key() {
        match (f, wire) {
            (f, 2) if f == want => match r.len_slice() {
                Some(entry) => visit(entry),
                None => return,
            },
            (_, w) => r.skip(w),
        }
    }
}

/// A field's bytes as text. None if it is not UTF-8: reported as an absent field rather than
/// silently replaced, since every one of these is a path.
fn text(b: &[u8]) -> Option<&str> {
    std::str::from_utf8(b).ok()
}

/// `map<string, Output>` entry: {1: key, 2: Output{1: type, 2: dest}} -> (key, kind, dest).
fn output_entry(b: &[u8]) -> Option<(String, String, String)> {
    let (mut key, mut kind, mut dest) = (String::new(), String::new(), String::new());
    let mut r = Reader::new(b);
    while let Some((f, wire)) = r.next_key() {
        match (f, wire) {
            (1, 2) => key = string(r.len_slice()?),
            (2, 2) => (kind, dest) = parse_map_entry(r.len_slice()?)?,
            (_, w) => r.skip(w),
        }
    }
    r.ok.then_some((key, kind, dest))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::Writer;

    /// A manifest as Bazel sends it: scalars, an `input_root_digest` naming a tree that is not
    /// here, two outputs (one path-mapped), one writable dir.
    fn wire_manifest() -> Vec<u8> {
        let mut digest = Writer::default();
        digest.str(1, "rootdg");
        let mut out_a = Writer::default();
        out_a.str(1, "file");
        let mut out_b = Writer::default();
        out_b.str(1, "file");
        out_b.str(2, "/_main/unmapped/b.o");

        let mut w = Writer::default();
        w.str(1, "CppCompile");
        w.str(2, "/exec/root");
        w.msg(4, &digest.out);
        w.msg(5, &entry("/_main/z.o", &out_a.out));
        w.msg(5, &entry("/_main/mapped/b.o", &out_b.out));
        w.msg(6, &entry("/_main/scratch", b""));
        w.out
    }

    fn entry(key: &str, value: &[u8]) -> Vec<u8> {
        let mut w = Writer::default();
        w.str(1, key);
        w.msg(2, value);
        w.out
    }

    #[test]
    fn scalars_are_slices_of_the_frame() {
        let bytes = wire_manifest();
        let m = Manifest::new(&bytes);
        assert_eq!(m.mnemonic(), Some("CppCompile"));
        assert_eq!(m.exec_root(), Some("/exec/root"));
        assert_eq!(m.input_root_digest(), "rootdg");
        // Borrowed, not copied: the text lives inside the frame we were handed.
        let inside = |s: &str| {
            let base = bytes.as_ptr() as usize;
            let p = s.as_ptr() as usize;
            p >= base && p < base + bytes.len()
        };
        assert!(inside(m.mnemonic().unwrap()) && inside(m.exec_root().unwrap()));
    }

    #[test]
    fn outputs_split_kinds_from_path_mapped_destinations() {
        let bytes = wire_manifest();
        let m = Manifest::new(&bytes);
        let outputs = m.outputs();
        assert_eq!(outputs.kinds.len(), 2);
        assert_eq!(outputs.kinds.get("/_main/z.o").map(String::as_str), Some("file"));
        // Only the mapped output carries a destination.
        assert_eq!(outputs.dests.get("/_main/mapped/b.o").map(String::as_str), Some("/_main/unmapped/b.o"));
        assert!(!outputs.dests.contains_key("/_main/z.o"));
        assert_eq!(m.writable_dirs().keys().next().map(String::as_str), Some("/_main/scratch"));
    }

    /// Slot binding wants the action's identity, which is its first output, not its inputs.
    #[test]
    fn first_output_is_the_lexicographically_first_key() {
        let bytes = wire_manifest();
        assert_eq!(Manifest::new(&bytes).first_output(), Some("/_main/mapped/b.o"));
    }

    /// A field nobody sent reads as absent, and a manifest naming no tree says so with an empty
    /// digest -- there is nothing to resolve, which is not a failure.
    #[test]
    fn missing_fields_read_as_absent() {
        let m = Manifest::new(&[]);
        assert_eq!(m.mnemonic(), None);
        assert_eq!(m.exec_root(), None);
        assert_eq!(m.input_root_digest(), "");
        assert!(m.outputs().kinds.is_empty());
        assert!(m.writable_dirs().is_empty());
        assert_eq!(m.first_output(), None);
    }

    /// Unknown fields are skipped by wire type, so a newer Bazel adding fields cannot break us.
    #[test]
    fn unknown_fields_are_skipped() {
        let mut w = Writer::default();
        w.uint(9, 42); // a varint field we have never heard of
        w.str(1, "Mnemonic");
        w.msg(11, b"whatever"); // length-delimited ditto
        w.str(2, "/exec/root");
        let m = Manifest::new(&w.out);
        assert_eq!(m.mnemonic(), Some("Mnemonic"));
        assert_eq!(m.exec_root(), Some("/exec/root"));
    }
}
