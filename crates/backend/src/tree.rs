use crate::blobstore::BlobStore;
use crate::wire::{parse_digest, parse_map_entry, sha256_hex, string, Reader, Writer};
use rustc_hash::{FxHashMap as HashMap, FxHashSet as HashSet};
use std::sync::Arc;

/// What an empty `Directory` hashes to. Bazel ships no blob for it, so this is never a missing
/// digest. `node_properties` are excluded from the hash, so a tree-artifact reached through a
/// runfiles farm collapses to it too, despite having content -- see `strip_runfiles_prefix`.
pub const EMPTY_DIRECTORY_DIGEST: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

/// A runfiles tree mirrors the repo-relative structure exactly, so the tail after
/// `<target>.runfiles/<repo>/` is where a direct reference to the same content would live.
pub(crate) fn strip_runfiles_prefix(path: &str) -> Option<&str> {
    let after_marker = path.split_once(".runfiles/")?.1;
    let (_repo, tail) = after_marker.split_once('/')?;
    Some(tail)
}

/// Absolutize a host source. Only leaves with one reach here; the rest stay empty and are derived
/// at placement time.
pub(crate) fn resolve_host(exec_root: Option<&str>, mapped: Option<&str>) -> String {
    match (exec_root, mapped) {
        (_, None) => String::new(),
        (Some(_), Some(v)) if v.starts_with('/') => v.to_string(),
        (Some(er), Some(v)) => format!("{er}/{v}"),
        (None, Some(v)) => v.to_string(),
    }
}

/// Why a `Dir.host_path` is set, so the morph layer can attribute a wholesale clone to its cause.
#[derive(Default, Clone, Copy, Debug, PartialEq, Eq)]
pub enum DirHostKind {
    #[default]
    None,
    /// Captured content, or a host a backend recorded itself.
    Explicit,
    /// REAPI `node_properties` marker `is_treeartifact`.
    TreeArtifact,
    /// REAPI `node_properties` marker `is_sourcedir`.
    SourceDir,
}

#[derive(Default, Clone, Debug, PartialEq)]
pub struct Dir {
    pub name: String,
    pub digest: String,
    /// One real host directory backs this whole subtree, so it can be cloned in one call.
    /// Children stay populated: the digest still covers them, so content changes are detected.
    pub host_path: String,
    /// Why `host_path` is set; `None` iff `host_path` is empty.
    pub host_kind: DirHostKind,
    pub files: Arc<Vec<File>>,
    pub directories: Arc<Vec<Dir>>,
    pub symlinks: Arc<Vec<Symlink>>,
    /// Where this dir's content probably lives, when it carries the empty digest but sits under a
    /// runfiles farm. UNVERIFIED: the morph layer must confirm content is really there. Kept out of
    /// `host_path` precisely so it cannot skip that check.
    pub speculative_host_path: String,
}

#[derive(Default, Clone, Debug, PartialEq)]
pub struct File {
    pub name: String,
    pub digest: String,
    /// Empty for the common case: the source is `exec_root/<tree path>`, derived at placement time
    /// so only files actually cloned ever allocate one.
    pub host_path: String,
    pub size: u64,
    pub executable: bool,
    /// True when `host_path` came from a verified host file registered via REAPI v2
    /// `instance_name = "local-file-paths"`. Because `MerkleTreeComputer` sets
    /// `FileNode.is_executable = true` on all files in `v2.Directory`, verified host files keep
    /// their authoritative host mode and inode rather than being copied into `LinkStore`.
    pub from_verified_host: bool,
}

#[derive(Default, Clone, Debug, PartialEq)]
pub struct Symlink {
    pub name: String,
    pub target: String,
}

/// Resolve the tree named by `root_digest`, walking its `Directory` closure out of the store.
/// `None` when no tree was named. `MissingContent` names every digest the store lacked.
pub fn resolve(
    root_digest: &str,
    exec_root: Option<&str>,
    store: &BlobStore,
) -> Result<Option<Dir>, crate::CreateError> {
    if root_digest.is_empty() {
        return Ok(None);
    }
    if store.has_cas_root() && !store.is_verified_mode() {
        if root_digest == EMPTY_DIRECTORY_DIGEST {
            return Ok(Some(Dir::default()));
        }
        let mut missing = Vec::new();
        if let Some(dir) = resolve_cas_dir(root_digest, "", store, &mut missing) {
            if missing.is_empty() {
                return Ok(Some(dir));
            }
        }
        missing.sort();
        missing.dedup();
        return Err(crate::CreateError::MissingContent(missing));
    }
    let (collected, missing) = resolve_closure(root_digest, store);
    if !missing.is_empty() {
        return Err(crate::CreateError::MissingContent(missing));
    }
    // Borrow the resolved blobs for the shared walk; `collected` outlives it.
    let view: HashMap<String, &[u8]> =
        collected.iter().map(|(k, v)| (k.clone(), v.as_ref())).collect();
    build_root(root_digest, &view, Some(store), exec_root).map(Some).map_err(|e| {
        crate::CreateError::Failed(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("input tree: {e}"),
        ))
    })
}

fn resolve_cas_dir(
    digest_hex: &str,
    name: &str,
    store: &BlobStore,
    missing: &mut Vec<String>,
) -> Option<Dir> {
    if digest_hex == EMPTY_DIRECTORY_DIGEST {
        return Some(Dir {
            name: name.to_string(),
            digest: digest_hex.to_string(),
            ..Default::default()
        });
    }
    if let Some(mut cached) = store.resolved_dir(digest_hex) {
        if !name.is_empty() {
            cached.name = name.to_string();
        }
        return Some(cached);
    }
    let Some(bytes) = store.dir(digest_hex) else {
        missing.push(digest_hex.to_string());
        return None;
    };
    let missing_before = missing.len();
    let mut files = Vec::new();
    let mut directories = Vec::new();
    let mut symlinks = Vec::new();
    let mut r = Reader::new(&bytes);
    while let Some((field, wire)) = r.next_key() {
        match (field, wire) {
            (1, 2) => {
                if let Some(g) = r.len_slice() {
                    if let Some(f) = parse_file_node(g, Some(store), None) {
                        files.push(f);
                    }
                }
            }
            (2, 2) => {
                if let Some(g) = r.len_slice() {
                    if let Some((dn_name, dn_digest)) = parse_dir_node(g, true) {
                        if let Some(child) = resolve_cas_dir(&dn_digest, &dn_name, store, missing) {
                            directories.push(child);
                        }
                    }
                }
            }
            (3, 2) => {
                if let Some(g) = r.len_slice() {
                    if let Some(s) = parse_symlink_node(g) {
                        symlinks.push(s);
                    }
                }
            }
            (_, w) => r.skip(w),
        }
    }
    if missing.len() != missing_before {
        return None;
    }
    let d = Dir {
        name: String::new(),
        digest: digest_hex.to_string(),
        files: Arc::new(files),
        directories: Arc::new(directories),
        symlinks: Arc::new(symlinks),
        ..Default::default()
    };
    store.insert_resolved_dir(digest_hex.to_string(), d.clone());
    let mut named = d;
    if !name.is_empty() {
        named.name = name.to_string();
    }
    Some(named)
}

/// Collects all leaf `FileNode` digests reachable from `root_digest_hex` in `store`.
pub fn collect_file_digests(root_digest_hex: &str, store: &BlobStore) -> Vec<String> {
    collect_file_digests_with_sizes(root_digest_hex, store).into_iter().map(|(dg, _)| dg).collect()
}

/// Collects all leaf `FileNode` `(digest, size)` pairs reachable from `root_digest_hex` in `store`.
pub fn collect_file_digests_with_sizes(
    root_digest_hex: &str,
    store: &BlobStore,
) -> Vec<(String, u64)> {
    let (collected, _) = resolve_closure(root_digest_hex, store);
    let mut out = Vec::new();
    for bytes in collected.values() {
        let mut r = Reader::new(bytes);
        while let Some((field, wire)) = r.next_key() {
            match (field, wire) {
                (1, 2) => {
                    if let Some(g) = r.len_slice() {
                        if let Some(f) = parse_file_node(g, None, None) {
                            if !f.digest.is_empty()
                                && f.digest != EMPTY_DIRECTORY_DIGEST
                                && f.size > 0
                            {
                                out.push((f.digest, f.size));
                            }
                        }
                    }
                }
                (_, w) => r.skip(w),
            }
        }
    }
    out.sort();
    out.dedup();
    out
}

/// The blobs reachable from `root_digest_hex`, and the digests the store lacked. A missing blob
/// hides its own descendants, so one pass may not surface every miss -- Bazel pushes what we report
/// and retries, which converges in one round in practice.
pub(crate) fn resolve_closure(
    root_digest_hex: &str,
    store: &BlobStore,
) -> (HashMap<String, Arc<[u8]>>, Vec<String>) {
    let verified_mode = store.is_verified_mode() || store.has_cas_root();
    let mut collected: HashMap<String, Arc<[u8]>> = HashMap::default();
    let mut missing: Vec<String> = Vec::new();
    let mut seen: HashSet<String> = HashSet::default();
    let mut stack: Vec<String> = Vec::new();
    if !root_digest_hex.is_empty() && root_digest_hex != EMPTY_DIRECTORY_DIGEST {
        stack.push(root_digest_hex.to_string());
    }
    while let Some(dg) = stack.pop() {
        if !seen.insert(dg.clone()) {
            continue;
        }
        match store.dir(&dg) {
            Some(bytes) => {
                for child in child_dir_digests(&bytes, verified_mode) {
                    if child != EMPTY_DIRECTORY_DIGEST && !seen.contains(&child) {
                        stack.push(child);
                    }
                }
                collected.insert(dg, bytes);
            }
            None => missing.push(dg),
        }
    }
    missing.sort(); // stable order for the MissingContent reply (and deterministic tests)
    (collected, missing)
}

/// Just the child digests -- enough to walk the closure before building the model.
fn child_dir_digests(b: &[u8], verified_mode: bool) -> Vec<String> {
    let mut r = Reader::new(b);
    let mut out = Vec::new();
    while let Some((field, wire)) = r.next_key() {
        match (field, wire) {
            (2, 2) => {
                if let Some(g) = r.len_slice() {
                    if let Some((_, dg)) = parse_dir_node(g, verified_mode) {
                        out.push(dg);
                    }
                }
            }
            (_, w) => r.skip(w),
        }
    }
    out
}

/// Walk the root out of `directories`, which holds every dir in the tree, root included.
pub(crate) fn build_root(
    root_digest_hex: &str,
    directories: &HashMap<String, &[u8]>,
    captured: Option<&BlobStore>,
    exec_root: Option<&str>,
) -> Result<Dir, String> {
    if root_digest_hex == EMPTY_DIRECTORY_DIGEST {
        return Ok(Dir::default());
    }
    let root_bytes = *directories
        .get(root_digest_hex)
        .ok_or_else(|| format!("no directory blob for input_root_digest {root_digest_hex}"))?;

    // The one entry point worth verifying. Every other blob is trusted as shipped: re-hashing the
    // whole tree would be pure overhead.
    if !captured.map_or(false, |s| s.is_verified_mode() || s.has_cas_root()) {
        let root_hash = sha256_hex(root_bytes);
        if root_hash != root_digest_hex {
            return Err(format!(
                "root digest mismatch: input_root_digest says {root_digest_hex}, root blob hashes to {root_hash}"
            ));
        }
    }

    build_dir(root_bytes, "", root_digest_hex, directories, captured, exec_root, "")
}

/// REAPI `Directory{ files = 1, directories = 2, symlinks = 3, node_properties = 5 }`.
/// `path` is this dir's accumulated path.
pub(crate) fn build_dir(
    b: &[u8],
    name: &str,
    digest_hex: &str,
    child_index: &HashMap<String, &[u8]>,
    // Content captured during a `Push`, digest-keyed. A node with digest D resolves to
    // `captured[D]` if there is one, else the `exec_root/<tree path>` derivation.
    captured: Option<&BlobStore>,
    exec_root: Option<&str>,
    path: &str,
) -> Result<Dir, String> {
    let verified_mode = captured.map_or(false, |s| s.is_verified_mode() || s.has_cas_root());
    let lookup = |dg: &str| -> Option<String> {
        if dg.is_empty() {
            return None;
        }
        captured.and_then(|s| s.captured(dg))
    };
    let mut d = Dir {
        name: name.to_string(),
        digest: digest_hex.to_string(),
        host_path: resolve_host(exec_root, lookup(digest_hex).as_deref()),
        ..Default::default()
    };
    let mut files = Vec::new();
    let mut directories = Vec::new();
    let mut symlinks = Vec::new();
    let mut marker_kind: Option<DirHostKind> = None;
    let mut r = Reader::new(b);
    while let Some((field, wire)) = r.next_key() {
        match (field, wire) {
            (1, 2) => {
                if let Some(g) = r.len_slice() {
                    if let Some(f) = parse_file_node(g, captured, exec_root) {
                        files.push(f);
                    }
                }
            }
            (2, 2) => {
                if let Some(g) = r.len_slice() {
                    if let Some((dn_name, dn_digest)) = parse_dir_node(g, verified_mode) {
                        let child_path = if path.is_empty() {
                            dn_name.clone()
                        } else {
                            format!("{}/{}", path, dn_name)
                        };
                        if dn_digest == EMPTY_DIRECTORY_DIGEST {
                            // Nothing is shipped for the empty digest, so stop rather than look it
                            // up. A runfiles-nested tree artifact collapses to it too, so if the
                            // path says we are inside a farm, leave an unverified candidate.
                            let speculative_host_path = exec_root
                                .filter(|_| !child_path.is_empty())
                                .and_then(|er| {
                                    strip_runfiles_prefix(&child_path)
                                        .map(|tail| format!("{er}/{tail}"))
                                })
                                .unwrap_or_default();
                            directories.push(Dir {
                                name: dn_name,
                                digest: dn_digest,
                                speculative_host_path,
                                ..Default::default()
                            });
                        } else {
                            // Any other absent digest is a missing blob. Failing here names it;
                            // materializing an empty Dir instead surfaces as execvp ENOENT later.
                            let cr = child_index.get(&dn_digest).ok_or_else(|| {
                                format!(
                                    "no directory blob for digest {dn_digest} (dir {child_path:?})"
                                )
                            })?;
                            directories.push(build_dir(
                                cr,
                                &dn_name,
                                &dn_digest,
                                child_index,
                                captured,
                                exec_root,
                                &child_path,
                            )?);
                        }
                    }
                }
            }
            (3, 2) => {
                if let Some(g) = r.len_slice() {
                    if let Some(s) = parse_symlink_node(g) {
                        symlinks.push(s);
                    }
                }
            }
            (5, 2) => {
                if let Some(g) = r.len_slice() {
                    marker_kind = node_property_dir_kind(g);
                }
            }
            (_, w) => r.skip(w),
        }
    }
    d.files = Arc::new(files);
    d.directories = Arc::new(directories);
    d.symlinks = Arc::new(symlinks);
    if !d.host_path.is_empty() {
        d.host_kind = DirHostKind::Explicit;
    } else if let Some(kind) = marker_kind {
        // Marked a tree artifact or source dir: the whole subtree is one real host directory at
        // the usual derivation. The root is the exec_root itself, never wholesale-clonable.
        if let (Some(er), false) = (exec_root, path.is_empty()) {
            d.host_path = format!("{er}/{path}");
            d.host_kind = kind;
        }
    }
    Ok(d)
}

/// `node_properties` (field 5): Bazel stamps `is_treeartifact` / `is_sourcedir` here, the only
/// signal that a directory is backed wholesale by one host directory.
fn node_property_dir_kind(b: &[u8]) -> Option<DirHostKind> {
    let mut r = Reader::new(b);
    while let Some((field, wire)) = r.next_key() {
        match (field, wire) {
            (1, 2) => {
                let g = r.len_slice()?;
                match node_property_name(g).as_deref() {
                    Some("is_treeartifact") => return Some(DirHostKind::TreeArtifact),
                    Some("is_sourcedir") => return Some(DirHostKind::SourceDir),
                    _ => {}
                }
            }
            (_, w) => r.skip(w),
        }
    }
    None
}

fn node_property_name(b: &[u8]) -> Option<String> {
    let mut r = Reader::new(b);
    let mut name = None;
    while let Some((field, wire)) = r.next_key() {
        match (field, wire) {
            (1, 2) => name = r.len_slice().map(string),
            (_, w) => r.skip(w),
        }
    }
    name
}

/// REAPI `FileNode{ name = 1, digest = 2, is_executable = 4 }` (3 is reserved in v2). Almost every
/// file has nothing captured and stays lazily derived.
fn parse_file_node(
    b: &[u8],
    captured: Option<&BlobStore>,
    exec_root: Option<&str>,
) -> Option<File> {
    let mut r = Reader::new(b);
    let mut name = String::new();
    let mut digest = String::new();
    let mut size = 0u64;
    let mut exec = false;
    while let Some((field, wire)) = r.next_key() {
        match (field, wire) {
            (1, 2) => name = string(r.len_slice()?),
            (2, 2) => {
                let (h, s) = parse_digest(r.len_slice()?)?;
                digest = h;
                size = s;
            }
            (4, 0) => exec = r.varint() != 0,
            (_, w) => r.skip(w),
        }
    }
    if name.is_empty() {
        return None;
    }
    let has_cas_root = captured.is_some_and(|s| s.has_cas_root());
    let mut from_verified_host = has_cas_root;
    let mapped = if digest.is_empty() || has_cas_root {
        None
    } else if let Some(host) = captured.and_then(|s| s.resolve_verified_host(&digest)) {
        from_verified_host = true;
        Some(host)
    } else {
        captured.and_then(|s| s.captured(&digest))
    };
    Some(File {
        host_path: resolve_host(exec_root, mapped.as_deref()),
        name,
        digest,
        size,
        executable: exec,
        from_verified_host,
    })
}

/// `DirectoryNode{ string name = 1; Digest digest = 2; }`.
fn parse_dir_node(b: &[u8], verified_mode: bool) -> Option<(String, String)> {
    let mut r = Reader::new(b);
    let mut name = String::new();
    let mut digest = String::new();
    while let Some((field, wire)) = r.next_key() {
        match (field, wire) {
            (1, 2) => name = string(r.len_slice()?),
            (2, 2) => {
                if let Some((h, s)) = parse_digest(r.len_slice()?) {
                    digest = if verified_mode && s == 0 && !h.is_empty() {
                        EMPTY_DIRECTORY_DIGEST.to_string()
                    } else {
                        h
                    };
                }
            }
            (_, w) => r.skip(w),
        }
    }
    Some((name, digest))
}

/// `SymlinkNode{ string name = 1; string target = 2; }`.
fn parse_symlink_node(b: &[u8]) -> Option<Symlink> {
    let mut r = Reader::new(b);
    let mut s = Symlink::default();
    while let Some((field, wire)) = r.next_key() {
        match (field, wire) {
            (1, 2) => s.name = string(r.len_slice()?),
            (2, 2) => s.target = string(r.len_slice()?),
            (_, w) => r.skip(w),
        }
    }
    Some(s)
}

/// Serialize a tree as-is, digests included, so a decode returns exactly what went in. Nothing is
/// re-hashed: a re-derived digest would be in a different domain than the wire ones a later create
/// is matched against.
pub fn encode(d: &Dir) -> Vec<u8> {
    let mut w = Writer::default();
    w.str(1, &d.name);
    w.str(2, &d.digest);
    w.str(3, &d.host_path);
    w.uint(4, d.host_kind as u64);
    w.str(5, &d.speculative_host_path);
    for f in d.files.iter() {
        let mut n = Writer::default();
        n.str(1, &f.name);
        n.str(2, &f.digest);
        n.str(3, &f.host_path);
        n.uint(4, f.size);
        n.bool(5, f.executable);
        n.bool(6, f.from_verified_host);
        w.msg(6, &n.out);
    }
    for sub in d.directories.iter() {
        w.msg(7, &encode(sub));
    }
    for s in d.symlinks.iter() {
        let mut n = Writer::default();
        n.str(1, &s.name);
        n.str(2, &s.target);
        w.msg(8, &n.out);
    }
    w.out
}

/// Inverse of `encode`.
pub fn decode(b: &[u8]) -> Option<Dir> {
    let mut d = Dir::default();
    let mut files = Vec::new();
    let mut directories = Vec::new();
    let mut symlinks = Vec::new();
    let mut r = Reader::new(b);
    while let Some((field, wire)) = r.next_key() {
        match (field, wire) {
            (1, 2) => d.name = string(r.len_slice()?),
            (2, 2) => d.digest = string(r.len_slice()?),
            (3, 2) => d.host_path = string(r.len_slice()?),
            (4, 0) => d.host_kind = host_kind(r.varint()),
            (5, 2) => d.speculative_host_path = string(r.len_slice()?),
            (6, 2) => files.push(decode_file(r.len_slice()?)?),
            (7, 2) => directories.push(decode(r.len_slice()?)?),
            (8, 2) => {
                let (name, target) = parse_map_entry(r.len_slice()?)?;
                symlinks.push(Symlink { name, target });
            }
            (_, w) => r.skip(w),
        }
    }
    d.files = Arc::new(files);
    d.directories = Arc::new(directories);
    d.symlinks = Arc::new(symlinks);
    r.ok.then_some(d)
}

fn decode_file(b: &[u8]) -> Option<File> {
    let mut f = File::default();
    let mut r = Reader::new(b);
    while let Some((field, wire)) = r.next_key() {
        match (field, wire) {
            (1, 2) => f.name = string(r.len_slice()?),
            (2, 2) => f.digest = string(r.len_slice()?),
            (3, 2) => f.host_path = string(r.len_slice()?),
            (4, 0) => f.size = r.varint(),
            (5, 0) => f.executable = r.varint() != 0,
            (6, 0) => f.from_verified_host = r.varint() != 0,
            (_, w) => r.skip(w),
        }
    }
    r.ok.then_some(f)
}

fn host_kind(v: u64) -> DirHostKind {
    match v {
        1 => DirHostKind::Explicit,
        2 => DirHostKind::TreeArtifact,
        3 => DirHostKind::SourceDir,
        _ => DirHostKind::None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::{sha256_hex, Writer};
    use crate::CreateError;

    /// Build a wire manifest (input_root_digest only, NO inline field 14) plus the raw Directory
    /// blobs it references, so a test can push some/all into a store and drive `resolve`.
    fn wire_manifest_and_blobs() -> (Vec<u8>, Vec<(String, Vec<u8>)>) {
        // root -> { file a.c } + { dir "sub" -> { file tool } }
        let mut sub = Writer::default();
        let mut tool_dg = Writer::default();
        tool_dg.str(1, "toolhash");
        let mut tool = Writer::default();
        tool.str(1, "tool");
        tool.msg(2, &tool_dg.out);
        sub.msg(1, &tool.out);
        let sub_bytes = sub.out.clone();
        let sub_dg = sha256_hex(&sub_bytes);

        let mut a_dg = Writer::default();
        a_dg.str(1, "ahash");
        let mut a = Writer::default();
        a.str(1, "a.c");
        a.msg(2, &a_dg.out);
        let mut root = Writer::default();
        root.msg(1, &a.out); // files
        root.msg(2, &dir_node("sub", &sub_bytes)); // directories
        let root_bytes = root.out.clone();
        let root_dg = sha256_hex(&root_bytes);

        let mut root_digest = Writer::default();
        root_digest.str(1, &root_dg);
        let mut w = Writer::default();
        w.msg(4, &root_digest.out); // input_root_digest only -- no field 14
        w.str(2, "/exec/root");

        let blobs = vec![(root_dg, root_bytes), (sub_dg, sub_bytes)];
        (w.out, blobs)
    }

    #[test]
    fn resolves_the_tree_from_the_store() {
        let (manifest, blobs) = wire_manifest_and_blobs();
        let store = BlobStore::new();
        store.insert_dirs(blobs);
        match resolve(&root_digest(&manifest), Some("/exec/root"), &store) {
            Ok(root) => {
                let root = root.expect("root");
                assert_eq!(root.files[0].name, "a.c");
                let sub = root.directories.iter().find(|d| d.name == "sub").expect("sub");
                assert_eq!(sub.files[0].name, "tool");
            }
            Err(e) => panic!("all blobs present, should be Ready: {e:?}"),
        }
    }

    /// Captured content beats the `exec_root/<tree path>` derivation, and a leaf with neither
    /// stays empty for the morph layer to derive.
    #[test]
    fn a_leaf_host_comes_from_captured_content_then_the_exec_root_derivation() {
        let (manifest, blobs) = wire_manifest_and_blobs();
        let store = BlobStore::new();
        store.insert_dirs(blobs);
        // Only sub/tool was captured on its way through a `Push`.
        store.insert_captured("toolhash".to_string(), "/pool/.content/toolhash".to_string());

        match resolve(&root_digest(&manifest), Some("/exec/root"), &store) {
            Ok(root) => {
                let root = root.expect("root");
                let sub = root.directories.iter().find(|d| d.name == "sub").expect("sub");
                assert_eq!(sub.files[0].host_path, "/pool/.content/toolhash", "the captured copy is used verbatim");
                // Nothing captured for a.c, so it stays empty and the morph layer derives
                // `exec_root/<tree path>` at placement time -- no per-file String here.
                assert_eq!(root.files[0].host_path, "", "no captured content -> derived lazily at placement");
            }
            Err(e) => panic!("all blobs present, should resolve: {e:?}"),
        }
    }

    #[test]
    fn reports_missing_blobs_without_failing() {
        let (manifest, blobs) = wire_manifest_and_blobs();
        // Push only the root; the child "sub" blob is absent.
        let store = BlobStore::new();
        store.insert_dirs(blobs[..1].to_vec());
        match resolve(&root_digest(&manifest), Some("/exec/root"), &store) {
            Err(CreateError::MissingContent(hashes)) => {
                assert_eq!(hashes.len(), 1, "exactly the one absent child blob");
                assert_eq!(hashes[0], blobs[1].0, "the sub-dir digest");
            }
            other => panic!("child blob missing, should be MissingContent: {other:?}"),
        }
    }

    #[test]
    fn a_missing_root_blob_reports_the_root_digest() {
        let (manifest, blobs) = wire_manifest_and_blobs();
        let store = BlobStore::new();
        match resolve(&root_digest(&manifest), Some("/exec/root"), &store) {
            Err(CreateError::MissingContent(hashes)) => {
                assert_eq!(hashes, vec![blobs[0].0.clone()], "just the root -- its children are unknown until it arrives");
            }
            other => panic!("empty store, should be MissingContent: {other:?}"),
        }
    }

    /// The digest a manifest names its tree by, read back out of the frame.
    fn root_digest(manifest: &[u8]) -> String {
        crate::Manifest::new(manifest).input_root_digest().to_string()
    }

    fn dir_node(name: &str, child_bytes: &[u8]) -> Vec<u8> {
        let mut digest = Writer::default();
        digest.str(1, &sha256_hex(child_bytes));
        digest.uint(2, child_bytes.len() as u64);
        let mut d = Writer::default();
        d.str(1, name);
        d.msg(2, &digest.out);
        d.out
    }

    /// `Directory{files:[file_name], node_properties:[marker]}` -- the marker is how Bazel says a
    /// directory is a tree artifact or a source dir.
    fn directory_with_marker(file_name: &str, marker: Option<&str>) -> Vec<u8> {
        let mut digest = Writer::default();
        digest.str(1, "fd1");
        let mut file_node = Writer::default();
        file_node.str(1, file_name);
        file_node.msg(2, &digest.out);
        let mut dir = Writer::default();
        dir.msg(1, &file_node.out);
        if let Some(name) = marker {
            let mut prop = Writer::default();
            prop.str(1, name);
            let mut props = Writer::default();
            props.msg(1, &prop.out);
            dir.msg(5, &props.out);
        }
        dir.out
    }

    /// A store holding every blob in `blobs`.
    fn store_of(blobs: &[&[u8]]) -> BlobStore {
        let store = BlobStore::new();
        store.insert_dirs(blobs.iter().map(|b| (sha256_hex(b), b.to_vec())));
        store
    }

    #[test]
    fn a_directory_host_comes_from_its_node_properties_marker() {
        let tree_out = directory_with_marker("f.txt", Some("is_treeartifact"));
        let src_dir = directory_with_marker("f.txt", Some("is_sourcedir"));
        let plain = directory_with_marker("f.txt", None);
        // Distinct content from tree_out: captured hosts are digest-keyed and content-addressed,
        // so a byte-identical sibling would (correctly) share the override.
        let tree_out2 = directory_with_marker("g.txt", Some("is_treeartifact"));

        let mut root = Writer::default();
        root.msg(2, &dir_node("tree_out", &tree_out));
        root.msg(2, &dir_node("src_dir", &src_dir));
        root.msg(2, &dir_node("plain", &plain));
        root.msg(2, &dir_node("tree_out2", &tree_out2));
        let root_dg = sha256_hex(&root.out);

        let store = store_of(&[&root.out, &tree_out, &src_dir, &plain, &tree_out2]);
        store.insert_captured(sha256_hex(&tree_out2), "/explicit/override".to_string());

        let root = resolve(&root_dg, Some("/exec/root"), &store).expect("resolve").expect("root");
        let by_name = |n: &str| root.directories.iter().find(|d| d.name == n).unwrap();

        assert_eq!(by_name("tree_out").host_path, "/exec/root/tree_out", "is_treeartifact derives default");
        assert_eq!(by_name("tree_out").host_kind, DirHostKind::TreeArtifact);
        assert_eq!(by_name("src_dir").host_path, "/exec/root/src_dir", "is_sourcedir derives default");
        assert_eq!(by_name("src_dir").host_kind, DirHostKind::SourceDir);
        assert_eq!(by_name("plain").host_path, "", "no marker, nothing captured -> not wholesale-clonable");
        assert_eq!(by_name("plain").host_kind, DirHostKind::None);
        assert_eq!(by_name("tree_out2").host_path, "/explicit/override", "captured content wins over the marker");
        assert_eq!(by_name("tree_out2").host_kind, DirHostKind::Explicit);
    }

    /// A `DirectoryNode.digest` with no blob behind it is reported as missing, never quietly
    /// materialized as an empty `Dir`. That silent fallback is what once turned a wire bug into a
    /// downstream `execvp` ENOENT with nothing pointing back at the tree.
    #[test]
    fn a_directory_node_with_no_blob_is_missing_not_empty() {
        let real_child = directory_with_marker("f.txt", Some("is_treeartifact"));
        let never_shipped: &[u8] = b"this blob is never shipped";

        let mut root = Writer::default();
        root.msg(2, &dir_node("present", &real_child));
        root.msg(2, &dir_node("missing", never_shipped));
        let root_dg = sha256_hex(&root.out);

        let store = store_of(&[&root.out, &real_child]);
        match resolve(&root_dg, None, &store) {
            Err(CreateError::MissingContent(hashes)) => assert_eq!(hashes, vec![sha256_hex(never_shipped)]),
            other => panic!("expected MissingContent: {other:?}"),
        }
    }

    /// A DirectoryNode pointing at the well-known empty-Directory digest is a real, legitimately
    /// empty directory: Bazel ships no blob for it (an all-default proto3 message serializes to
    /// zero bytes), so it must resolve with no children rather than count as a miss.
    #[test]
    fn an_empty_directory_needs_no_shipped_blob() {
        let mut root = Writer::default();
        root.msg(2, &dir_node("empty_dir", b""));
        let root_dg = sha256_hex(&root.out);

        let root = resolve(&root_dg, None, &store_of(&[&root.out])).expect("resolve").expect("root");
        let empty_dir = &root.directories[0];
        assert_eq!(empty_dir.name, "empty_dir");
        assert_eq!(empty_dir.digest, EMPTY_DIRECTORY_DIGEST);
        assert!(empty_dir.files.is_empty() && empty_dir.directories.is_empty());
        assert!(empty_dir.speculative_host_path.is_empty(), "no runfiles segment in the path -> no candidate");
    }

    #[test]
    fn strip_runfiles_prefix_finds_the_repo_relative_tail() {
        assert_eq!(
            strip_runfiles_prefix("bin.runfiles/_main/node_modules/.aspect_rules_js/acorn@8.12.1/node_modules/acorn"),
            Some("node_modules/.aspect_rules_js/acorn@8.12.1/node_modules/acorn")
        );
        assert_eq!(strip_runfiles_prefix("node_modules/.aspect_rules_js/acorn@8.12.1/node_modules/acorn"), None, "no .runfiles/ segment");
        assert_eq!(strip_runfiles_prefix("bin.runfiles/_main"), None, "no tail after the repo segment");
    }

    /// Chased live with `--sandbox_debug`: a tree-artifact reached through a runfiles symlink farm
    /// collapses to the empty-Directory digest (node_properties are excluded from the hash), so it
    /// looks exactly like an empty dir -- but its path runs through `<target>.runfiles/<repo>/`, so
    /// it gets a speculative candidate at the position a direct reference would have resolved to.
    #[test]
    fn a_runfiles_nested_empty_dir_gets_a_speculative_host_path() {
        let mut main_repo = Writer::default();
        main_repo.msg(2, &dir_node("acorn", b""));
        let mut runfiles = Writer::default();
        runfiles.msg(2, &dir_node("_main", &main_repo.out));
        let mut root = Writer::default();
        root.msg(2, &dir_node("bin.runfiles", &runfiles.out));
        let root_dg = sha256_hex(&root.out);

        let store = store_of(&[&root.out, &runfiles.out, &main_repo.out]);
        let root = resolve(&root_dg, Some("/exec/root"), &store).expect("resolve").expect("root");
        let acorn = &root.directories[0].directories[0].directories[0];
        assert_eq!(acorn.name, "acorn");
        assert_eq!(acorn.digest, EMPTY_DIRECTORY_DIGEST);
        assert_eq!(acorn.speculative_host_path, "/exec/root/acorn", "path bin.runfiles/_main/acorn -> tail is acorn");
    }

    /// The named root digest must match the SHA-256 of the blob serving it: a mismatch is rejected
    /// rather than silently walked.
    #[test]
    fn a_root_digest_mismatch_is_rejected() {
        let mut file_node = Writer::default();
        file_node.str(1, "a.c");
        let mut root = Writer::default();
        root.msg(1, &file_node.out);

        let store = BlobStore::new();
        store.insert_dirs([("not-the-real-hash".to_string(), root.out)]);
        assert!(matches!(resolve("not-the-real-hash", None, &store), Err(CreateError::Failed(_))));
    }

    /// A tree round-trips through our own serialization with every digest intact -- no re-hashing,
    /// so nothing shifts digest domain on the way back.
    #[test]
    fn a_tree_round_trips_with_its_digests_unchanged() {
        let d = Dir {
            digest: "wire-root".into(),
            host_path: "/host/root".into(),
            host_kind: DirHostKind::TreeArtifact,
            files: Arc::new(vec![File {
                name: "a.c".into(),
                digest: "fdg".into(),
                host_path: "/host/a.c".into(),
                size: 3,
                executable: true,
                from_verified_host: true,
            }]),
            directories: Arc::new(vec![Dir {
                name: "sub".into(),
                digest: "sub-dg".into(),
                speculative_host_path: "/spec".into(),
                ..Default::default()
            }]),
            symlinks: Arc::new(vec![Symlink { name: "l".into(), target: "a.c".into() }]),
            ..Default::default()
        };
        assert_eq!(decode(&encode(&d)).expect("round trip"), d);
    }
}
