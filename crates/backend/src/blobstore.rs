// The session's content-addressed store: `Directory` blobs and captured leaf content, both shipped
// out of band by `Push` (or REAPI v2 `ContentAddressableStorage.BatchUpdateBlobs`). Everything here
// is immutable, so a re-push is a no-op, and a digest a create needs but the store lacks comes back
// as `CreateError::MissingContent`.
//
// Sharded, and no read handle outlives the call that took it: an earlier shape held one read guard
// for a whole tree decode, which stalled every `Push` behind it.

use crate::proto::ContentSource;
use crate::tree::Dir;
use rustc_hash::FxHashMap;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock, RwLock};

const SHARDS: usize = 64;

/// Digests are lowercase hex; `'1'` and `'a'` collide on the low nibble, merging a few buckets.
/// Harmless — this splits locks, it does not index a table.
fn shard(digest: &str) -> usize {
    let b = digest.as_bytes();
    let nibble = |i: usize| b.get(i).map_or(0, |c| (*c & 0xf) as usize);
    (nibble(0) << 3 | nibble(1)) & (SHARDS - 1)
}

type Shards<V> = [RwLock<FxHashMap<String, V>>; SHARDS];

fn shards<V>() -> Shards<V> {
    std::array::from_fn(|_| RwLock::new(FxHashMap::default()))
}

/// Stat fingerprint of a host file registered via REAPI v2 `BatchUpdateBlobs`
/// (`instance_name = "local-file-paths"`).
///
/// A host path registered for digest `D1` may later be deleted or mutated in-place on disk (even
/// to different bytes of the exact same length). Validating `(dev, ino, size, mtime_sec,
/// mtime_nsec)` before hardlinking and after action execution guarantees that mutated or deleted
/// host paths are never trusted as `D1`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedLocation {
    pub path: String,
    pub dev: u64,
    pub ino: u64,
    pub size: u64,
    pub mtime_sec: i64,
    pub mtime_nsec: i64,
}

impl VerifiedLocation {
    pub fn capture(path: String) -> Option<VerifiedLocation> {
        let meta = std::fs::symlink_metadata(&path).ok()?;
        if meta.file_type().is_dir() {
            return None;
        }
        Some(VerifiedLocation {
            path,
            dev: meta.dev(),
            ino: meta.ino(),
            size: meta.len(),
            mtime_sec: meta.mtime(),
            mtime_nsec: meta.mtime_nsec(),
        })
    }

    pub fn matches_disk(&self) -> bool {
        let Ok(meta) = std::fs::symlink_metadata(&self.path) else {
            return false;
        };
        !meta.file_type().is_dir()
            && meta.dev() == self.dev
            && meta.ino() == self.ino
            && meta.len() == self.size
            && meta.mtime() == self.mtime_sec
            && meta.mtime_nsec() == self.mtime_nsec
    }
}

pub struct BlobStore {
    /// Directory structure blobs: digest -> the `Directory` bytes the tree walk parses.
    dirs: Shards<Arc<[u8]>>,
    /// Decoded `Dir` nodes cached by digest in `--cas_root` mode so shared directory subtrees are
    /// parsed once instead of on every `Hardlink::create`.
    resolved_dirs: Shards<Dir>,
    /// Digest -> the controller's OWN copy of that leaf, minted during a `Push` and valid for the
    /// session whatever happens to the path it came from. Resolution order for a node with digest
    /// D: `Manifest.host_mapping[D]` > `captured[D]` > derived `exec_root/<tree path>`.
    captured: Shards<String>,
    /// Multi-candidate verified host locations per digest (`instance_name = "local-file-paths"`).
    verified_locations: Shards<Vec<VerifiedLocation>>,
    /// Host path -> latest digest registered for that path, so re-registering an output path with
    /// a new digest `D2` immediately prunes its stale association with `D1`.
    path_to_digest: Mutex<FxHashMap<String, String>>,
    /// True when the daemon is serving REAPI v2 `instance_name = "local-file-paths"`, disabling
    /// unverified `exec_root/<tree_path>` fallback for non-empty files.
    verified_mode: AtomicBool,
    /// Fast atomic flag indicating whether `cas_root` is configured (`--disk_cache` shared CAS
    /// mode).
    has_cas_root: AtomicBool,
    /// Shared local `--disk_cache` CAS root (`<disk_cache>/[<digest_fn>/]cas`) using the
    /// `<cas_root>/<hash[0..2]>/<hash>` layout.
    cas_root: RwLock<Option<PathBuf>>,
    /// Leaf content staged for the `Backend::push` in progress and drained by it; whatever is left
    /// is dropped, never trusted later. One thread stages and drains it, hence a plain Mutex.
    pending: Mutex<FxHashMap<String, ContentSource>>,
    /// Latched from the first decoded manifest (field 2 is session-stable), so push-time capture
    /// can resolve relative `location` values before it has a manifest of its own.
    exec_root: OnceLock<String>,
}

impl Default for BlobStore {
    fn default() -> BlobStore {
        BlobStore {
            dirs: shards(),
            resolved_dirs: shards(),
            captured: shards(),
            verified_locations: shards(),
            path_to_digest: Mutex::new(FxHashMap::default()),
            verified_mode: AtomicBool::new(false),
            has_cas_root: AtomicBool::new(false),
            cas_root: RwLock::new(None),
            pending: Mutex::new(FxHashMap::default()),
            exec_root: OnceLock::new(),
        }
    }
}

impl BlobStore {
    pub fn new() -> BlobStore {
        BlobStore::default()
    }

    pub fn enable_verified_mode(&self) {
        self.verified_mode.store(true, Ordering::Release);
    }

    pub fn is_verified_mode(&self) -> bool {
        self.verified_mode.load(Ordering::Acquire)
    }

    pub fn has_cas_root(&self) -> bool {
        self.has_cas_root.load(Ordering::Acquire)
    }

    pub fn set_cas_root(&self, root: PathBuf) {
        {
            let guard = self.cas_root.read().unwrap();
            if guard.as_ref() == Some(&root) {
                return;
            }
        }
        let mut guard = self.cas_root.write().unwrap();
        if guard.as_ref() != Some(&root) {
            // Pre-create the 256 two-hex-digit shard directories once so output capture never needs
            // `create_dir_all` on the per-file hot path.
            const HEX: &[u8; 16] = b"0123456789abcdef";
            let _ = std::fs::create_dir_all(&root);
            for &hi in HEX {
                for &lo in HEX {
                    let prefix = [hi, lo];
                    let s = unsafe { std::str::from_utf8_unchecked(&prefix) };
                    let _ = std::fs::create_dir(root.join(s));
                }
            }
            *guard = Some(root);
            self.has_cas_root.store(true, Ordering::Release);
        }
    }

    pub fn resolved_dir(&self, hash: &str) -> Option<Dir> {
        self.resolved_dirs[shard(hash)].read().unwrap().get(hash).cloned()
    }

    pub fn insert_resolved_dir(&self, hash: String, dir: Dir) {
        self.resolved_dirs[shard(&hash)].write().unwrap().entry(hash).or_insert(dir);
    }

    pub fn cas_root(&self) -> Option<PathBuf> {
        if !self.has_cas_root() {
            return None;
        }
        self.cas_root.read().unwrap().clone()
    }

    /// Resolves `<cas_root>/<hash[0..2]>/<hash>` for `hash` when `cas_root` is configured.
    pub fn cas_blob_path(&self, hash: &str) -> Option<PathBuf> {
        if !self.has_cas_root()
            || hash.len() < 2
            || hash.contains('/')
            || hash.contains('\\')
            || hash.contains('.')
            || !hash.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
        {
            return None;
        }
        let guard = self.cas_root.read().unwrap();
        let root = guard.as_ref()?;
        Some(root.join(&hash[..2]).join(hash))
    }

    /// Immutable and content-addressed, so a digest already present keeps its bytes.
    pub fn insert_dirs(&self, blobs: impl IntoIterator<Item = (String, Vec<u8>)>) {
        for (hash, bytes) in blobs {
            self.dirs[shard(&hash)].write().unwrap().entry(hash).or_insert_with(|| Arc::from(bytes.into_boxed_slice()));
        }
    }

    /// The `Directory` (or CAS blob) bytes for a digest, or None if the store lacks it (→
    /// `MissingContent`). Checks the in-memory `dirs` shard first; on a miss when `cas_root` is
    /// configured (`--disk_cache` shared CAS mode), reads `<cas_root>/<hash[0..2]>/<hash>` from
    /// disk and caches it in `dirs`.
    pub fn dir(&self, hash: &str) -> Option<Arc<[u8]>> {
        if let Some(cached) = self.dirs[shard(hash)].read().unwrap().get(hash).cloned() {
            return Some(cached);
        }
        if let Some(cas_path) = self.cas_blob_path(hash) {
            if let Ok(bytes) = std::fs::read(&cas_path) {
                let arc: Arc<[u8]> = Arc::from(bytes.into_boxed_slice());
                self.dirs[shard(hash)].write().unwrap().insert(hash.to_string(), arc.clone());
                return Some(arc);
            }
        }
        None
    }

    /// Stage leaf content for the `Backend::push` that follows.
    pub fn stage_content(&self, content: impl IntoIterator<Item = (String, ContentSource)>) {
        self.pending.lock().unwrap().extend(content);
    }

    /// Take one staged leaf, to capture it now. Drains: the second call returns None.
    pub fn take_content(&self, digest: &str) -> Option<ContentSource> {
        self.pending.lock().unwrap().remove(digest)
    }

    /// End the staging window. An undrained digest is simply absent, which a dependent `Create`
    /// reports as `MissingContent` and Bazel answers by pushing it again.
    pub fn clear_pending(&self) -> usize {
        let mut g = self.pending.lock().unwrap();
        let n = g.len();
        g.clear();
        n
    }

    /// Record a captured leaf. Pinned for the session; last write wins for a digest.
    pub fn insert_captured(&self, digest: String, host: String) {
        self.captured[shard(&digest)].write().unwrap().insert(digest, host);
    }

    /// The captured copy of a digest, if this session captured it.
    pub fn captured(&self, digest: &str) -> Option<String> {
        self.captured[shard(digest)].read().unwrap().get(digest).cloned()
    }

    /// Register a host path for `digest` in REAPI v2 `local-file-paths` mode.
    /// Captures the stat fingerprint `(dev, ino, size, mtime)` at registration time and prunes any
    /// prior digest association for `path`.
    pub fn register_verified_location(&self, digest: String, path: String) -> bool {
        let normalized = Path::new(&path)
            .components()
            .collect::<std::path::PathBuf>()
            .to_string_lossy()
            .into_owned();
        {
            let mut p2d = self.path_to_digest.lock().unwrap();
            if let Some(prev_digest) = p2d.insert(normalized.clone(), digest.clone()) {
                if prev_digest != digest {
                    let mut prev_shard =
                        self.verified_locations[shard(&prev_digest)].write().unwrap();
                    if let Some(list) = prev_shard.get_mut(&prev_digest) {
                        list.retain(|loc| loc.path != normalized);
                        if list.is_empty() {
                            prev_shard.remove(&prev_digest);
                        }
                    }
                }
            }
        }
        let Some(loc) = VerifiedLocation::capture(normalized.clone()) else {
            return false;
        };
        let mut s = self.verified_locations[shard(&digest)].write().unwrap();
        let list = s.entry(digest).or_default();
        if let Some(existing) = list.iter_mut().find(|e| e.path == normalized) {
            *existing = loc;
        } else {
            list.push(loc);
        }
        true
    }

    /// Resolve a verified host path for `digest` (registered via `INSTANCE_LOCAL_FILE_PATHS`),
    /// pruning any candidates whose on-disk stat fingerprint no longer matches registration time.
    pub fn resolve_verified_host(&self, digest: &str) -> Option<String> {
        if self.verified_locations[shard(digest)].read().unwrap().get(digest).is_none() {
            return None;
        }
        let mut s = self.verified_locations[shard(digest)].write().unwrap();
        if let Some(list) = s.get_mut(digest) {
            list.retain(|loc| loc.matches_disk());
            let found = list.first().map(|loc| loc.path.clone());
            if list.is_empty() {
                s.remove(digest);
            }
            if found.is_some() {
                return found;
            }
        }
        None
    }

    /// Returns true if `digest` is present either as a CAS blob, a captured file, or a valid
    /// verified host location.
    pub fn has_blob_or_location(&self, digest: &str) -> bool {
        if digest == crate::tree::EMPTY_DIRECTORY_DIGEST {
            return true;
        }
        if self.dir(digest).is_some() || self.captured(digest).is_some() {
            return true;
        }
        if let Some(cas_path) = self.cas_blob_path(digest) {
            if cas_path.exists() {
                return true;
            }
        }
        self.resolve_verified_host(digest).is_some()
    }

    /// Returns all currently valid registered host paths for `digest` (pruning stale ones).
    pub fn registered_paths_for(&self, digest: &str) -> Vec<String> {
        let mut s = self.verified_locations[shard(digest)].write().unwrap();
        let Some(list) = s.get_mut(digest) else {
            return Vec::new();
        };
        list.retain(|loc| loc.matches_disk());
        let out = list.iter().map(|l| l.path.clone()).collect();
        if list.is_empty() {
            s.remove(digest);
        }
        out
    }

    /// Snapshot all valid `(digest, path)` pairs across all shards for diagnostic reporting.
    pub fn all_registered_paths(&self) -> Vec<(String, String)> {
        let mut out = Vec::new();
        for s in &self.verified_locations {
            let mut guard = s.write().unwrap();
            guard.retain(|dg, list| {
                list.retain(|loc| loc.matches_disk());
                for loc in list.iter() {
                    out.push((dg.clone(), loc.path.clone()));
                }
                !list.is_empty()
            });
        }
        out.sort();
        out
    }

    /// Verify that all `VerifiedLocation` entries for `digests` still match disk after an action
    /// finishes (`AbstractSandboxSpawnRunner.verifyPostCondition`).
    /// If any hardlinked input was modified in-place during execution, it is evicted (and if in
    /// `--disk_cache/cas/`, the corrupted CAS blob is unlinked so it cannot poison subsequent
    /// actions) and an error naming the modified file is returned.
    pub fn verify_post_condition(&self, digests: &[String]) -> Result<(), String> {
        let has_cas_root = self.has_cas_root();
        for dg in digests {
            let mut s = self.verified_locations[shard(dg)].write().unwrap();
            let Some(list) = s.get_mut(dg) else { continue };
            let mut tampered_path: Option<String> = None;
            list.retain(|loc| {
                if loc.matches_disk() {
                    true
                } else {
                    if has_cas_root {
                        let _ = std::fs::remove_file(&loc.path);
                    }
                    if tampered_path.is_none() {
                        tampered_path = Some(loc.path.clone());
                    }
                    false
                }
            });
            if list.is_empty() {
                s.remove(dg);
            }
            if let Some(p) = tampered_path {
                return Err(format!("input dependency '{p}' was modified during execution"));
            }
        }
        Ok(())
    }

    /// Verify that all CAS blobs `(digest, expected_size)` in `cas_root` still match their expected
    /// size and content hash after an action finishes
    /// (`AbstractSandboxSpawnRunner.verifyPostCondition`). If any hardlinked CAS blob was modified
    /// in-place during execution, it is unlinked from `--disk_cache/cas/` so it cannot poison
    /// subsequent actions.
    pub fn verify_cas_post_condition(&self, files: &[(String, u64)]) -> Result<(), String> {
        for (dg, expected_size) in files {
            let Some(cas_path) = self.cas_blob_path(dg) else { continue };
            let tampered = match std::fs::symlink_metadata(&cas_path) {
                Ok(meta) => {
                    meta.len() != *expected_size
                        || std::fs::read(&cas_path)
                            .map(|b| crate::wire::sha256_hex(&b) != *dg)
                            .unwrap_or(true)
                }
                Err(_) => false,
            };
            if tampered {
                let _ = std::fs::remove_file(&cas_path);
                return Err(format!(
                    "input dependency '{}' was modified during execution",
                    cas_path.display()
                ));
            }
        }
        Ok(())
    }

    /// Latch the session exec root (idempotent — field 2 is session-stable).
    pub fn set_exec_root(&self, er: &str) {
        let _ = self.exec_root.set(er.to_string());
    }

    pub fn exec_root(&self) -> Option<&str> {
        self.exec_root.get().map(String::as_str)
    }

    pub fn len(&self) -> usize {
        self.dirs.iter().map(|s| s.read().unwrap().len()).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn captured_content_and_blobs_are_pinned_for_the_session() {
        let store = BlobStore::new();
        store.insert_dirs([("dg1".to_string(), b"dir".to_vec())]);
        store.insert_captured("aaaa".to_string(), "/pool/.content/aaaa".to_string());

        // Content-addressed: re-capturing a digest just refreshes the host (last write wins).
        store.insert_captured("aaaa".to_string(), "/pool/.content/aaaa2".to_string());
        assert_eq!(store.captured("aaaa").as_deref(), Some("/pool/.content/aaaa2"));

        // Both tiers survive for the controller's lifetime — nothing retires them.
        assert!(store.dir("dg1").is_some());
    }

    /// Immutability: a second push of a digest keeps the bytes already stored.
    #[test]
    fn re_pushing_a_digest_keeps_the_original_bytes() {
        let store = BlobStore::new();
        store.insert_dirs([("dg".to_string(), b"first".to_vec())]);
        store.insert_dirs([("dg".to_string(), b"second".to_vec())]);
        assert_eq!(&*store.dir("dg").unwrap(), b"first");
    }

    /// Staged content is drainable exactly once, and what a backend leaves behind does not
    /// outlive its push — a `Location` path is only an assertion about push time.
    #[test]
    fn staged_content_is_taken_once_and_the_rest_is_dropped() {
        let store = BlobStore::new();
        store.stage_content([
            ("a".to_string(), ContentSource::Inline(b"x".to_vec())),
            ("b".to_string(), ContentSource::Location("/tmp/gone".to_string())),
        ]);
        assert!(matches!(store.take_content("a"), Some(ContentSource::Inline(_))));
        assert!(store.take_content("a").is_none(), "a staged leaf is drained exactly once");
        assert_eq!(store.clear_pending(), 1, "the undrained location is dropped, not remembered");
        assert!(store.take_content("b").is_none());
    }

    #[test]
    fn exec_root_latches_the_first_value() {
        let store = BlobStore::new();
        assert_eq!(store.exec_root(), None);
        store.set_exec_root("/exec/root");
        store.set_exec_root("/other");
        assert_eq!(store.exec_root(), Some("/exec/root"));
    }

    /// Every digest must land in a shard that exists, including degenerate short keys.
    #[test]
    fn sharding_stays_in_bounds_for_any_key() {
        for k in ["", "a", "0", "e3b0c442", "ZZZ"] {
            assert!(shard(k) < SHARDS, "{k:?}");
        }
    }
}
