//! The hardlink projection: an action's inputs are `link(2)`s to the host inodes Bazel already
//! holds, laid into a reused slot by a Merkle diff.
//!
//! Nothing here is macOS-only. `link`, `symlink`, `mkdirat`, `rename` are the whole vocabulary, so
//! the same projection is the Linux story too — the one platform-specific behaviour is that a link
//! can be *refused* (a SIP-protected path answers EPERM), and that is handled by catching it rather
//! than predicting it.
//!
//! Two properties follow from linking rather than copying: the sandbox reads pages the host already
//! faulted in, and an executable carries the code signature the kernel already validated. The cost
//! is that a link shares its inode's permission bits, which is why `morph::LinkStore` exists.

pub mod fsops;
pub mod morph;
mod slots;

use backend::tree::{self, Dir, EMPTY_DIRECTORY_DIGEST};
use backend::wire::sha256_hex;
use backend::{Backend, BlobStore, ContentSource, CreateError, Manifest, Options};
use morph::{Context, LinkStore, Missing};
use slots::{Prior, SlotTable};
use std::collections::{BTreeMap, HashMap};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

/// Where this workspace's pool lives. Deterministic across restarts, and readable enough to debug:
/// the workspace's basename plus a digest of its full path.
fn workspace_key(workspace: &str) -> String {
    let base: String = Path::new(workspace)
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default()
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-')
        .take(40)
        .collect();
    format!("{base}-{}", &sha256_hex(workspace.as_bytes())[..16])
}

/// The daemon's one call into this backend. `pool_root=<path>` moves the whole tree, which has to
/// stay on the workspace's volume: `link` is same-device-only and `collect` renames out of a slot.
pub fn open(workspace: &str, options: &Options) -> io::Result<Arc<Hardlink>> {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
    let base = options
        .pool_root
        .clone()
        .unwrap_or_else(|| PathBuf::from(home).join(".sandboxfs/hardlink"));
    let hl = Hardlink::open(&base, workspace)?;
    hl.heal_untracked.store(options.metrics, Ordering::Release);
    Ok(Arc::new(hl))
}

/// What a live sandbox needs remembered between `create` and `collect`.
struct Live {
    slot: usize,
    outputs: BTreeMap<String, String>,
    dests: BTreeMap<String, String>,
}

pub struct Hardlink {
    base: PathBuf,
    root: PathBuf,
    slots_dir: PathBuf,
    /// Leaves Bazel pushed ahead of the creates that name them, pinned for the session.
    content: PathBuf,
    empty_file: PathBuf,
    links: LinkStore,
    table: Mutex<SlotTable>,
    live: Mutex<HashMap<String, Live>>,
    heal_untracked: AtomicBool,
}

impl Hardlink {
    pub fn open(base: &Path, workspace: &str) -> io::Result<Hardlink> {
        let root = base.join(workspace_key(workspace));
        let slots_dir = root.join("slots");
        let content = root.join(".content");
        // A previous controller's slots are directories full of links whose trees died with it.
        // Without a listing to diff against they are not a baseline, only work for the first
        // reconcile to undo, so they go — renamed aside first so startup does not wait on the
        // unlinks.
        if slots_dir.exists() {
            let graveyard = root.join(format!(".dead.{}", std::process::id()));
            if std::fs::rename(&slots_dir, &graveyard).is_ok() {
                std::thread::spawn(move || {
                    let _ = fsops::remove(&graveyard);
                });
            }
        }
        for d in [base, &slots_dir, &content] {
            fsops::mkdir_p(d)?;
        }
        let empty_file = content.join(EMPTY_DIRECTORY_DIGEST);
        if !empty_file.exists() {
            std::fs::write(&empty_file, b"")?;
        }
        // Provide a stable `<base>/slots` symlink pointing to the workspace's `slots_dir` for
        // external callers and integration tests inspecting slots under `pool_root`.
        let base_slots_link = base.join("slots");
        let _ = fsops::remove(&base_slots_link);
        let _ = std::os::unix::fs::symlink(&slots_dir, &base_slots_link);

        Ok(Hardlink {
            base: base.to_path_buf(),
            links: LinkStore::new(root.join(".links"))?,
            root,
            slots_dir,
            content,
            empty_file,
            table: Mutex::new(SlotTable::default()),
            live: Mutex::new(HashMap::new()),
            heal_untracked: AtomicBool::new(false),
        })
    }

    pub fn base_path(&self) -> &Path {
        &self.base
    }

    pub fn slot_metrics(&self) -> (usize, u64, u64, u64, u64) {
        let t = self.table.lock().unwrap();
        (
            t.total_allocated(),
            t.reuse_count(),
            morph::SKIPPED_SUBTREES.load(Ordering::Relaxed),
            morph::REMOVED_ENTRIES.load(Ordering::Relaxed),
            morph::REPAIRED_FILES.load(Ordering::Relaxed),
        )
    }

    /// Invalidate a slot's cached tree listing (e.g. when post-execution verification detects that
    /// an action modified a hardlinked input file inside the slot).
    pub fn invalidate_slot_for(&self, sandbox_id: &str) {
        let slot = self.live.lock().unwrap().get(sandbox_id).map(|l| l.slot);
        if let Some(s) = slot {
            self.table.lock().unwrap().occupy(s, "", "", Prior::default());
        }
    }

    fn slot_path(&self, n: usize) -> PathBuf {
        self.slots_dir.join(n.to_string())
    }

    /// Lay the tree into the slot. `Ok(digests)` with a non-empty list means the tree is there but
    /// some leaves had no host anywhere -- recoverable, and the caller reports it so Bazel pushes
    /// them and retries.
    fn project(
        &self,
        slot_root: &Path,
        prior: &Prior,
        new: &Dir,
        exec_root: &str,
        outputs: &BTreeMap<String, String>,
        writable: &BTreeMap<String, String>,
        verified_mode: bool,
        cas_root: Option<&Path>,
    ) -> io::Result<Vec<String>> {
        morph::clear_outputs(&prior.outputs, &prior.writable, slot_root)?;
        let missing = Missing::default();
        let cx = Context {
            exec_root,
            links: &self.links,
            missing: &missing,
            empty_file: Some(&self.empty_file),
            verified_mode,
            cas_root,
            heal_untracked: self.heal_untracked.load(Ordering::Acquire),
        };
        morph::reconcile(prior.tree.as_deref(), new, slot_root, &cx)?;
        let missing = missing.take();
        if missing.is_empty() {
            morph::prepare_outputs(outputs, writable, slot_root)?;
        }
        Ok(missing)
    }

    /// Return a slot to the pool and delete whatever the pool decided to retire.
    fn release(&self, slot: usize) {
        for n in self.table.lock().unwrap().release(slot) {
            let _ = fsops::remove(&self.slot_path(n));
        }
    }
}

impl Backend for Hardlink {
    fn name(&self) -> &'static str {
        "hardlink"
    }

    fn mount_path(&self) -> &Path {
        &self.root
    }

    fn create(
        &self,
        sandbox_id: &str,
        manifest: &Manifest<'_>,
        store: &BlobStore,
    ) -> Result<String, CreateError> {
        let root_digest = manifest.input_root_digest();
        let exec_root = manifest.exec_root().unwrap_or_default();
        let identity = manifest
            .first_output()
            .or_else(|| manifest.mnemonic())
            .unwrap_or("default")
            .to_string();
        let tree = tree::resolve(root_digest, manifest.exec_root(), store)?;
        let new = tree.map(Arc::new).unwrap_or_default();

        let declared = manifest.outputs();
        let writable = manifest.writable_dirs();
        let cas_root = store.cas_root();

        let (slot, prior) = self.table.lock().unwrap().claim(root_digest, &identity);
        let slot_root = self.slot_path(slot);
        let outcome = self.project(
            &slot_root,
            &prior,
            &new,
            exec_root,
            &declared.kinds,
            writable,
            store.is_verified_mode(),
            cas_root.as_deref(),
        );

        // Anything short of a finished morph forfeits the slot's listing: the next create must
        // treat what is on disk as unknown rather than trust a tree that was never fully placed.
        let settled = matches!(&outcome, Ok(m) if m.is_empty());
        self.table.lock().unwrap().occupy(
            slot,
            root_digest,
            &identity,
            Prior {
                tree: settled.then(|| new.clone()),
                outputs: declared.kinds.clone(),
                writable: writable.clone(),
            },
        );
        if !settled {
            self.release(slot);
        }

        match outcome {
            Ok(missing) if missing.is_empty() => {
                self.live.lock().unwrap().insert(
                    sandbox_id.to_string(),
                    Live { slot, outputs: declared.kinds.clone(), dests: declared.dests.clone() },
                );
                Ok(slot_root.to_string_lossy().into_owned())
            }
            Ok(missing) => Err(CreateError::MissingContent(missing)),
            Err(e) => Err(CreateError::Failed(e)),
        }
    }

    fn collect(&self, sandbox_id: &str, exec_root: &str) -> io::Result<()> {
        let live = self.live.lock().unwrap();
        let Some(l) = live.get(sandbox_id) else { return Ok(()) };
        morph::collect_outputs(&l.outputs, &l.dests, &self.slot_path(l.slot), Path::new(exec_root))
    }

    fn destroy(&self, sandbox_id: &str) {
        let Some(l) = self.live.lock().unwrap().remove(sandbox_id) else { return };
        self.release(l.slot);
    }

    /// Capture the leaves Bazel pushed ahead of the creates that name them. A pushed `location` is
    /// only an assertion about THIS moment, so the content has to be pinned now. A hardlink does
    /// that without copying a byte and without minting an inode, so the page cache stays shared
    /// with the original.
    ///
    /// Without this every leaf falls back to the `exec_root/<tree path>` derivation, which is wrong
    /// for exactly the files Bazel bothers to push: a generated file reached through a runfiles
    /// farm has no such path, so the projection dangles and the action dies on ENOENT.
    fn push(&self, store: &BlobStore, digests: &[String]) {
        for digest in digests {
            let Some(source) = store.take_content(digest) else { continue };
            let pinned = self.content.join(digest);
            let captured = match source {
                ContentSource::Location(path) => {
                    let _ = fsops::remove(&pinned);
                    std::fs::hard_link(&path, &pinned)
                        .or_else(|_| std::fs::copy(&path, &pinned).map(|_| ()))
                        .is_ok()
                }
                // A virtual input (a param file): no host path ever existed, so this IS the copy.
                ContentSource::Inline(bytes) => std::fs::write(&pinned, bytes).is_ok(),
            };
            if captured {
                store.insert_captured(digest.clone(), pinned.to_string_lossy().into_owned());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::MetadataExt;

    fn tmp(tag: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!("hlbackend-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    /// One `Manifest` frame: mnemonic(1), exec_root(2), input_root_digest(4), outputs(5).
    fn manifest_bytes(exec_root: &str, root_digest: &str, outputs: &[(&str, &str)]) -> Vec<u8> {
        use backend::wire::Writer;
        let mut w = Writer::default();
        w.str(1, "Mnemonic");
        w.str(2, exec_root);
        let mut dg = Writer::default();
        dg.str(1, root_digest);
        w.msg(4, &dg.out);
        for (path, kind) in outputs {
            let mut out = Writer::default();
            out.str(1, path);
            let mut v = Writer::default();
            v.str(1, kind);
            out.msg(2, &v.out);
            w.msg(5, &out.out);
        }
        w.out
    }

    /// REAPI `Directory{ files = 1, directories = 2 }`, as Bazel ships it. `resolve` verifies the
    /// root blob against the digest that names it, so every blob is published under its own hash.
    fn publish(
        store: &BlobStore,
        files: &[(&str, &str, u64, bool)],
        subdirs: &[(&str, &str)],
    ) -> String {
        use backend::wire::Writer;
        let node = |name: &str, hash: &str, size: u64| {
            let mut n = Writer::default();
            n.str(1, name);
            let mut d = Writer::default();
            d.str(1, hash);
            d.uint(2, size);
            n.msg(2, &d.out);
            n
        };
        let mut w = Writer::default();
        for (name, hash, size, exec) in files {
            let mut n = node(name, hash, *size);
            n.bool(4, *exec);
            w.msg(1, &n.out);
        }
        for (name, hash) in subdirs {
            w.msg(2, &node(name, hash, 0).out);
        }
        let hash = sha256_hex(&w.out);
        store.insert_dirs([(hash.clone(), w.out)]);
        hash
    }

    /// End to end through the trait: a create lays real links, a second create for the same action
    /// reuses the slot without re-placing them, and collect moves the output out.
    #[test]
    fn serves_a_sandbox_and_reuses_the_slot() {
        let base = tmp("e2e");
        let exec_root = base.join("exec");
        std::fs::create_dir_all(exec_root.join("_main/pkg")).unwrap();
        let host = exec_root.join("_main/pkg/in.txt");
        std::fs::write(&host, b"input").unwrap();

        let fs = Hardlink::open(&base.join("pool"), "/ws/demo").unwrap();
        let store = BlobStore::new();
        let pkg = publish(&store, &[("in.txt", "d1", 5, false)], &[]);
        let main = publish(&store, &[], &[("pkg", &pkg)]);
        let root = publish(&store, &[], &[("_main", &main)]);

        let bytes = manifest_bytes(
            exec_root.to_str().unwrap(),
            &root,
            &[("/_main/bazel-out/out.txt", "file")],
        );
        let m = Manifest::new(&bytes);

        let path = fs.create("sb1", &m, &store).unwrap();
        let placed = Path::new(&path).join("_main/pkg/in.txt");
        let first_ino = std::fs::symlink_metadata(&placed).unwrap().ino();
        assert_eq!(
            first_ino,
            std::fs::symlink_metadata(&host).unwrap().ino(),
            "an input is the host inode, not a copy of it"
        );

        // The action writes its output, then Bazel collects and releases.
        std::fs::write(Path::new(&path).join("_main/bazel-out/out.txt"), b"result").unwrap();
        let dest = base.join("collected");
        fs.collect("sb1", dest.to_str().unwrap()).unwrap();
        assert_eq!(std::fs::read(dest.join("_main/bazel-out/out.txt")).unwrap(), b"result");
        fs.destroy("sb1");

        // Same tree again: the slot comes back, and the diff touches nothing.
        let path2 = fs.create("sb2", &m, &store).unwrap();
        assert_eq!(path2, path, "the same action returns to its own slot");
        assert_eq!(
            std::fs::symlink_metadata(&placed).unwrap().ino(),
            first_ino,
            "an unchanged tree must not re-place a single leaf"
        );
        fs.destroy("sb2");
        let _ = std::fs::remove_dir_all(&base);
    }

    /// A tree naming a blob the store lacks is recoverable, not a failure.
    #[test]
    fn a_missing_directory_blob_asks_rather_than_fails() {
        let base = tmp("missing");
        let fs = Hardlink::open(&base.join("pool"), "/ws/demo").unwrap();
        let store = BlobStore::new();
        let bytes = manifest_bytes("/nowhere", "absent-digest", &[]);
        let m = Manifest::new(&bytes);
        match fs.create("sb", &m, &store) {
            Err(CreateError::MissingContent(d)) => assert_eq!(d, vec!["absent-digest".to_string()]),
            other => panic!("expected MissingContent, got {other:?}"),
        }
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn a_workspace_key_is_stable_and_path_specific() {
        assert_eq!(workspace_key("/a/demo"), workspace_key("/a/demo"));
        assert_ne!(workspace_key("/a/demo"), workspace_key("/b/demo"));
        assert!(workspace_key("/a/demo").starts_with("demo-"));
    }
}
