// The lazyfs projection: nothing is materialized here. One persistent FSKit mount serves every
// sandbox of a workspace, and a create only writes down what the appex needs to build that
// sandbox's subroot the first time anything looks at it — so the FSKit mount is paid once per
// workspace instead of once per action, and an action's inputs cost nothing until read.

use backend::tree::{self, Dir};
use backend::wire::{sha256_hex, Writer};
use backend::{Backend, BlobStore, ContentSource, CreateError, Manifest, Options};
use std::collections::{BTreeMap, HashMap};
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

/// Create `p` and any missing parents. Existing is not an error.
fn mkdir_p(p: &Path) -> io::Result<()> {
    std::fs::create_dir_all(p).map_err(|e| io::Error::new(e.kind(), format!("mkdir_p {}: {e}", p.display())))
}

/// Delete a path — file, symlink, or whole subtree. Missing is not an error.
fn remove(p: &Path) -> io::Result<()> {
    match std::fs::symlink_metadata(p) {
        Ok(m) if m.file_type().is_dir() => std::fs::remove_dir_all(p),
        Ok(_) => std::fs::remove_file(p),
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(io::Error::new(e.kind(), format!("symlink_metadata {}: {e}", p.display()))),
    }
    .map_err(|e| io::Error::new(e.kind(), format!("remove {}: {e}", p.display())))
}

/// Where this workspace's mount and scratch live. Deterministic across restarts, and readable
/// enough to debug: the workspace's basename plus a digest of its full path.
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
/// stay on the workspace's volume: `collect` renames out of scratch.
pub fn open(workspace: &str, options: &Options) -> io::Result<Arc<dyn Backend>> {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
    let base = options.pool_root.clone().unwrap_or_else(|| PathBuf::from(home).join(".sandboxfs/fskit"));
    Ok(Arc::new(Fskit::open(&base, workspace)?))
}

pub struct Fskit {
    root: PathBuf,
    mnt: PathBuf,
    manifests: PathBuf,
    scratch: PathBuf,
    content: PathBuf,
    /// Names a subroot after the create that made it, never after the sandbox id alone: Bazel
    /// reuses ids, and a name the kernel has ever answered ENOENT for is negative-cached per
    /// name — it stops asking us, so a reused name stays dead for the rest of the build.
    epoch: AtomicU64,
    /// Live sandbox id -> the subroot name this create published, for `collect` and `destroy`.
    live: Mutex<HashMap<String, String>>,
}

impl Fskit {
    pub fn open(base: &Path, workspace: &str) -> io::Result<Fskit> {
        let root = base.join(workspace_key(workspace));
        let (mnt, manifests, scratch) = (root.join("mnt"), root.join("manifests"), root.join("scratch"));
        let content = root.join("content");
        for d in [&mnt, &manifests, &scratch, &content] {
            mkdir_p(d)?;
        }
        let fs = Fskit { root, mnt, manifests, scratch, content, epoch: AtomicU64::new(0), live: Mutex::new(HashMap::new()) };
        fs.ensure_mounted()?;
        Ok(fs)
    }

    fn ensure_mounted(&self) -> io::Result<()> {
        let mnt = self.mnt.to_string_lossy();
        let mounted = Command::new("/sbin/mount")
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).lines().any(|l| l.contains(&*mnt) && l.contains("sandboxfs")))
            .unwrap_or(false);
        if mounted {
            return Ok(());
        }
        // One mount for the whole daemon. Resource is the manifests DIR; the appex
        // starts with an empty root and loads <id>.pb on the first lookup of <id>.
        let st = Command::new("/sbin/mount")
            .args(["-F", "-t", "sandboxfs", "-o", "nobrowse"])
            .arg(&self.manifests)
            .arg(&self.mnt)
            .status()?;
        if !st.success() {
            return Err(io::Error::other(format!("mount sandboxfs at {mnt} failed ({st})")));
        }
        Ok(())
    }

    fn manifest_path(&self, name: &str) -> PathBuf {
        self.manifests.join(format!("{name}.pb"))
    }

    /// The name this sandbox is published under, if it is live.
    fn published(&self, sandbox_id: &str) -> Option<String> {
        self.live.lock().unwrap().get(sandbox_id).cloned()
    }
}

/// Point each declared path at the host SCRATCH target the appex symlinks to, pre-created writable
/// so the action's write-through lands on a real file. `is_dir` targets are created themselves; a
/// file's target is left to the action, so only its parent is.
///
/// `rel` is where the target sits under scratch, which is what decides where `collect` renames it:
/// for a path-mapped output that is the DESTINATION Bazel wants, not the mapped path the action
/// writes to.
fn stage<'a>(entries: impl Iterator<Item = (&'a str, &'a str, bool)>, scratch: &Path) -> io::Result<BTreeMap<String, String>> {
    let mut out = BTreeMap::new();
    for (path, rel, is_dir) in entries {
        let target = scratch.join(rel.trim_start_matches('/'));
        mkdir_p(if is_dir { &target } else { target.parent().unwrap_or(&target) })?;
        out.insert(path.to_string(), target.to_string_lossy().into_owned());
    }
    Ok(out)
}

/// Where a runfiles leaf's content really lives on the host.
///
/// A runfiles tree is a symlink forest Bazel does not materialize in the exec root, so the standard
/// `exec_root/<tree path>` derivation has nothing at the farm's own path. The farm mirrors
/// repo-relative structure, so the tail after `.runfiles/<repo>/` is where a direct reference to
/// the same content sits: under the farm's own bazel-out bin root if it is generated, or under the
/// repo root if it is a source file.
fn farm_candidates(exec_root: &str, tree_path: &str) -> Vec<String> {
    let Some((farm, rest)) = tree_path.split_once(".runfiles/") else { return Vec::new() };
    let Some((repo, tail)) = rest.split_once('/') else { return Vec::new() };
    if tail.is_empty() {
        return Vec::new();
    }
    // A repo other than the main one keeps its own subtree on both sides.
    let suffix = if repo == "_main" { tail.to_string() } else { format!("external/{repo}/{tail}") };
    let mut out = Vec::new();
    if let Some(bin) = farm.find("/bin/") {
        out.push(format!("{exec_root}/{}{suffix}", &farm[..bin + "/bin/".len()]));
    }
    if let Some(ws) = tree_path.find('/') {
        out.push(format!("{exec_root}/{}/{suffix}", &tree_path[..ws]));
    }
    out
}

/// Bind every runfiles leaf to a real host file, and name the ones that have none.
///
/// This is the one class of leaf the derivation cannot reach on its own, and the appex resolves
/// host paths lazily -- far too late to tell Bazel anything. So they are settled here: a leaf that
/// resolves is recorded as captured content, which both writes the answer into this tree and means
/// no later create pays the stat again; a leaf with no host copy anywhere goes back as
/// `MissingContent`, which Bazel answers by pushing the bytes (they exist only inside Bazel --
/// `bazel_tools`' own runfiles.bash is never written to an exec root at all).
fn bind_farm_leaves(exec_root: &str, dir: &mut Dir, path: &str, store: &BlobStore, missing: &mut Vec<String>) {
    for f in Arc::make_mut(&mut dir.files) {
        let tree_path = if path.is_empty() { f.name.clone() } else { format!("{path}/{}", f.name) };
        if !f.host_path.is_empty() || f.digest.is_empty() || !tree_path.contains(".runfiles/") {
            continue;
        }
        if let Some(host) = store.captured(&f.digest) {
            f.host_path = host;
            continue;
        }
        let primary = format!("{exec_root}/{tree_path}");
        match std::iter::once(primary)
            .chain(farm_candidates(exec_root, &tree_path))
            .find(|c| std::fs::symlink_metadata(c).is_ok())
        {
            Some(host) => {
                store.insert_captured(f.digest.clone(), host.clone());
                f.host_path = host;
            }
            None => missing.push(f.digest.clone()),
        }
    }
    for sub in Arc::make_mut(&mut dir.directories) {
        let sub_path = if path.is_empty() { sub.name.clone() } else { format!("{path}/{}", sub.name) };
        bind_farm_leaves(exec_root, sub, &sub_path, store, missing);
    }
}

/// What the appex reads for one sandbox. Neither Bazel's manifest nor the daemon wire: only what it
/// takes to project this tree.
///
///   1 exec_root      anchors every file whose `host_path` the tree leaves derived
///   2 root           the resolved input tree, as `tree::encode` writes it
///   3 outputs        map<in-sandbox path, host scratch target>
///   4 writable_dirs  ditto
fn encode(exec_root: &str, root: Option<&Dir>, outputs: &BTreeMap<String, String>, writable: &BTreeMap<String, String>) -> Vec<u8> {
    let mut w = Writer::default();
    w.str(1, exec_root);
    if let Some(root) = root {
        w.msg(2, &tree::encode(root));
    }
    for (field, map) in [(3u32, outputs), (4, writable)] {
        for (k, v) in map {
            let mut entry = Writer::default();
            entry.str(1, k);
            entry.str(2, v);
            w.msg(field, &entry.out);
        }
    }
    w.out
}

/// Move everything the action produced under `src` to the matching path under
/// `exec_root` (rename, same volume). Walks the scratch tree; only produced paths
/// exist, so undeclared/unproduced outputs are naturally skipped.
fn harvest(src: &Path, exec_root: &Path) -> io::Result<()> {
    fn walk(dir: &Path, base: &Path, exec_root: &Path) -> io::Result<()> {
        for e in std::fs::read_dir(dir)?.flatten() {
            let p = e.path();
            let rel = p.strip_prefix(base).unwrap_or(&p);
            let dst = exec_root.join(rel);
            let ft = e.file_type()?;
            if ft.is_dir() {
                mkdir_p(&dst)?;
                walk(&p, base, exec_root)?;
            } else {
                if let Some(parent) = dst.parent() {
                    mkdir_p(parent)?;
                }
                let _ = remove(&dst);
                std::fs::rename(&p, &dst)?;
            }
        }
        Ok(())
    }
    if src.exists() {
        walk(src, src, exec_root)?;
    }
    Ok(())
}

impl Backend for Fskit {
    fn name(&self) -> &'static str {
        "fskit"
    }

    fn mount_path(&self) -> &Path {
        &self.root
    }

    fn create(&self, sandbox_id: &str, manifest: &Manifest<'_>, store: &BlobStore) -> Result<String, CreateError> {
        // Nothing is materialized here, so there is no byte-scan tier to take: the appex needs the
        // whole tree in the file it reads, and every create resolves the closure to write it.
        let mut root = tree::resolve(manifest.input_root_digest(), manifest.exec_root(), store)?;
        let exec_root = manifest.exec_root().unwrap_or_default();
        if let Some(root) = root.as_mut() {
            let mut missing = Vec::new();
            bind_farm_leaves(exec_root, root, "", store, &mut missing);
            if !missing.is_empty() {
                missing.sort();
                missing.dedup();
                return Err(CreateError::MissingContent(missing));
            }
        }
        let name = format!("{sandbox_id}.{}", self.epoch.fetch_add(1, Ordering::Relaxed));
        let scratch = self.scratch.join(&name);
        let declared = manifest.outputs();
        let outputs = stage(
            declared.kinds.iter().map(|(p, kind)| {
                let rel = declared.dests.get(p).map(String::as_str).unwrap_or(p);
                (p.as_str(), rel, kind == "dir")
            }),
            &scratch,
        )?;
        let writable = stage(manifest.writable_dirs().keys().map(|p| (p.as_str(), p.as_str(), true)), &scratch)?;
        let bytes = encode(exec_root, root.as_ref(), &outputs, &writable);
        std::fs::write(self.manifest_path(&name), bytes)?;
        let path = self.mnt.join(&name);
        // Publish it OURSELVES rather than leaving the first touch to the action. This one lookup
        // is what makes the projection real: it reaches the appex, which builds the subroot, and
        // it leaves the kernel holding a POSITIVE entry for the name. Skipping it would let some
        // earlier probe of the same path plant a negative the action can never get past. It also
        // means a manifest the appex cannot read fails the create instead of the action.
        if let Err(e) = std::fs::symlink_metadata(&path) {
            // The mount can go away under us — an appex crash, or someone unmounting by hand —
            // and the daemon outlives any single mount. Remount once and ask again before
            // failing the action.
            self.ensure_mounted()?;
            std::fs::symlink_metadata(&path).map_err(|_| {
                io::Error::new(e.kind(), format!("appex did not project {}: {e}", path.display()))
            })?;
        }
        self.live.lock().unwrap().insert(sandbox_id.to_string(), name);
        Ok(path.to_string_lossy().into_owned())
    }

    fn collect(&self, sandbox_id: &str, exec_root: &str) -> io::Result<()> {
        let Some(name) = self.published(sandbox_id) else { return Ok(()) };
        harvest(&self.scratch.join(name), Path::new(exec_root))
    }

    /// Capture the leaves Bazel pushed ahead of the creates that name them. A pushed `location`
    /// is only an assertion about THIS moment, and the appex reads a file lazily — long after —
    /// so the content has to be pinned here. A hardlink does that without copying a byte and
    /// without minting a new inode, so the page cache stays shared with the original.
    ///
    /// Without this every leaf falls back to the `exec_root/<tree path>` derivation, which is
    /// wrong for exactly the files Bazel bothers to push: a generated file reached through a
    /// runfiles farm has no such path (its content lives under bazel-out), so the projection
    /// dangles and the action dies on ENOENT.
    fn push(&self, store: &BlobStore, digests: &[String]) {
        for digest in digests {
            let Some(source) = store.take_content(digest) else { continue };
            let pinned = self.content.join(digest);
            let captured = match source {
                ContentSource::Location(path) => {
                    let _ = remove(&pinned);
                    std::fs::hard_link(&path, &pinned).or_else(|_| std::fs::copy(&path, &pinned).map(|_| ())).is_ok()
                }
                // A virtual input (a param file): no host path ever existed, so this IS the copy.
                ContentSource::Inline(bytes) => std::fs::write(&pinned, bytes).is_ok(),
            };
            if captured {
                store.insert_captured(digest.clone(), pinned.to_string_lossy().into_owned());
            }
        }
    }

    fn destroy(&self, sandbox_id: &str) {
        let Some(name) = self.live.lock().unwrap().remove(sandbox_id) else { return };
        // Drop the appex's in-memory subroot so a long build doesn't accumulate every sandbox's
        // tree: a lookup of the sentinel evicts it. The name is unique per create, so this lookup
        // is never served from a cached negative either.
        let _ = std::fs::symlink_metadata(self.mnt.join(format!("sandboxfs_evict_{name}")));
        let _ = remove(&self.manifest_path(&name));
        let _ = remove(&self.scratch.join(&name));
    }
}
