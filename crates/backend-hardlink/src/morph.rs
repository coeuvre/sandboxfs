//! Turning a manifest tree into files in a slot, and the output scratch around it.
//!
//! `reconcile` is a Merkle diff: where the incoming tree and the slot's last tree agree on a
//! digest, nothing happens at all. Everywhere they differ, the leaf is placed with `link(2)` — the
//! sandbox path and the host path name one inode, so the action reads pages that are already warm
//! and execs code whose signature the kernel has already validated.
//!
//! Leaving a vnode alone is not just fewer syscalls: a directory the diff does not touch reads far
//! faster than one destroyed and recreated. That is what pays for the diff's bookkeeping, and it is
//! the whole reason this backend can be ahead of a projection that rebuilds its forest per action.

use crate::fsops;
use backend::tree::{Dir, File, EMPTY_DIRECTORY_DIGEST};
use std::borrow::Cow;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::io;
use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

pub static SKIPPED_SUBTREES: AtomicU64 = AtomicU64::new(0);
pub static REMOVED_ENTRIES: AtomicU64 = AtomicU64::new(0);
pub static REPAIRED_FILES: AtomicU64 = AtomicU64::new(0);

/// What every level of the recursion needs and none of it changes.
pub struct Context<'a> {
    /// The directory containing the workspace exec root; host paths derive from it.
    pub exec_root: &'a str,
    pub links: &'a LinkStore,
    pub missing: &'a Missing,
    /// Pre-seeded 0-byte file for virtual empty inputs (e.g. `RunfilesTree` `__init__.py`).
    pub empty_file: Option<&'a Path>,
    /// True in REAPI v2 mode (`instance_name = "local-file-paths"`), disabling unverified
    /// `exec_root/<tree_path>` fallback when a non-empty file has no valid `VerifiedLocation`.
    pub verified_mode: bool,
    /// Shared local `--disk_cache` CAS root (`<disk_cache>/[<digest_fn>/]cas`) using the
    /// `<cas_root>/<hash[0..2]>/<hash>` layout.
    pub cas_root: Option<&'a Path>,
    /// When true (`--metrics`), verifies existing hardlinks and scans warm directories for
    /// undeclared scratch files left behind by prior actions.
    pub heal_untracked: bool,
}

/// Leaves a morph could not source, collected for a `MissingContent` reply.
///
/// A leaf resolves either from content the session captured, or from the `exec_root/<tree path>`
/// derivation. The derivation is only a convention, and for a runfiles entry it cannot hold at all
/// — a runfiles tree is a mapping Bazel need never materialize, so those leaves are supposed to
/// arrive as captured content. When one did not, the bytes exist but we have no path to them, and
/// the protocol's answer is to ask: report the digest, let Bazel push it, and let it retry the
/// create. Failing the action instead throws that recovery away.
#[derive(Default)]
pub struct Missing(Mutex<Vec<String>>);

impl Missing {
    fn record(&self, digest: &str) {
        self.0.lock().unwrap().push(digest.to_string());
    }

    pub fn take(&self) -> Vec<String> {
        let mut v = std::mem::take(&mut *self.0.lock().unwrap());
        v.sort();
        v.dedup();
        v
    }
}

/// Mode-corrected copies, keyed by digest.
///
/// A hardlink shares its inode's permission bits, so a leaf the manifest declares executable whose
/// host blob is not `+x` cannot be fixed in the sandbox: `chmod` would mutate Bazel's own file.
/// The answer is one copy we own, minted at 0555 and linked everywhere after. This is the only
/// place this backend copies a byte, and it is memoized per digest because a build places the same
/// blob thousands of times and the deciding `stat` costs as much as the link it gates.
pub struct LinkStore {
    root: PathBuf,
    /// digest -> the 0555 copy, or `None` when the host blob already carried `+x`.
    fixed: Mutex<HashMap<String, Option<PathBuf>>>,
    seq: AtomicU64,
}

impl LinkStore {
    pub fn new(root: PathBuf) -> io::Result<LinkStore> {
        fsops::mkdir_p(&root)?;
        Ok(LinkStore { root, fixed: Mutex::new(HashMap::new()), seq: AtomicU64::new(0) })
    }

    /// Where to link `f` from: the host itself, or a mode-corrected copy. `None` means the host.
    fn source_for(&self, f: &File, host: &Path) -> Option<PathBuf> {
        // For verified host files (`f.from_verified_host`), the host file already carries its
        // authoritative executable bit (`0644` vs `0755`), whereas Bazel's `MerkleTreeComputer`
        // sets `FileNode.is_executable = true` on all files in `v2.Directory`.
        if f.from_verified_host || !f.executable || f.digest.is_empty() {
            return None;
        }
        if let Some(hit) = self.fixed.lock().unwrap().get(&f.digest) {
            return hit.clone();
        }
        let fixed = match fsops::mode_of(host) {
            // Missing hosts are the placement path's problem (runfiles fallbacks, MissingContent);
            // do not cache a verdict for one, or a later push that fixes it would be ignored.
            None => return None,
            Some(m) if m & 0o111 != 0 => None,
            Some(_) => self.mint(&f.digest, host).ok(),
        };
        self.fixed.lock().unwrap().insert(f.digest.clone(), fixed.clone());
        fixed
    }

    /// Copy `host` to `.links/<digest>` at 0555. Staged under a unique name and linked in so two
    /// creates racing on one digest neither show each other a half-written file nor unlink an
    /// already-published inode while a peer is mid-`linkat`.
    fn mint(&self, digest: &str, host: &Path) -> io::Result<PathBuf> {
        let final_path = self.root.join(digest);
        if final_path.exists() {
            return Ok(final_path);
        }
        let tmp =
            self.root.join(format!("{digest}.tmp.{}", self.seq.fetch_add(1, Ordering::Relaxed)));
        std::fs::copy(host, &tmp).map_err(|e| {
            io::Error::new(e.kind(), format!("mint {} from {}: {e}", digest, host.display()))
        })?;
        fsops::set_mode(&tmp, 0o555)?;
        let res = match std::fs::hard_link(&tmp, &final_path) {
            Ok(()) => Ok(final_path),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => Ok(final_path),
            Err(e) => Err(io::Error::new(e.kind(), format!("publish {digest}: {e}"))),
        };
        let _ = fsops::remove(&tmp);
        res
    }
}

/// Join a tree-relative directory path with a child name.
fn join_rel(rel: &str, name: &str) -> String {
    if rel.is_empty() {
        name.to_string()
    } else {
        format!("{rel}/{name}")
    }
}

/// Where a leaf's bytes live on the host. A captured `host_path` wins; in `--cas_root` mode the
/// leaf sits at `<cas_root>/<digest[0..2]>/<digest>`; otherwise it sits at the
/// `exec_root/<tree path>` derivation, built here so only files actually placed allocate one.
fn file_host(f: &File, cx: &Context, rel: &str) -> String {
    if !f.host_path.is_empty() {
        return f.host_path.clone();
    }
    if let Some(cas_root) = cx.cas_root {
        if f.digest.len() >= 2 {
            return cas_root.join(&f.digest[..2]).join(&f.digest).to_string_lossy().into_owned();
        }
    }
    format!("{}/{}", cx.exec_root, join_rel(rel, &f.name))
}

/// Where a runfiles leaf's content really lives on the host.
///
/// A runfiles tree is a symlink forest Bazel does not materialize in the exec root, so the standard
/// derivation has nothing at the farm's own path. The farm mirrors repo-relative structure, so the
/// tail after `.runfiles/<repo>/` is where a direct reference to the same content sits: under the
/// farm's own bin root if it is generated, or under the repo root if it is a source file.
fn farm_candidates(exec_root: &str, tree_path: &str) -> Vec<String> {
    let Some((farm, rest)) = tree_path.split_once(".runfiles/") else { return Vec::new() };
    let Some((repo, tail)) = rest.split_once('/') else { return Vec::new() };
    if tail.is_empty() {
        return Vec::new();
    }
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

/// Place one leaf: a hardlink to the host inode, or a symlink where the link is refused.
///
/// `EXDEV`/`EPERM`/`EMLINK` all arrive as `Unsupported`. `EPERM` is what a SIP-protected path
/// answers, and it cannot be predicted — the signed system volume is firmlinked into the data
/// volume, so `st_dev` matches and only the attempt tells you. A symlink is the only correct
/// fallback there: a *copy* of a platform binary is killed on exec, while a symlink to it runs.
fn place_file(
    f: &File,
    rel: &str,
    dir_fd: &OwnedFd,
    fs_path: &Path,
    cx: &Context,
) -> io::Result<()> {
    if f.host_path.is_empty() && (f.size == 0 || f.digest == EMPTY_DIRECTORY_DIGEST) {
        if let Some(empty) = cx.empty_file {
            if cx.verified_mode
                || cx.cas_root.is_some()
                || !Path::new(&file_host(f, cx, rel)).exists()
            {
                return attach(empty, dir_fd, &f.name, fs_path);
            }
        }
    }
    if cx.verified_mode && cx.cas_root.is_none() && f.host_path.is_empty() {
        if !f.digest.is_empty() {
            cx.missing.record(&f.digest);
            return Ok(());
        }
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("unverified empty digest for {}", f.name),
        ));
    }
    let host = file_host(f, cx, rel);
    let host = PathBuf::from(host);
    let source: Cow<Path> = match cx.links.source_for(f, &host) {
        Some(p) => Cow::Owned(p),
        None => Cow::Borrowed(host.as_path()),
    };
    match attach(&source, dir_fd, &f.name, fs_path) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            if !cx.verified_mode && cx.cas_root.is_none() {
                for retry in farm_candidates(cx.exec_root, &join_rel(rel, &f.name)) {
                    if attach(Path::new(&retry), dir_fd, &f.name, fs_path).is_ok() {
                        return Ok(());
                    }
                }
            }
            if f.digest.is_empty() {
                return Err(e); // nothing to ask Bazel for
            }
            cx.missing.record(&f.digest);
            Ok(())
        }
        r => r,
    }
}

/// One link attempt with its own retries: displace a stale occupant on `EEXIST`, fall back to a
/// symlink when the source cannot be linked from at all.
fn attach(source: &Path, dir_fd: &OwnedFd, name: &str, fs_path: &Path) -> io::Result<()> {
    match fsops::link_at(source, dir_fd, name) {
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
            fsops::remove_at(dir_fd, name, &fs_path.join(name))?;
            fsops::link_at(source, dir_fd, name)
        }
        Err(e) if e.kind() == io::ErrorKind::Unsupported => {
            let target = source.to_string_lossy().into_owned();
            match fsops::symlink_at(&target, dir_fd, name) {
                Err(e2) if e2.kind() == io::ErrorKind::AlreadyExists => {
                    fsops::remove_at(dir_fd, name, &fs_path.join(name))?;
                    fsops::symlink_at(&target, dir_fd, name)
                }
                r => r,
            }
        }
        r => r,
    }
}

/// The host directory backing a subtree the manifest did not enumerate. `host_path` is a fact;
/// `speculative_host_path` is a guess the tree layer deliberately keeps separate so it cannot skip
/// a content check, so both are verified before use.
fn mirror_source(d: &Dir) -> Option<&str> {
    [d.host_path.as_str(), d.speculative_host_path.as_str()]
        .into_iter()
        .find(|c| !c.is_empty() && fsops::has_real_content(Path::new(c)))
}

/// Link a host directory's contents into the slot, for a subtree the manifest describes only by
/// its host location — a tree artifact, a source directory, or a runfiles directory that collapsed
/// to the empty digest.
fn mirror_host(host: &Path, dir_fd: &OwnedFd, fs_path: &Path) -> io::Result<()> {
    for entry in std::fs::read_dir(host)?.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        let src = entry.path();
        let ft = entry.file_type()?;
        if ft.is_dir() {
            fsops::mkdir_at(dir_fd, name)?;
            let child = fs_path.join(name);
            let child_fd = fsops::open_dir(&child)?;
            mirror_host(&src, &child_fd, &child)?;
        } else if ft.is_symlink() {
            let target = std::fs::read_link(&src)?;
            let _ = fsops::symlink_at(&target.to_string_lossy(), dir_fd, name);
        } else {
            attach(&src, dir_fd, name, fs_path)?;
        }
    }
    Ok(())
}

/// Diff `old` into `new` at `fs_path`, which is the slot root.
pub fn reconcile(old: Option<&Dir>, new: &Dir, fs_path: &Path, cx: &Context) -> io::Result<()> {
    fsops::mkdir_p(fs_path)?;
    reconcile_dir(old, new, fs_path, None, "", "", false, cx)
}

/// Reconcile one directory.
///
/// `parent_fd` and `name` anchor it at its parent's fd, so creating it resolves one path component
/// instead of re-walking the whole slot path; `None` is the slot root.
///
/// `known_absent` means the caller has proven `fs_path` is either missing or an empty directory it
/// just made — every defensive "clear whatever might be here" below is then a known no-op and is
/// skipped. It propagates: a child of a known-absent directory is itself known-absent, and so is a
/// child that came from an old manifest, because there disk and manifest agree.
#[allow(clippy::too_many_arguments)]
fn reconcile_dir(
    old: Option<&Dir>,
    new: &Dir,
    fs_path: &Path,
    parent_fd: Option<&OwnedFd>,
    name: &str,
    rel: &str,
    known_absent: bool,
    cx: &Context,
) -> io::Result<()> {
    match parent_fd {
        Some(pfd) => match fsops::mkdir_at(pfd, name) {
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                fsops::remove(fs_path)?; // a non-directory occupant this tree never recorded
                fsops::mkdir_at(pfd, name)?;
            }
            r => r?,
        },
        None => fsops::mkdir_p(fs_path)?,
    }
    let dir_fd = fsops::open_dir(fs_path)?;

    let (of, os, od) = match old {
        Some(o) => (
            o.files.iter().map(|f| (f.name.as_str(), f)).collect::<HashMap<_, _>>(),
            o.symlinks.iter().map(|s| (s.name.as_str(), s)).collect::<HashMap<_, _>>(),
            o.directories.iter().map(|d| (d.name.as_str(), d)).collect::<HashMap<_, _>>(),
        ),
        None => (HashMap::new(), HashMap::new(), HashMap::new()),
    };

    let is_mirrored_leaf_dir = new.files.is_empty()
        && new.directories.is_empty()
        && new.symlinks.is_empty()
        && mirror_source(new).is_some();
    if is_mirrored_leaf_dir {
        // Described only by where it lives on the host. Mirror it, but never over content that is
        // already here: an ancestor may have placed the real thing already.
        if let Some(host) = mirror_source(new) {
            if !fsops::has_real_content(fs_path) {
                mirror_host(Path::new(host), &dir_fd, fs_path)?;
            }
        }
    }

    let mut keep: HashSet<&str> = HashSet::new();

    for f in new.files.iter() {
        keep.insert(&f.name);
        let existed = of.get(f.name.as_str());
        if let Some(o) = existed {
            if !f.digest.is_empty() && o.digest == f.digest {
                if !cx.heal_untracked || fsops::is_regular_file_at(&dir_fd, &f.name) {
                    continue; // unchanged — leave the existing link, and its warm vnode, alone
                }
                REPAIRED_FILES.fetch_add(1, Ordering::Relaxed);
            }
        }
        if existed.is_some() {
            fsops::remove_at(&dir_fd, &f.name, &fs_path.join(&f.name))?;
        }
        place_file(f, rel, &dir_fd, fs_path, cx)?;
    }

    for s in new.symlinks.iter() {
        keep.insert(&s.name);
        if os.get(s.name.as_str()).is_some_and(|o| o.target == s.target) {
            continue;
        }
        if !known_absent {
            fsops::remove_at(&dir_fd, &s.name, &fs_path.join(&s.name))?;
        }
        match fsops::symlink_at(&s.target, &dir_fd, &s.name) {
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                let target = fs_path.join(&s.name);
                if std::fs::read_link(&target).ok().as_deref() != Some(Path::new(&s.target)) {
                    fsops::remove_at(&dir_fd, &s.name, &target)?;
                    fsops::symlink_at(&s.target, &dir_fd, &s.name)?;
                }
            }
            r => r?,
        }
    }

    // A child is provably absent if this directory is known-absent, or if it came from the old
    // manifest, where disk matches the listing.
    let child_fresh = known_absent || old.is_some();
    for nd in new.directories.iter() {
        keep.insert(&nd.name);
        let target = fs_path.join(&nd.name);
        let child_rel = join_rel(rel, &nd.name);
        match od.get(nd.name.as_str()) {
            Some(o) => {
                if !nd.digest.is_empty()
                    && nd.digest != EMPTY_DIRECTORY_DIGEST
                    && o.digest == nd.digest
                    && (!cx.heal_untracked || target.is_dir())
                {
                    SKIPPED_SUBTREES.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
                reconcile_dir(
                    Some(o),
                    nd,
                    &target,
                    Some(&dir_fd),
                    &nd.name,
                    &child_rel,
                    false,
                    cx,
                )?;
            }
            None => {
                // An entry that describes nothing — no children, no host — cannot be rebuilt
                // "from" itself. If content is already here, placed by an ancestor's mirror, that
                // IS the content, and starting over would replace it with nothing.
                let uninformative = nd.files.is_empty()
                    && nd.directories.is_empty()
                    && nd.symlinks.is_empty()
                    && mirror_source(nd).is_none();
                if uninformative && fsops::has_real_content(&target) {
                    continue;
                }
                reconcile_dir(
                    None,
                    nd,
                    &target,
                    Some(&dir_fd),
                    &nd.name,
                    &child_rel,
                    child_fresh,
                    cx,
                )?;
            }
        }
    }

    for name in of.keys().chain(os.keys()).chain(od.keys()) {
        if !keep.contains(name) {
            REMOVED_ENTRIES.fetch_add(1, Ordering::Relaxed);
            fsops::remove_at(&dir_fd, name, &fs_path.join(name))?;
        }
    }

    // Self-heal any undeclared scratch files left behind in a warm directory by a prior action.
    if cx.heal_untracked && old.is_some() && !is_mirrored_leaf_dir {
        if let Ok(entries) = std::fs::read_dir(fs_path) {
            for entry in entries.flatten() {
                if let Some(ename) = entry.file_name().to_str() {
                    if !keep.contains(ename) {
                        REMOVED_ENTRIES.fetch_add(1, Ordering::Relaxed);
                        let _ = fsops::remove_at(&dir_fd, ename, &fs_path.join(ename));
                    }
                }
            }
        }
    }
    Ok(())
}

/// Join a sandbox path under `root`, trimming any leading `/` so an absolute sandbox path
/// (`writable_dirs` commonly uses `/tmp`) stays inside the slot instead of escaping to the host —
/// `Path::join` discards the base on an absolute argument.
fn join_under(root: &Path, sandbox_path: &str) -> PathBuf {
    root.join(sandbox_path.trim_start_matches('/'))
}

/// Remove the previous occupant's projected output scratch. MUST run BEFORE `reconcile`: a path
/// that was a prior action's output can be the new action's input (a generated file consumed
/// downstream), and reconcile re-materializes it — so clearing afterwards would delete the freshly
/// placed input.
pub fn clear_outputs(
    outputs: &BTreeMap<String, String>,
    writable_dirs: &BTreeMap<String, String>,
    fs_root: &Path,
) -> io::Result<()> {
    for p in outputs.keys().chain(writable_dirs.keys()) {
        fsops::remove(&join_under(fs_root, p))?;
    }
    Ok(())
}

/// Make the new action's writable output scratch, after `reconcile`. A `"dir"` output needs the
/// directory itself, since tools chdir into it; a file output needs only its parent, because the
/// action creates the leaf.
pub fn prepare_outputs(
    outputs: &BTreeMap<String, String>,
    writable_dirs: &BTreeMap<String, String>,
    fs_root: &Path,
) -> io::Result<()> {
    // Outputs arrive sorted, so siblings are adjacent: prepare each parent once instead of walking
    // every component per output.
    let mut ready_parent: Option<PathBuf> = None;
    for (p, kind) in outputs {
        let target = join_under(fs_root, p);
        if kind == "dir" {
            fsops::remove(&target)?;
            fsops::mkdir_p(&target)?;
        } else {
            if let Some(parent) = target.parent() {
                if ready_parent.as_deref() != Some(parent) {
                    fsops::mkdir_p(parent)?;
                    ready_parent = Some(parent.to_path_buf());
                }
            }
            // A reused slot can hold this exact path as a stale 0555 leaf: Bazel marks action
            // outputs read-only, so an earlier occupant's copy survives here and the action's
            // open-for-write is denied. A writable parent only lets us unlink it, not overwrite in
            // place, so clear the leaf.
            fsops::remove(&target)?;
        }
    }
    for p in writable_dirs.keys() {
        let target = join_under(fs_root, p);
        fsops::remove(&target)?;
        fsops::mkdir_p(&target)?;
    }
    Ok(())
}

/// Harvest a successful action's declared outputs out of the slot to their place under `exec_root`
/// — a rename, same volume. `outputs` keys are the sandbox-relative paths the action wrote to;
/// `slot_root` and `exec_root` are both anchored at the directory containing the workspace, so the
/// same key joins under each. Under path mapping the key is the MAPPED path and `dests` holds the
/// unmapped destination Bazel expects. Outputs the action did not produce are skipped — the
/// runner's own existence check reports those.
pub fn collect_outputs(
    outputs: &BTreeMap<String, String>,
    dests: &BTreeMap<String, String>,
    slot_root: &Path,
    exec_root: &Path,
) -> io::Result<()> {
    let mut ready_parent: Option<PathBuf> = None;
    for key in outputs.keys() {
        let src = join_under(slot_root, key);
        if src.symlink_metadata().is_err() {
            continue;
        }
        let dst = join_under(exec_root, dests.get(key).map(String::as_str).unwrap_or(key));
        if let Some(parent) = dst.parent() {
            if ready_parent.as_deref() != Some(parent) {
                fsops::mkdir_p(parent)?;
                ready_parent = Some(parent.to_path_buf());
            }
        }
        // rename(2) replaces a plain-file (or empty-dir) destination on its own; only a populated
        // directory or a type mismatch needs clearing, so try the one syscall first.
        if std::fs::rename(&src, &dst).is_err() {
            fsops::remove(&dst)?;
            std::fs::rename(&src, &dst)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use backend::tree::Symlink;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use std::sync::Arc;

    fn ino(p: &Path) -> u64 {
        std::fs::symlink_metadata(p).unwrap().ino()
    }

    fn tmp(tag: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!(
            "hlmorph-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    /// A host file plus the `File` node that names it through the exec-root derivation.
    fn host_file(exec_root: &Path, rel: &str, body: &[u8], exec: bool) -> File {
        let p = exec_root.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(&p, body).unwrap();
        std::fs::set_permissions(
            &p,
            std::fs::Permissions::from_mode(if exec { 0o755 } else { 0o644 }),
        )
        .unwrap();
        File {
            name: Path::new(rel).file_name().unwrap().to_string_lossy().into_owned(),
            digest: format!("d{}", body.len()),
            host_path: String::new(),
            size: body.len() as u64,
            executable: exec,
            from_verified_host: false,
        }
    }

    struct Fixture {
        base: PathBuf,
        exec_root: PathBuf,
        slot: PathBuf,
        links: LinkStore,
    }

    impl Fixture {
        fn new(tag: &str) -> Fixture {
            let base = tmp(tag);
            let exec_root = base.join("exec");
            let slot = base.join("slot");
            std::fs::create_dir_all(&exec_root).unwrap();
            let links = LinkStore::new(base.join("links")).unwrap();
            Fixture { base, exec_root, slot, links }
        }

        fn morph(&self, old: Option<&Dir>, new: &Dir) -> Vec<String> {
            let missing = Missing::default();
            let er = self.exec_root.to_string_lossy().into_owned();
            let cx = Context {
                exec_root: &er,
                links: &self.links,
                missing: &missing,
                empty_file: None,
                verified_mode: false,
                cas_root: None,
                heal_untracked: false,
            };
            reconcile(old, new, &self.slot, &cx).unwrap();
            missing.take()
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.base);
        }
    }

    /// The diff thesis: a leaf whose digest did not change keeps its inode across a second morph.
    #[test]
    fn unchanged_digest_keeps_its_inode() {
        let f = Fixture::new("unchanged");
        let a = host_file(&f.exec_root, "pkg/a.txt", b"aaa", false);
        let nested = Dir {
            name: "pkg".into(),
            digest: "dp".into(),
            files: Arc::new(vec![a.clone()]),
            ..Default::default()
        };
        let root = Dir { directories: Arc::new(vec![nested]), ..Default::default() };

        f.morph(None, &root);
        let placed = f.slot.join("pkg/a.txt");
        let first = ino(&placed);
        assert_eq!(first, ino(&f.exec_root.join("pkg/a.txt")), "a placed leaf IS the host inode");

        f.morph(Some(&root), &root);
        assert_eq!(ino(&placed), first, "an unchanged digest must not be re-placed");
    }

    /// A changed digest is replaced, and a leaf the new tree drops is removed.
    #[test]
    fn changed_digest_replaced_and_dropped_leaf_removed() {
        let f = Fixture::new("changed");
        let a = host_file(&f.exec_root, "a.txt", b"aaa", false);
        let b = host_file(&f.exec_root, "b.txt", b"bbbb", false);
        let old = Dir { files: Arc::new(vec![a.clone(), b]), ..Default::default() };
        f.morph(None, &old);
        assert!(f.slot.join("b.txt").exists());

        // Same name, new content: a fresh host inode under the same derivation.
        std::fs::write(f.exec_root.join("a.txt"), b"aaaaa").unwrap();
        let a2 = File { digest: "d5".into(), size: 5, ..a };
        let new = Dir { files: Arc::new(vec![a2]), ..Default::default() };
        f.morph(Some(&old), &new);

        assert_eq!(ino(&f.slot.join("a.txt")), ino(&f.exec_root.join("a.txt")));
        assert!(!f.slot.join("b.txt").exists(), "a leaf absent from the new tree is removed");
    }

    /// The mode problem: an executable whose host blob lacks `+x` gets a copy we own, at 0555, and
    /// the host is left exactly as it was.
    #[test]
    fn executable_without_host_exec_bit_gets_a_mode_corrected_copy() {
        let f = Fixture::new("mode");
        let mut leaf = host_file(&f.exec_root, "tool", b"#!/bin/sh\n", true);
        let host = f.exec_root.join("tool");
        std::fs::set_permissions(&host, std::fs::Permissions::from_mode(0o644)).unwrap();
        leaf.executable = true;

        let root = Dir { files: Arc::new(vec![leaf]), ..Default::default() };
        f.morph(None, &root);

        let placed = f.slot.join("tool");
        assert_eq!(std::fs::metadata(&placed).unwrap().permissions().mode() & 0o777, 0o555);
        assert_ne!(
            ino(&placed),
            ino(&host),
            "must not share the host inode, or chmod would have hit it"
        );
        assert_eq!(
            std::fs::metadata(&host).unwrap().permissions().mode() & 0o777,
            0o644,
            "the host file is left untouched"
        );
        assert_eq!(std::fs::read(&placed).unwrap(), b"#!/bin/sh\n");
    }

    /// An executable whose host already carries `+x` links, and stays one inode with the host.
    #[test]
    fn executable_with_host_exec_bit_links() {
        let f = Fixture::new("modeok");
        let leaf = host_file(&f.exec_root, "tool", b"#!/bin/sh\n", true);
        let root = Dir { files: Arc::new(vec![leaf]), ..Default::default() };
        f.morph(None, &root);
        assert_eq!(ino(&f.slot.join("tool")), ino(&f.exec_root.join("tool")));
    }

    /// A stale occupant the old tree never recorded is displaced rather than tripping EEXIST.
    #[test]
    fn stale_leftover_is_displaced() {
        let f = Fixture::new("stale");
        let a = host_file(&f.exec_root, "a.txt", b"aaa", false);
        fsops::mkdir_p(&f.slot).unwrap();
        std::fs::write(f.slot.join("a.txt"), b"garbage").unwrap();

        let root = Dir { files: Arc::new(vec![a]), ..Default::default() };
        f.morph(None, &root);
        assert_eq!(std::fs::read(f.slot.join("a.txt")).unwrap(), b"aaa");
    }

    /// A symlink node is materialized as a symlink, and a retarget replaces it.
    #[test]
    fn symlink_written_and_retargeted() {
        let f = Fixture::new("symlink");
        let old = Dir {
            symlinks: Arc::new(vec![Symlink { name: "s".into(), target: "one".into() }]),
            ..Default::default()
        };
        f.morph(None, &old);
        assert_eq!(std::fs::read_link(f.slot.join("s")).unwrap().to_str(), Some("one"));

        let new = Dir {
            symlinks: Arc::new(vec![Symlink { name: "s".into(), target: "two".into() }]),
            ..Default::default()
        };
        f.morph(Some(&old), &new);
        assert_eq!(std::fs::read_link(f.slot.join("s")).unwrap().to_str(), Some("two"));
    }

    /// A leaf with no host anywhere comes back as a digest to ask Bazel for, not an error.
    #[test]
    fn unsourceable_leaf_is_reported_missing() {
        let f = Fixture::new("missing");
        let ghost =
            File { name: "ghost".into(), digest: "dead".into(), size: 3, ..Default::default() };
        let root = Dir { files: Arc::new(vec![ghost]), ..Default::default() };
        assert_eq!(f.morph(None, &root), vec!["dead".to_string()]);
    }

    /// A directory the manifest describes only by its host location is mirrored, leaf by leaf,
    /// sharing inodes with the host.
    #[test]
    fn host_only_directory_is_mirrored() {
        let f = Fixture::new("mirror");
        let src = f.base.join("treeart");
        std::fs::create_dir_all(src.join("sub")).unwrap();
        std::fs::write(src.join("top.txt"), b"top").unwrap();
        std::fs::write(src.join("sub/deep.txt"), b"deep").unwrap();

        let art = Dir {
            name: "art".into(),
            digest: "dart".into(),
            host_path: src.to_string_lossy().into_owned(),
            ..Default::default()
        };
        let root = Dir { directories: Arc::new(vec![art]), ..Default::default() };
        f.morph(None, &root);

        assert_eq!(ino(&f.slot.join("art/top.txt")), ino(&src.join("top.txt")));
        assert_eq!(std::fs::read(f.slot.join("art/sub/deep.txt")).unwrap(), b"deep");
    }

    /// An entry describing nothing must not erase content an ancestor's mirror already placed.
    #[test]
    fn uninformative_child_over_real_content_is_left_alone() {
        let f = Fixture::new("uninformative");
        fsops::mkdir_p(&f.slot.join("d")).unwrap();
        std::fs::write(f.slot.join("d/kept.txt"), b"real").unwrap();

        let empty_child = Dir { name: "d".into(), digest: String::new(), ..Default::default() };
        let root = Dir { directories: Arc::new(vec![empty_child]), ..Default::default() };
        f.morph(None, &root);
        assert_eq!(std::fs::read(f.slot.join("d/kept.txt")).unwrap(), b"real");
    }

    /// `prepare_outputs` must clear a stale read-only output leaf a reused slot left behind.
    #[test]
    fn prepare_outputs_clears_a_stale_readonly_leaf() {
        let f = Fixture::new("outputs");
        let leaf = f.slot.join("_main/bazel-out/x/out.o");
        fsops::mkdir_p(leaf.parent().unwrap()).unwrap();
        std::fs::write(&leaf, b"stale").unwrap();
        fsops::set_mode(&leaf, 0o555).unwrap();

        let outputs =
            BTreeMap::from([("/_main/bazel-out/x/out.o".to_string(), "file".to_string())]);
        let writable = BTreeMap::from([("/tmp".to_string(), String::new())]);
        prepare_outputs(&outputs, &writable, &f.slot).unwrap();

        assert!(
            !leaf.exists(),
            "a stale read-only leaf must be unlinked, not left to fail the action"
        );
        assert!(leaf.parent().unwrap().is_dir());
        assert!(f.slot.join("tmp").is_dir(), "an absolute writable dir stays inside the slot");
    }

    /// `collect_outputs` honors a path-mapped destination and skips what the action did not write.
    #[test]
    fn collect_honors_dests_and_skips_unproduced() {
        let f = Fixture::new("collect");
        let produced = f.slot.join("_main/bazel-out/cfg/lib.a");
        fsops::mkdir_p(produced.parent().unwrap()).unwrap();
        std::fs::write(&produced, b"archive").unwrap();

        let outputs = BTreeMap::from([
            ("/_main/bazel-out/cfg/lib.a".to_string(), "file".to_string()),
            ("/_main/bazel-out/cfg/never.a".to_string(), "file".to_string()),
        ]);
        let dests = BTreeMap::from([(
            "/_main/bazel-out/cfg/lib.a".to_string(),
            "/_main/bazel-out/unmapped/lib.a".to_string(),
        )]);
        let dest_root = f.base.join("out");
        collect_outputs(&outputs, &dests, &f.slot, &dest_root).unwrap();

        assert_eq!(
            std::fs::read(dest_root.join("_main/bazel-out/unmapped/lib.a")).unwrap(),
            b"archive"
        );
        assert!(!produced.exists(), "collect moves, it does not copy");
    }
}
