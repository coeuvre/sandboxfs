// The protocol every sandbox projection backend is driven through: the wire codec, the session
// blob store, shared instrumentation, and the trait the daemon dispatches on.

pub mod blobstore;
pub mod manifest;
pub mod proto;
pub mod tree;
pub mod wire;

pub use blobstore::{BlobStore, VerifiedLocation};
pub use manifest::{Manifest, Outputs};
pub use proto::ContentSource;

use std::io;
use std::path::{Path, PathBuf};

/// Why a `create` did not return a sandbox path. `MissingContent` asks for more input -- Bazel
/// pushes the named digests and re-sends the create, so the action still runs. `Failed` fails it.
#[derive(Debug)]
pub enum CreateError {
    /// Every digest the store lacked, not just the first: Bazel pushes the list in one round trip.
    MissingContent(Vec<String>),
    Failed(io::Error),
}

impl From<io::Error> for CreateError {
    fn from(e: io::Error) -> CreateError {
        CreateError::Failed(e)
    }
}

/// The backend args Bazel relays in the `Negotiate` handshake
/// (`--sandbox_backend_opt=<name>=<opt>`), parsed once and handed to `Backend::start`.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct Options {
    /// `pool_root=<path>`: where to put the pool, for when the default is not on the workspace's
    /// volume. Projection and `collect`'s rename are same-device-only.
    pub pool_root: Option<PathBuf>,
    /// `metrics`: arm kdebug attribution for this workspace.
    pub metrics: bool,
    /// `linux_sandbox=<path>`: optional path to Bazel's `linux-sandbox` helper binary for hermetic
    /// mount/network/inaccessible-path confinement inside projected slots on Linux.
    pub linux_sandbox: Option<PathBuf>,
    /// `cas_root=<path>`: shared local CAS directory (`<disk_cache>/[<digest_fn>/]cas`) using
    /// Bazel's `DiskCacheClient` `<cas_root>/<hash[0..2]>/<hash>` layout.
    pub cas_root: Option<PathBuf>,
    /// `disk_cache=<path>`: shared local `--disk_cache` root directory.
    pub disk_cache: Option<PathBuf>,
}

impl Options {
    pub fn parse(args: &[String]) -> Result<Options, String> {
        let mut options = Options::default();
        for arg in args {
            match arg.split_once('=').unwrap_or((arg, "")) {
                ("pool_root", path) | ("pool-root", path) if !path.is_empty() => options.pool_root = Some(PathBuf::from(path)),
                ("linux_sandbox", path) | ("linux-sandbox", path) if !path.is_empty() => options.linux_sandbox = Some(PathBuf::from(path)),
                ("cas_root", path) | ("cas-root", path) if !path.is_empty() => options.cas_root = Some(PathBuf::from(path)),
                ("disk_cache", path) | ("disk-cache", path) if !path.is_empty() => options.disk_cache = Some(PathBuf::from(path)),
                ("metrics", "") => options.metrics = true,
                _ => return Err(format!("unknown sandbox option {arg:?} (expected: pool_root=<path>, linux_sandbox=<path>, cas_root=<path>, disk_cache=<path>, metrics)")),
            }
        }
        Ok(options)
    }

    /// Parses CLI `--experimental_sandbox_backend_opt` flags passed to `sandboxfs serve
    /// --socket=...`.
    pub fn parse_cli(args: &[String]) -> Options {
        let mut options = Options::default();
        let mut i = 0;
        while i < args.len() {
            let raw = args[i].trim_start_matches('-');
            if let Some((k, v)) = raw.split_once('=') {
                match k {
                    "pool_root" | "pool-root" if !v.is_empty() => {
                        options.pool_root = Some(PathBuf::from(v))
                    }
                    "linux_sandbox" | "linux-sandbox" if !v.is_empty() => {
                        options.linux_sandbox = Some(PathBuf::from(v))
                    }
                    "cas_root" | "cas-root" if !v.is_empty() => {
                        options.cas_root = Some(PathBuf::from(v))
                    }
                    "disk_cache" | "disk-cache" if !v.is_empty() => {
                        options.disk_cache = Some(PathBuf::from(v))
                    }
                    "metrics" => options.metrics = v.is_empty() || v == "1" || v == "true",
                    _ => {}
                }
            } else {
                match raw {
                    "metrics" => options.metrics = true,
                    "pool_root" | "pool-root" if i + 1 < args.len() => {
                        options.pool_root = Some(PathBuf::from(&args[i + 1]));
                        i += 1;
                    }
                    "linux_sandbox" | "linux-sandbox" if i + 1 < args.len() => {
                        options.linux_sandbox = Some(PathBuf::from(&args[i + 1]));
                        i += 1;
                    }
                    "cas_root" | "cas-root" if i + 1 < args.len() => {
                        options.cas_root = Some(PathBuf::from(&args[i + 1]));
                        i += 1;
                    }
                    "disk_cache" | "disk-cache" if i + 1 < args.len() => {
                        options.disk_cache = Some(PathBuf::from(&args[i + 1]));
                        i += 1;
                    }
                    _ => {}
                }
            }
            i += 1;
        }
        options
    }
}

/// One way of projecting an action's input tree onto a real filesystem path. The daemon owns the
/// protocol and calls in here for the projection itself.
///
/// A cross-repository interface: the shipping backend is built from its own repository against this
/// crate, so a signature change here is a coordinated change in both.
///
/// `start` runs first, before anything else here. `create`, `collect` and `destroy` then run
/// concurrently on the worker pool, never twice for one `sandbox_id` at once; `push` runs on the
/// reader thread instead.
pub trait Backend: Send + Sync {
    /// Also the namespace a backend keys its on-disk state by, so one workspace built under two
    /// backends keys to two subtrees and neither adopts the other's.
    fn name(&self) -> &'static str;

    /// The root every path this backend materializes lives under. The daemon attributes filesystem
    /// activity by matching against it, so it has to cover the projection and reach no further.
    /// Same device as the workspace, stable for the backend's lifetime.
    fn mount_path(&self) -> &Path;

    /// The first call on this seam: the handshake has landed and nothing is in flight yet, which is
    /// what makes it the place for background reapers and global latches.
    fn start(&self, _options: &Options) {}

    /// Project one action's input tree and return the path Bazel runs it in. Returning a path also
    /// declares the sandbox unconfined: the projected view IS the confinement, and a Seatbelt jail
    /// on top would deny the action its own `$TMPDIR`.
    ///
    /// `manifest` carries no tree, and decodes lazily, so a backend that recognizes a tree it
    /// already has on disk decides from a byte scan. Resolving the tree is the separate, expensive
    /// step -- `tree::resolve(manifest.input_root_digest(), .., store)` -- and the only one that can
    /// report `MissingContent`.
    fn create(&self, sandbox_id: &str, manifest: &Manifest<'_>, store: &BlobStore) -> Result<String, CreateError>;

    /// Move the declared outputs out to `exec_root`, after the action exits and before `destroy`.
    /// An unproduced output is a skip; anything reported here fails the action.
    fn collect(&self, sandbox_id: &str, exec_root: &str) -> io::Result<()>;

    /// Release the sandbox. Infallible by contract, and never guaranteed to arrive at all, so keep
    /// slow or failure-prone teardown off it.
    fn destroy(&self, sandbox_id: &str);

    /// `digests` just landed, ahead of the creates that reference them.
    ///
    /// Take leaf content with `store.take_content` and capture it NOW -- a location is a path we
    /// may only read during this call -- then record it with `store.insert_captured`. Directory
    /// blobs are the pre-staging window, purely advisory. Runs on the reader thread and blocks the
    /// next frame.
    fn push(&self, _store: &BlobStore, _digests: &[String]) {}
}

#[cfg(test)]
mod options_tests {
    use super::*;

    fn parse(args: &[&str]) -> Result<Options, String> {
        Options::parse(&args.iter().map(|s| s.to_string()).collect::<Vec<_>>())
    }

    #[test]
    fn bare_names_parse() {
        let o = parse(&["metrics", "pool_root=/tmp/pool"]).unwrap();
        assert_eq!(
            o,
            Options {
                pool_root: Some(PathBuf::from("/tmp/pool")),
                metrics: true,
                linux_sandbox: None,
                cas_root: None,
                disk_cache: None,
            }
        );
    }

    #[test]
    fn unknown_and_malformed_options_fail() {
        assert!(parse(&["--metrics"]).is_err());
        assert!(parse(&["metrics=1"]).is_err());
        assert!(parse(&["pool_root"]).is_err());
        assert!(parse(&["bogus"]).is_err());
    }
}
