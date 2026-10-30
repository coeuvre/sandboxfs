use backend::proto::{
    self, ContentSource, CreateReply, NegotiateReply, Reply, Request, Response, Status,
};
use backend::{Backend, BlobStore, CreateError, Manifest, Options};
pub mod grpc;
pub mod reapi;
pub mod stats;

use std::collections::VecDeque;
use std::io::{self, Read, Write};
use std::path::Path;
use std::sync::{Arc, Condvar, Mutex};
use std::thread;

fn main() {
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        Some("serve") => {
            let rest: Vec<String> = args.collect();
            let workspace = flag(&rest, "--workspace")
                .or_else(|| std::env::current_dir().ok().map(|p| p.to_string_lossy().into_owned()))
                .unwrap_or_else(|| ".".into());
            let backend_flag = flag(&rest, "--backend");
            if let Some(socket) = flag(&rest, "--socket") {
                serve_reapi(&socket, &workspace, backend_flag.as_deref(), &rest);
            } else {
                serve(&workspace, backend_flag.as_deref());
            }
        }
        // The metrics daemon (root LaunchDaemon) owns kdebug only between begin/end.
        #[cfg(target_os = "macos")]
        Some("metricsd") => metrics::run_daemon(),
        #[cfg(target_os = "macos")]
        Some("metrics") => {
            let method = args.next().unwrap_or_default();
            let build_id = args.next().unwrap_or_default();
            // Optional explicit prefix (for `begin`, mainly manual testing); the controller
            // always supplies the backend's prefix via the gate.
            let prefix = args.next();
            let needs_id = matches!(method.as_str(), "begin" | "end");
            if !(needs_id || matches!(method.as_str(), "feed" | "clear"))
                || (needs_id && build_id.is_empty())
            {
                eprintln!("usage: sandboxfs metrics <begin|end> <build_id> [prefix]");
                eprintln!("       sandboxfs metrics feed [since_ms]   (dump the JSON feed)");
                eprintln!("       sandboxfs metrics clear             (drop retained history)");
                std::process::exit(2);
            }
            // `feed` takes an optional since cursor in the build_id slot (manual debug).
            let payload = if method == "feed" { build_id.clone() } else { String::new() };
            let prefix = prefix.unwrap_or_default(); // only `begin` uses it; the controller supplies the real one
            match metrics::client(&method, &build_id, &prefix, &payload) {
                Ok(Some(json)) => println!("{json}"),
                Ok(None) => {}
                Err(e) => {
                    eprintln!("sandboxfs metrics: {e}");
                    std::process::exit(1);
                }
            }
        }
        _ => {
            eprintln!("usage: sandboxfs serve [--socket=<path>] [--workspace <path>] [--backend cfs|fskit|hardlink] [options...]");
            eprintln!("       sandboxfs metrics <begin|end> <build_id>   (read: sandboxfs metrics feed)");
            eprintln!("       backend also settable via env sandboxfs_backend (Bazel: --client_env=sandboxfs_backend=fskit)");
            std::process::exit(2);
        }
    }
}

fn flag(args: &[String], name: &str) -> Option<String> {
    let prefix = format!("{name}=");
    for (i, a) in args.iter().enumerate() {
        if let Some(val) = a.strip_prefix(&prefix) {
            return Some(val.to_string());
        }
        if a == name {
            return args.get(i + 1).cloned();
        }
    }
    None
}

/// Extract backend options from CLI arguments (`--pool_root=...`, `--linux_sandbox=...`, etc.)
fn parse_cli_options(args: &[String]) -> io::Result<Options> {
    let mut raw_opts = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        if a.starts_with("--socket=")
            || a.starts_with("--workspace=")
            || a.starts_with("--backend=")
        {
            i += 1;
            continue;
        }
        if a == "--socket" || a == "--workspace" || a == "--backend" {
            i += 2;
            continue;
        }
        let trimmed = a.strip_prefix("--").unwrap_or(a);
        if trimmed.contains('=') || trimmed == "metrics" || trimmed == "verified" {
            raw_opts.push(trimmed.to_string());
            i += 1;
        } else if (trimmed == "pool_root"
            || trimmed == "pool-root"
            || trimmed == "linux_sandbox"
            || trimmed == "linux-sandbox"
            || trimmed == "cas_root"
            || trimmed == "cas-root"
            || trimmed == "disk_cache"
            || trimmed == "disk-cache")
            && i + 1 < args.len()
        {
            raw_opts.push(format!("{trimmed}={}", args[i + 1]));
            i += 2;
        } else {
            i += 1;
        }
    }
    Options::parse(&raw_opts).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))
}

/// Which backend to use. `--backend` flag wins, else the env knob, else the default.
/// Case-insensitive.
fn resolve(flag: Option<&str>, env: Option<&str>) -> io::Result<&'static str> {
    match flag.or(env).map(|s| s.to_ascii_lowercase()).as_deref() {
        None => {
            #[cfg(target_os = "macos")]
            {
                Ok("cfs")
            }
            #[cfg(not(target_os = "macos"))]
            {
                Ok("hardlink")
            }
        }
        Some("cfs") => Ok("cfs"),
        Some("fskit") => Ok("fskit"),
        Some("hardlink") => Ok("hardlink"),
        Some(other) => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("unknown backend {other:?} (expected: cfs, fskit, hardlink)"),
        )),
    }
}

/// Build the projection backend. This is the whole of the daemon's knowledge of any particular
/// backend -- one call to get a `dyn Backend`; everything after it goes through the trait. Where
/// its state lives on disk, and whether that placement is legal, is the backend's own business.
fn select_with_hardlink(
    flag: Option<&str>,
    workspace: &str,
    options: &Options,
) -> io::Result<(Arc<dyn Backend>, Option<Arc<backend_hardlink::Hardlink>>)> {
    let env =
        std::env::var("sandboxfs_backend").or_else(|_| std::env::var("SANDBOXFS_BACKEND")).ok();
    match resolve(flag, env.as_deref())? {
        "fskit" => Ok((backend_fskit::open(workspace, options)?, None)),
        "hardlink" => {
            let hl = backend_hardlink::open(workspace, options)?;
            let dyn_b: Arc<dyn Backend> = hl.clone();
            Ok((dyn_b, Some(hl)))
        }
        _ => Ok((backend_cfs::open(workspace, options)?, None)),
    }
}

fn select(flag: Option<&str>, workspace: &str, options: &Options) -> io::Result<Arc<dyn Backend>> {
    select_with_hardlink(flag, workspace, options).map(|(b, _)| b)
}

/// REAPI v2 daemon mode over Unix domain socket (`sandboxfs serve --socket=<path> [opts...]`),
/// spawned by Bazel's `SandboxBackendSpawnRunner`.
fn serve_reapi(socket: &str, workspace: &str, backend_name: Option<&str>, raw_args: &[String]) {
    unsafe { libc::signal(libc::SIGPIPE, libc::SIG_IGN) };

    let options = match parse_cli_options(raw_args) {
        Ok(o) => o,
        Err(e) => {
            eprintln!("sandboxfs: {e}");
            std::process::exit(1);
        }
    };
    let (backend, hardlink) =
        match select_with_hardlink(backend_name.or(Some("hardlink")), workspace, &options) {
            Ok(pair) => pair,
            Err(e) => {
                eprintln!("sandboxfs: cannot open backend: {e}");
                std::process::exit(1);
            }
        };
    backend.start(&options);
    let store = Arc::new(BlobStore::new());
    if let Some(ref cas_root) = options.cas_root {
        store.set_cas_root(cas_root.clone());
    } else if let Some(ref disk_cache) = options.disk_cache {
        store.set_cas_root(disk_cache.join("cas"));
    } else {
        store.enable_verified_mode();
    }
    let state = Arc::new(reapi::ReapiState::new(backend, hardlink, store, options));
    if let Err(e) = grpc::serve_unix(Path::new(socket), state) {
        eprintln!("sandboxfs: socket server error on {socket}: {e}");
        std::process::exit(1);
    }
}

/// Spawns the worker pool that drains `queue` and writes framed replies (rid echoed, so
/// out-of-order is fine). One worker per core is optimal: measured oversubscription (3x) added
/// concurrent-morph contention and was slightly slower, so creates aren't queue-bound.
/// CFS_WORKERS overrides for tuning.
fn spawn_workers(
    backend: Arc<dyn Backend>,
    queue: Arc<Queue>,
    out: Arc<Mutex<io::Stdout>>,
    store: Arc<BlobStore>,
) -> Vec<thread::JoinHandle<()>> {
    let cores = thread::available_parallelism().map(|n| n.get()).unwrap_or(4);
    let n = std::env::var("CFS_WORKERS").ok().and_then(|s| s.parse().ok()).unwrap_or(cores);
    (0..n)
        .map(|_| {
            let (backend, queue, out, store) =
                (backend.clone(), queue.clone(), out.clone(), store.clone());
            thread::spawn(move || {
                while let Some((req, queued_at)) = queue.pop() {
                    let wait = queued_at.elapsed();
                    let (timing, kind) = match &req {
                        Request::Create { .. } => (&stats::CREATE_T, 1u8),
                        Request::Collect { .. } => (&stats::COLLECT_T, 0u8),
                        Request::Destroy { .. } => (&stats::DESTROY_T, 2u8),
                        Request::Negotiate { .. } => {
                            unreachable!("negotiate is answered inline in serve(), before queueing")
                        }
                        Request::Push { .. } => {
                            unreachable!("push is applied inline in serve(), never queued")
                        }
                    };
                    // The action mnemonic rides on the Create manifest (field 16); peek just
                    // that field (no tree, no maps) so grouping stays off the create hot path.
                    let mnemonic = match &req {
                        Request::Create { manifest_bytes, .. } => {
                            Manifest::new(manifest_bytes).mnemonic().map(str::to_string)
                        }
                        _ => None,
                    };
                    stats::INFLIGHT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    let t0 = std::time::Instant::now();
                    let resp = handle(backend.as_ref(), req, &store);
                    let handle = t0.elapsed();
                    stats::INFLIGHT.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
                    // LIVE feeds the metrics gate's build-window detection.
                    match kind {
                        1 if matches!(resp.reply, Reply::Create(CreateReply::Ok { .. })) => {
                            stats::LIVE.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            stats::record_create(
                                mnemonic.as_deref().unwrap_or(""),
                                handle.as_nanos() as u64,
                            );
                        }
                        2 => {
                            stats::LIVE.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
                        }
                        _ => {}
                    }
                    let frame = frame(&proto::encode_response(&resp));
                    let t1 = std::time::Instant::now();
                    let mut o = out.lock().unwrap();
                    let werr = o.write_all(&frame).is_err() || o.flush().is_err();
                    drop(o);
                    timing.record(
                        wait.as_nanos() as u64,
                        handle.as_nanos() as u64,
                        t1.elapsed().as_nanos() as u64,
                    );
                    if werr {
                        break;
                    }
                }
            })
        })
        .collect()
}

/// The controller, spawned by Bazel: varint length-delimited proto on stdin/stdout. This thread
/// frames requests onto a queue; a pool of workers projects sandboxes and writes framed replies.
///
/// The backend is not built until the handshake arrives, since that is where its options come
/// from. Bazel always sends it first, so deferring costs nothing.
fn serve(workspace: &str, backend_name: Option<&str>) {
    unsafe { libc::signal(libc::SIGPIPE, libc::SIG_IGN) };

    let queue = Arc::new(Queue::new());
    let out = Arc::new(Mutex::new(io::stdout()));
    // Session-scoped content store for pushed directory blobs. Shared with the workers; Pushes are
    // applied here in the reader thread (below) before the next frame is read, so any Create framed
    // after a Push is guaranteed to see its blobs — the ordering invariant the no-ack Push relies on.
    let store = Arc::new(BlobStore::new());
    let mut metrics = MetricsGate::off();
    let mut workers: Vec<thread::JoinHandle<()>> = Vec::new();
    let mut backend_ref: Option<Arc<dyn Backend>> = None;

    let stdin = io::stdin();
    let mut r = stdin.lock();
    while let Some(len) = read_len(&mut r) {
        let mut body = vec![0u8; len as usize];
        if r.read_exact(&mut body).is_err() {
            break;
        }
        match proto::decode_request(&body) {
            // The one-time handshake, sent before any sandbox is created: answer inline rather
            // than through the worker queue/timing stats, which model only Create/Collect/Destroy.
            Some(Request::Negotiate { rid, versions, options }) => {
                let options = match Options::parse(&options) {
                    Ok(o) => o,
                    Err(e) => {
                        let frame = frame(&proto::encode_response(&negotiate_error(rid, &e)));
                        let mut o = out.lock().unwrap();
                        let _ = o.write_all(&frame).and_then(|_| o.flush());
                        eprintln!("sandboxfs: {e}");
                        std::process::exit(1);
                    }
                };
                let backend = match select(backend_name, workspace, &options) {
                    Ok(b) => b,
                    Err(e) => {
                        eprintln!("sandboxfs: cannot open backend: {e}");
                        std::process::exit(1);
                    }
                };
                backend.start(&options);
                metrics = MetricsGate::start(workspace, backend.clone(), &options);
                backend_ref = Some(backend.clone());
                workers = spawn_workers(backend, queue.clone(), out.clone(), store.clone());
                let frame = frame(&proto::encode_response(&negotiate(rid, &versions)));
                let mut o = out.lock().unwrap();
                if o.write_all(&frame).is_err() || o.flush().is_err() {
                    break;
                }
            }
            // Fire-and-forget, no reply: applied inline so it lands before the next frame is read
            // (the ordering invariant `store` above relies on).
            Some(Request::Push { blobs, content }) => {
                let mut digests: Vec<String> = blobs.iter().map(|(h, _)| h.clone()).collect();
                store.insert_dirs(blobs);
                digests.extend(content.iter().map(|(h, _)| h.clone()));
                store.stage_content(resolve_locations(&store, content));
                if let Some(b) = &backend_ref {
                    b.push(&store, &digests);
                }
                // Capture-on-receipt: whatever the backend did not take is not ours to read later.
                store.clear_pending();
            }
            // A Create is the only frame carrying the session exec root (field 2), and a relative
            // `Push.content` location means nothing without it. Latch it here, on the way to the
            // worker queue, so every later push resolves — the first push of a session precedes
            // any Create, and the leaves it could not resolve are recovered through the
            // MissingContent retry once a Create has been seen.
            Some(req) => {
                latch_exec_root(&store, &req);
                queue.push(req)
            }
            None => {
                eprintln!("sandboxfs: undecodable {len}-byte request frame; Bazel and this controller disagree on the sandbox protocol");
                std::process::exit(1);
            }
        }
    }
    queue.close();
    for w in workers {
        let _ = w.join();
    }
    metrics.finish();
}

/// Opt-in metrics, keyed by workspace. Bazel sends no build boundaries and keeps this controller
/// alive across builds, so a build is inferred from live-sandbox edges: running while `stats::LIVE`
/// is above zero, done once it has sat at zero for the idle grace. The controller drives begin/end
/// itself so the daemon learns its pid. Armed by `sandboxfs_metrics=1` or a `metrics` backend
/// arg.
struct MetricsGate {
    stop: Option<Arc<std::sync::atomic::AtomicBool>>,
    monitor: Option<thread::JoinHandle<()>>,
}

impl MetricsGate {
    #[cfg(target_os = "macos")]
    const POLL: std::time::Duration = std::time::Duration::from_millis(250);

    fn off() -> MetricsGate {
        MetricsGate { stop: None, monitor: None }
    }

    #[cfg(not(target_os = "macos"))]
    fn start(_workspace: &str, _backend: Arc<dyn Backend>, _options: &Options) -> MetricsGate {
        Self::off()
    }

    #[cfg(target_os = "macos")]
    fn start(workspace: &str, backend: Arc<dyn Backend>, options: &Options) -> MetricsGate {
        let env_enabled = std::env::var("sandboxfs_metrics").ok().as_deref() == Some("1");
        if !(env_enabled || options.metrics) {
            return Self::off();
        }
        let prefix = backend.mount_path().to_string_lossy().into_owned();
        // How long LIVE must stay 0 before a build is called done. Bridges inter-wave
        // lulls; tunable via `--client_env=sandboxfs_idle_s=<seconds>` (default 4).
        let idle = std::env::var("sandboxfs_idle_s")
            .ok()
            .and_then(|s| s.parse().ok())
            .map(std::time::Duration::from_secs)
            .unwrap_or(std::time::Duration::from_secs(4));
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let (ws, st) = (workspace.to_string(), stop.clone());
        let monitor = thread::spawn(move || Self::watch(ws, prefix, backend, idle, st));
        MetricsGate { stop: Some(stop), monitor: Some(monitor) }
    }

    #[cfg(target_os = "macos")]
    fn watch(
        workspace: String,
        prefix: String,
        backend: Arc<dyn Backend>,
        idle: std::time::Duration,
        stop: Arc<std::sync::atomic::AtomicBool>,
    ) {
        use std::sync::atomic::Ordering::{Acquire, Relaxed};
        let report = |ws: &str| {
            let _ = metrics::client("report", ws, "", &stats::report_text(backend.name()));
        };
        let mut open = false;
        let mut idle_since: Option<std::time::Instant> = None;
        let mut ticks: u32 = 0;
        while !stop.load(Acquire) {
            thread::sleep(Self::POLL);
            ticks = ticks.wrapping_add(1);
            let live = stats::LIVE.load(Relaxed) > 0;
            if live {
                idle_since = None;
                if !open {
                    match metrics::client("begin", &workspace, &prefix, "") {
                        Ok(_) => {
                            open = true;
                            report(&workspace); // seed the daemon with the controller's counters
                        }
                        Err(e) => eprintln!("sandboxfs: metrics begin failed: {e}"),
                    }
                }
            } else if open {
                let since = *idle_since.get_or_insert_with(std::time::Instant::now);
                if since.elapsed() >= idle {
                    report(&workspace); // final snapshot before the window closes
                    let _ = metrics::client("end", &workspace, "", "");
                    (open, idle_since) = (false, None);
                    continue;
                }
            }
            // refresh the daemon's view ~1s while a build runs (POLL is 250ms)
            if open && ticks % 4 == 0 {
                report(&workspace);
            }
        }
        if open {
            report(&workspace);
            let _ = metrics::client("end", &workspace, "", ""); // finalize in-flight build on shutdown
        }
    }

    fn finish(self) {
        if let Some(stop) = self.stop {
            stop.store(true, std::sync::atomic::Ordering::Release);
        }
        if let Some(m) = self.monitor {
            let _ = m.join();
        }
    }
}

/// Latch the session exec root off a Create (field 2), the only frame that carries it. Every
/// relative `Push.content` location is resolved against it, so a push that arrives before any
/// Create — which is how a session starts — cannot resolve one; those leaves are recovered when a
/// dependent Create reports them as MissingContent and Bazel pushes them again.
fn latch_exec_root(store: &BlobStore, req: &Request) {
    if let Request::Create { manifest_bytes, .. } = req {
        if let Some(er) = Manifest::new(manifest_bytes).exec_root() {
            store.set_exec_root(er);
        }
    }
}

/// Make every leaf location absolute before the backend sees it. A `location` is relative to the
/// session exec root, and the push is the only moment it means anything — the backend must capture
/// the bytes now, so it cannot be handed a path it has no way to resolve.
fn resolve_locations(store: &BlobStore, content: Vec<(String, ContentSource)>) -> Vec<(String, ContentSource)> {
    let er = store.exec_root().map(str::to_string);
    content
        .into_iter()
        .map(|(digest, source)| match (source, &er) {
            (ContentSource::Location(host), Some(er)) if !host.starts_with('/') => {
                (digest, ContentSource::Location(format!("{er}/{host}")))
            }
            (source, _) => (digest, source),
        })
        .collect()
}

fn handle(backend: &dyn Backend, req: Request, store: &Arc<BlobStore>) -> Response {
    match req {
        Request::Create { rid, sandbox_id, manifest_bytes } => {
            let reply = match backend.create(&sandbox_id, &Manifest::new(&manifest_bytes), store) {
                // Ok reports `unconfined`: our projected filesystem view IS the confinement, so
                // Bazel applies no OS jail on top (a default Seatbelt jail would deny the action's
                // $TMPDIR writes). See CreateReply::Ok.
                Ok(path) => CreateReply::Ok { path },
                Err(CreateError::MissingContent(hashes)) => CreateReply::MissingContent(hashes),
                Err(CreateError::Failed(e)) => CreateReply::Error(format!("{e}")),
            };
            Response { rid, reply: Reply::Create(reply) }
        }
        Request::Collect { rid, sandbox_id, exec_root } => {
            let status = match backend.collect(&sandbox_id, &exec_root) {
                Ok(()) => Status::Ok,
                Err(e) => Status::Error(format!("{e}")),
            };
            Response { rid, reply: Reply::Collect(status) }
        }
        Request::Destroy { rid, sandbox_id } => {
            backend.destroy(&sandbox_id);
            Response { rid, reply: Reply::Destroy(Status::Ok) }
        }
        Request::Negotiate { .. } => unreachable!("negotiate is answered inline in serve(), before queueing"),
        Request::Push { .. } => unreachable!("push is applied inline in serve(), never queued"),
    }
}

/// Answers the Negotiate handshake: VERSION_1 is the only protocol version, so reject only if
/// Bazel's offered set excludes it.
fn negotiate(rid: u64, versions: &[u32]) -> Response {
    if !versions.contains(&proto::VERSION_1) {
        return negotiate_error(rid, "no shared protocol version");
    }
    Response { rid, reply: Reply::Negotiate(NegotiateReply::Ok { version: proto::VERSION_1 }) }
}

fn negotiate_error(rid: u64, message: &str) -> Response {
    Response { rid, reply: Reply::Negotiate(NegotiateReply::Error(format!("sandboxfs: {message}"))) }
}

/// A minimal MPMC work queue (std-only): workers block on `pop` until an item
/// arrives or the reader closes the queue at stdin EOF.
struct Queue {
    inner: Mutex<(VecDeque<(Request, std::time::Instant)>, bool)>,
    cv: Condvar,
}

impl Queue {
    fn new() -> Self {
        Queue { inner: Mutex::new((VecDeque::new(), false)), cv: Condvar::new() }
    }
    fn push(&self, r: Request) {
        self.inner.lock().unwrap().0.push_back((r, std::time::Instant::now()));
        self.cv.notify_one();
    }
    fn close(&self) {
        self.inner.lock().unwrap().1 = true;
        self.cv.notify_all();
    }
    fn pop(&self) -> Option<(Request, std::time::Instant)> {
        let mut g = self.inner.lock().unwrap();
        loop {
            if let Some(r) = g.0.pop_front() {
                return Some(r);
            }
            if g.1 {
                return None;
            }
            g = self.cv.wait(g).unwrap();
        }
    }
}

/// Read a base-128 varint length prefix one byte at a time; None at EOF.
fn read_len<R: Read>(r: &mut R) -> Option<u64> {
    let mut shift = 0u64;
    let mut v = 0u64;
    loop {
        let mut buf = [0u8; 1];
        match r.read(&mut buf) {
            Ok(0) => return None,
            Ok(_) => {}
            Err(ref e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => return None,
        }
        let b = buf[0];
        v |= ((b & 0x7f) as u64) << shift;
        if b & 0x80 == 0 {
            return Some(v);
        }
        shift += 7;
        if shift > 63 {
            return None;
        }
    }
}

/// varint(len) + payload.
fn frame(payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload.len() + 4);
    let mut v = payload.len() as u64;
    while v >= 0x80 {
        out.push((v as u8 & 0x7f) | 0x80);
        v >>= 7;
    }
    out.push(v as u8);
    out.extend_from_slice(payload);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backend_resolution() {
        assert!(resolve(None, None).is_ok(), "default backend");
        assert!(resolve(None, Some("CFS")).is_ok(), "env selects cfs, case-insensitively");
        assert!(resolve(Some("cfs"), Some("nope")).is_ok(), "flag wins over env");
        assert_eq!(resolve(None, Some("fskit")).unwrap(), "fskit", "env selects fskit");
        assert_eq!(resolve(Some("fskit"), None).unwrap(), "fskit", "flag selects fskit");
        assert_eq!(resolve(Some("hardlink"), None).unwrap(), "hardlink", "flag selects hardlink");
        assert!(resolve(Some("nope"), None).is_err(), "an unknown backend is refused");
    }

    struct StubBackend;
    impl Backend for StubBackend {
        fn name(&self) -> &'static str {
            "stub"
        }
        fn mount_path(&self) -> &std::path::Path {
            std::path::Path::new("/pool/stub")
        }
        fn create(
            &self,
            _sandbox_id: &str,
            _manifest: &Manifest<'_>,
            _store: &BlobStore,
        ) -> Result<String, CreateError> {
            Ok("/sandbox/path".into())
        }
        fn collect(&self, _sandbox_id: &str, _exec_root: &str) -> io::Result<()> {
            Ok(())
        }
        fn destroy(&self, _sandbox_id: &str) {}
    }

    #[test]
    fn handle_create_reports_ok_path() {
        let req = Request::Create { rid: 1, sandbox_id: "sbx".into(), manifest_bytes: vec![] };
        match handle(&StubBackend, req, &Arc::new(BlobStore::new())).reply {
            Reply::Create(CreateReply::Ok { path }) => assert_eq!(path, "/sandbox/path"),
            other => panic!("expected Ok, got {other:?}"),
        }
    }

    /// A backend reporting MissingContent is relayed as Create.Result.MissingContent, not an error,
    /// so Bazel pushes and retries rather than failing the action.
    #[test]
    fn handle_create_relays_missing_content() {
        struct MissBackend;
        impl Backend for MissBackend {
            fn name(&self) -> &'static str {
                "miss"
            }
            fn mount_path(&self) -> &std::path::Path {
                std::path::Path::new("/pool/miss")
            }
            fn create(
                &self,
                _s: &str,
                _m: &Manifest<'_>,
                _store: &BlobStore,
            ) -> Result<String, CreateError> {
                Err(CreateError::MissingContent(vec!["deadbeef".into()]))
            }
            fn collect(&self, _s: &str, _e: &str) -> io::Result<()> {
                Ok(())
            }
            fn destroy(&self, _s: &str) {}
        }
        let req = Request::Create { rid: 4, sandbox_id: "sbx".into(), manifest_bytes: vec![] };
        match handle(&MissBackend, req, &Arc::new(BlobStore::new())).reply {
            Reply::Create(CreateReply::MissingContent(h)) => {
                assert_eq!(h, vec!["deadbeef".to_string()])
            }
            other => panic!("expected MissingContent, got {other:?}"),
        }
    }

    #[test]
    fn negotiate_accepts_shared_version() {
        match negotiate(1, &[proto::VERSION_1]).reply {
            Reply::Negotiate(NegotiateReply::Ok { version }) => {
                assert_eq!(version, proto::VERSION_1);
            }
            other => panic!("expected Negotiated, got {other:?}"),
        }
    }

    #[test]
    fn negotiate_errors_when_no_shared_version() {
        assert!(matches!(negotiate(2, &[999]).reply, Reply::Negotiate(NegotiateReply::Error(_))));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn metrics_gate_off_without_env_or_option() {
        std::env::remove_var("sandboxfs_metrics");
        let gate = MetricsGate::start("ws", Arc::new(StubBackend), &Options::default());
        assert!(gate.stop.is_none());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn metrics_gate_armed_by_metrics_backend_opt() {
        // The --sandbox_backend_opt=<name>=metrics path: relayed via Negotiate.options, no env var.
        std::env::remove_var("sandboxfs_metrics");
        let gate = MetricsGate::start(
            "ws",
            Arc::new(StubBackend),
            &Options { metrics: true, ..Options::default() },
        );
        assert!(gate.stop.is_some());
        gate.finish();
    }

    #[test]
    fn framing_round_trips() {
        let payload = vec![1u8, 2, 3, 200, 255]; // >0x80 byte exercises the varint
        let f = frame(&payload);
        let mut c = io::Cursor::new(f);
        let len = read_len(&mut c).unwrap();
        assert_eq!(len, payload.len() as u64);
        let mut body = vec![0u8; len as usize];
        c.read_exact(&mut body).unwrap();
        assert_eq!(body, payload);
    }

    /// A `Push.content` location arrives relative to the session exec root, and the exec root only
    /// ever arrives on a Create. Without the latch every relative location reached the backend
    /// unresolved, every capture failed silently, and each affected leaf fell back to the
    /// `exec_root/<tree path>` derivation — which for a runfiles entry cannot resolve, failing the
    /// action with a bare ENOENT.
    #[test]
    fn a_create_latches_the_exec_root_so_relative_push_locations_resolve() {
        use backend::wire::Writer;
        let store = BlobStore::new();
        let relative = || {
            vec![(
                "dg".to_string(),
                ContentSource::Location("_main/bazel-out/bin/pkg/tool.repo_mapping".into()),
            )]
        };

        // Before any Create there is nothing to resolve against, and the location is left alone.
        match resolve_locations(&store, relative()).pop().unwrap().1 {
            ContentSource::Location(p) => {
                assert_eq!(p, "_main/bazel-out/bin/pkg/tool.repo_mapping")
            }
            other => panic!("expected a location, got {other:?}"),
        }

        let mut m = Writer::default();
        m.str(2, "/exec/root"); // Manifest field 2
        latch_exec_root(
            &store,
            &Request::Create { rid: 1, sandbox_id: "sbx".into(), manifest_bytes: m.out },
        );
        assert_eq!(store.exec_root(), Some("/exec/root"));

        match resolve_locations(&store, relative()).pop().unwrap().1 {
            ContentSource::Location(p) => {
                assert_eq!(p, "/exec/root/_main/bazel-out/bin/pkg/tool.repo_mapping")
            }
            other => panic!("expected a location, got {other:?}"),
        }

        // An absolute location is already meaningful and must not be rewritten.
        let absolute = vec![("dg2".to_string(), ContentSource::Location("/somewhere/else".into()))];
        match resolve_locations(&store, absolute).pop().unwrap().1 {
            ContentSource::Location(p) => assert_eq!(p, "/somewhere/else"),
            other => panic!("expected a location, got {other:?}"),
        }
    }
}
