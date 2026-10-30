//! REAPI v2 execution and CAS service implementation over Unix domain socket for `sandboxfs`.
//!
//! Translates `Capabilities.GetCapabilities`, `ContentAddressableStorage.{FindMissingBlobs,
//! BatchUpdateBlobs, BatchReadBlobs}`, and `Execution.Execute` into `backend::BlobStore` and
//! `backend::Backend` (`create`, `collect`, `destroy`) calls, while supporting optional
//! `linux-sandbox` OS namespace confinement and post-execution hardlink tamper verification.

use crate::stats;
use backend::tree::{self, EMPTY_DIRECTORY_DIGEST};
use backend::wire::{parse_digest, parse_map_entry, sha256_file, sha256_hex, string, Reader, Writer};
use backend::{Backend, BlobStore, ContentSource, CreateError, Manifest, Options};
use backend_hardlink::Hardlink;
use rustc_hash::FxHashMap;
use std::fs;
use std::io::Read;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const INSTANCE_LOCAL_FILE_PATHS: &str = "local-file-paths";

const RPC_OK: u64 = 0;
const RPC_CANCELLED: u64 = 1;
const RPC_INVALID_ARGUMENT: u64 = 3;
const RPC_DEADLINE_EXCEEDED: u64 = 4;
const RPC_NOT_FOUND: u64 = 5;
const RPC_FAILED_PRECONDITION: u64 = 9;
const RPC_INTERNAL: u64 = 13;

pub struct ReapiState {
    pub backend: Arc<dyn Backend>,
    pub hardlink: Option<Arc<Hardlink>>,
    pub store: Arc<BlobStore>,
    pub raw_blobs: Mutex<FxHashMap<String, Vec<u8>>>,
    pub options: Options,
    pub stats_dir: Option<PathBuf>,
    inaccessible_file: PathBuf,
    inaccessible_dir: PathBuf,
    op_seq: AtomicU64,
}

impl ReapiState {
    pub fn new(
        backend: Arc<dyn Backend>,
        hardlink: Option<Arc<Hardlink>>,
        store: Arc<BlobStore>,
        options: Options,
    ) -> Self {
        let base_dir = options.pool_root.clone().unwrap_or_else(|| {
            std::env::temp_dir().join(format!("sandboxfs-reapi-{}", std::process::id()))
        });
        let _ = fs::create_dir_all(&base_dir);
        let inaccessible_file = base_dir.join(".inaccessible_file");
        let inaccessible_dir = base_dir.join(".inaccessible_dir");
        let _ = fs::write(&inaccessible_file, b"");
        let _ = fs::set_permissions(&inaccessible_file, fs::Permissions::from_mode(0o000));
        let _ = fs::create_dir_all(&inaccessible_dir);
        let _ = fs::set_permissions(&inaccessible_dir, fs::Permissions::from_mode(0o000));

        let s = Self {
            backend,
            hardlink,
            store,
            raw_blobs: Mutex::new(FxHashMap::default()),
            stats_dir: options.metrics.then(|| options.pool_root.clone()).flatten(),
            options,
            inaccessible_file,
            inaccessible_dir,
            op_seq: AtomicU64::new(1),
        };
        s.write_stats_snapshot();
        s
    }

    pub fn write_stats_snapshot(&self) {
        let Some(ref dir) = self.stats_dir else { return };
        let mut out = stats::report_text(self.backend.name());
        if let Some(ref hl) = self.hardlink {
            let (alloc, reuse, skipped, removed, repaired) = hl.slot_metrics();
            out.push_str(&format!(
                "slots_allocated={alloc}\nslot_reuses={reuse}\nskipped_subtrees={skipped}\nremoved_entries={removed}\nrepaired_files={repaired}\n"
            ));
        }
        let mut by_digest: std::collections::BTreeMap<String, Vec<String>> =
            std::collections::BTreeMap::new();
        for (dg, path) in self.store.all_registered_paths() {
            by_digest.entry(dg).or_default().push(path);
        }
        for (dg, paths) in by_digest {
            out.push_str(&format!("registered:{dg}={}\n", paths.join("\t")));
        }
        let tmp =
            dir.join(format!("stats.txt.tmp.{}", self.op_seq.fetch_add(1, Ordering::Relaxed)));
        if fs::write(&tmp, out).is_ok() {
            let _ = fs::rename(&tmp, dir.join("stats.txt"));
        }
    }

    pub fn handle_get_capabilities(&self) -> Vec<u8> {
        let mut cache_caps = Writer::default();
        cache_caps.uint(1, 1); // digest_functions = SHA256 (1)
        cache_caps.uint(1, 0); // digest_functions = UNKNOWN (0) for Google3 Blaze PSHA2
        let mut action_cache_caps = Writer::default();
        action_cache_caps.bool(1, false);
        cache_caps.msg(2, &action_cache_caps.out);

        let mut exec_caps = Writer::default();
        exec_caps.uint(1, 1); // digest_function = SHA256 (1)
        exec_caps.bool(2, true); // exec_enabled = true
        exec_caps.uint(5, 1); // digest_functions = SHA256 (1)
        exec_caps.uint(5, 0); // digest_functions = UNKNOWN (0) for Google3 Blaze PSHA2

        let mut resp = Writer::default();
        resp.msg(1, &cache_caps.out);
        resp.msg(2, &exec_caps.out);
        resp.out
    }

    pub fn handle_find_missing_blobs(&self, req_bytes: &[u8]) -> Vec<u8> {
        let mut r = Reader::new(req_bytes);
        let mut digests: Vec<(String, u64)> = Vec::new();
        while let Some((field, wire)) = r.next_key() {
            match (field, wire) {
                (2, 2) => {
                    if let Some(s) = r.len_slice() {
                        if let Some(d) = parse_digest(s) {
                            digests.push(d);
                        }
                    }
                }
                (_, w) => r.skip(w),
            }
        }
        let raw = self.raw_blobs.lock().unwrap();
        let mut resp = Writer::default();
        for (hash, size) in digests {
            if size == 0 || hash == EMPTY_DIRECTORY_DIGEST {
                continue;
            }
            if !raw.contains_key(&hash) && !self.store.has_blob_or_location(&hash) {
                resp.msg(2, &encode_digest(&hash, size));
            }
        }
        resp.out
    }

    pub fn handle_batch_update_blobs(&self, req_bytes: &[u8]) -> Vec<u8> {
        let mut r = Reader::new(req_bytes);
        let mut instance_name = String::new();
        let mut items: Vec<(String, u64, Vec<u8>)> = Vec::new();
        while let Some((field, wire)) = r.next_key() {
            match (field, wire) {
                (1, 2) => {
                    if let Some(s) = r.len_slice() {
                        instance_name = string(s);
                    }
                }
                (2, 2) => {
                    if let Some(s) = r.len_slice() {
                        if let Some(item) = parse_update_request(s) {
                            items.push(item);
                        }
                    }
                }
                (_, w) => r.skip(w),
            }
        }

        let is_local_paths = instance_name == INSTANCE_LOCAL_FILE_PATHS;
        if is_local_paths {
            self.store.enable_verified_mode();
        }

        let mut resp = Writer::default();
        let mut inline_digests = Vec::new();
        let mut dir_blobs = Vec::new();
        let mut staged_inline = Vec::new();

        for (hash, size, data) in items {
            if is_local_paths {
                if let Ok(path_str) = std::str::from_utf8(&data) {
                    self.store.register_verified_location(hash.clone(), path_str.to_string());
                }
            } else {
                self.raw_blobs.lock().unwrap().insert(hash.clone(), data.clone());
                dir_blobs.push((hash.clone(), data.clone()));
                staged_inline.push((hash.clone(), ContentSource::Inline(data)));
                inline_digests.push(hash.clone());
            }

            let mut item_resp = Writer::default();
            item_resp.msg(1, &encode_digest(&hash, size));
            item_resp.msg(2, &encode_rpc_status(RPC_OK, "", &[]));
            resp.msg(1, &item_resp.out);
        }

        if !is_local_paths && !inline_digests.is_empty() {
            self.store.insert_dirs(dir_blobs);
            self.store.stage_content(staged_inline);
            self.backend.push(&self.store, &inline_digests);
            self.store.clear_pending();
        }

        self.write_stats_snapshot();
        resp.out
    }

    pub fn handle_batch_read_blobs(&self, req_bytes: &[u8]) -> Vec<u8> {
        let mut r = Reader::new(req_bytes);
        let mut digests: Vec<(String, u64)> = Vec::new();
        while let Some((field, wire)) = r.next_key() {
            match (field, wire) {
                (2, 2) => {
                    if let Some(s) = r.len_slice() {
                        if let Some(d) = parse_digest(s) {
                            digests.push(d);
                        }
                    }
                }
                (_, w) => r.skip(w),
            }
        }

        let raw = self.raw_blobs.lock().unwrap();
        let mut resp = Writer::default();
        for (hash, size) in digests {
            let mut item = Writer::default();
            item.msg(1, &encode_digest(&hash, size));
            if size == 0 || hash == EMPTY_DIRECTORY_DIGEST {
                item.msg(3, &encode_rpc_status(RPC_OK, "", &[]));
            } else if let Some(bytes) = raw.get(&hash) {
                item.bytes(2, bytes);
                item.msg(3, &encode_rpc_status(RPC_OK, "", &[]));
            } else if let Some(host_path) = self
                .store
                .resolve_verified_host(&hash)
                .or_else(|| self.store.captured(&hash))
                .or_else(|| {
                    self.store
                        .cas_blob_path(&hash)
                        .filter(|p| p.exists())
                        .map(|p| p.to_string_lossy().into_owned())
                })
            {
                match fs::read(&host_path) {
                    Ok(bytes) => {
                        item.bytes(2, &bytes);
                        item.msg(3, &encode_rpc_status(RPC_OK, "", &[]));
                    }
                    Err(e) => {
                        item.msg(
                            3,
                            &encode_rpc_status(
                                RPC_NOT_FOUND,
                                &format!("failed to read {host_path}: {e}"),
                                &[],
                            ),
                        );
                    }
                }
            } else {
                item.msg(
                    3,
                    &encode_rpc_status(RPC_NOT_FOUND, &format!("blob {hash} not found"), &[]),
                );
            }
            resp.msg(1, &item.out);
        }
        resp.out
    }

    pub fn handle_execute(
        &self,
        req_bytes: &[u8],
        cancelled: Arc<AtomicBool>,
        active_pid: Arc<AtomicI32>,
    ) -> Vec<u8> {
        let op_name =
            format!("operations/sandboxfs-{}", self.op_seq.fetch_add(1, Ordering::Relaxed));
        let Some(action_digest) = parse_execute_request(req_bytes) else {
            return encode_operation_error(
                &op_name,
                RPC_INVALID_ARGUMENT,
                "ExecuteRequest missing action_digest",
            );
        };

        let Some(action_bytes) = self.get_raw_blob(&action_digest.0) else {
            return self.encode_missing_blobs_operation(&op_name, &[action_digest.0]);
        };
        let Some(action) = parse_action(&action_bytes) else {
            return encode_operation_error(
                &op_name,
                RPC_INVALID_ARGUMENT,
                "Malformed Action proto",
            );
        };

        let Some(command_bytes) = self.get_raw_blob(&action.command_digest.0) else {
            return self.encode_missing_blobs_operation(&op_name, &[action.command_digest.0]);
        };
        let Some(cmd) = parse_command(&command_bytes) else {
            return encode_operation_error(
                &op_name,
                RPC_INVALID_ARGUMENT,
                "Malformed Command proto",
            );
        };

        let mut props = action.platform_props;
        for (k, v) in &cmd.platform_props {
            props.push((k.clone(), v.clone()));
        }

        let mut exec_root = String::new();
        let mut sandbox_id = String::new();
        let mut output_staging_dir = String::new();
        let mut allow_network = false;
        let mut path_mappings: FxHashMap<String, String> = FxHashMap::default();
        let mut writable_paths: Vec<String> = Vec::new();
        let mut tmpfs_paths: Vec<String> = Vec::new();
        let mut inaccessible_paths: Vec<String> = Vec::new();

        for (k, v) in &props {
            match k.as_str() {
                "exec_root" => exec_root = v.clone(),
                "sandbox_id" => sandbox_id = v.clone(),
                "output_staging_dir" => output_staging_dir = v.clone(),
                "allow_network" => allow_network = v == "true",
                "bazel.sandbox.cas_root" if !v.is_empty() => {
                    self.store.set_cas_root(PathBuf::from(v));
                }
                "disk_cache" if !v.is_empty() && self.store.cas_root().is_none() => {
                    self.store.set_cas_root(PathBuf::from(v).join("cas"));
                }
                "output_path_mapping" => {
                    if let Some((mapped, unmapped)) = v.split_once(':') {
                        path_mappings.insert(mapped.to_string(), unmapped.to_string());
                    }
                }
                "writable_path" => writable_paths.push(v.clone()),
                "tmpfs_path" => tmpfs_paths.push(v.clone()),
                "inaccessible_path" => inaccessible_paths.push(v.clone()),
                _ => {}
            }
        }
        if sandbox_id.is_empty() {
            sandbox_id = format!("sb-{}", self.op_seq.fetch_add(1, Ordering::Relaxed));
        }
        if !exec_root.is_empty() {
            self.store.set_exec_root(&exec_root);
        }

        // Build declared outputs list for `Manifest::encode`.
        // When `output_staging_dir` is set, `SandboxBackendSpawnRunner.commitOutputs` expects
        // staged outputs at `<output_staging_dir>/<mapped_path>` and performs the unmapping
        // move to `<exec_root>/<unmapped_path>` itself.
        let mut declared_outputs: Vec<(String, String, String)> = Vec::new();
        let mut seen_outputs = std::collections::HashSet::new();
        let dir_set: std::collections::HashSet<&str> =
            cmd.output_directories.iter().map(String::as_str).collect();
        for p in cmd
            .output_paths
            .iter()
            .chain(cmd.output_files.iter())
            .chain(cmd.output_directories.iter())
        {
            if !seen_outputs.insert(p.clone()) {
                continue;
            }
            let kind = if dir_set.contains(p.as_str()) { "dir" } else { "file" };
            let dest = if output_staging_dir.is_empty() {
                path_mappings.get(p).cloned().unwrap_or_default()
            } else {
                String::new()
            };
            declared_outputs.push((p.clone(), kind.to_string(), dest));
        }

        let root_digest_str = if action.input_root_digest.1 == 0 {
            EMPTY_DIRECTORY_DIGEST
        } else {
            &action.input_root_digest.0
        };
        let manifest_bytes =
            Manifest::encode("ReapiExecute", &exec_root, root_digest_str, &declared_outputs, &[]);
        let manifest = Manifest::new(&manifest_bytes);

        let create_t0 = Instant::now();
        let slot_path = match self.backend.create(&sandbox_id, &manifest, &self.store) {
            Ok(p) => p,
            Err(CreateError::MissingContent(missing)) => {
                self.write_stats_snapshot();
                return self.encode_missing_blobs_operation(&op_name, &missing);
            }
            Err(CreateError::Failed(e)) => {
                self.write_stats_snapshot();
                return encode_operation_error(
                    &op_name,
                    RPC_INTERNAL,
                    &format!("sandboxfs create failed: {e}"),
                );
            }
        };
        let create_ns = create_t0.elapsed().as_nanos() as u64;
        stats::CREATE_T.record(0, create_ns, 0);
        stats::record_create("ReapiExecute", create_ns);

        let slot_root = PathBuf::from(&slot_path);
        let work_dir = if cmd.working_directory.is_empty() {
            slot_root.clone()
        } else {
            slot_root.join(cmd.working_directory.trim_start_matches('/'))
        };
        let _ = fs::create_dir_all(&work_dir);

        // Ensure writable paths inside or outside the slot exist before running.
        for wp in &writable_paths {
            if !wp.starts_with('/') {
                let _ = fs::create_dir_all(slot_root.join(wp));
            }
        }

        // Execute the command (handle `builtin:noop` fast-path for synthetic tree benchmarks).
        let exec_outcome = if cmd.arguments.first().map(String::as_str) == Some("builtin:noop") {
            for (out_path, kind, _) in &declared_outputs {
                let target = slot_root.join(out_path.trim_start_matches('/'));
                if kind == "dir" {
                    let _ = fs::create_dir_all(&target);
                } else {
                    if let Some(parent) = target.parent() {
                        let _ = fs::create_dir_all(parent);
                    }
                    let _ = fs::write(&target, b"");
                }
            }
            Ok(SubprocessResult {
                exit_code: 0,
                stdout: Vec::new(),
                stderr: Vec::new(),
                timed_out: false,
                was_cancelled: false,
                user_time: Duration::from_millis(1),
            })
        } else {
            self.run_subprocess(
                &cmd,
                &slot_root,
                &work_dir,
                action.timeout,
                allow_network,
                &writable_paths,
                &tmpfs_paths,
                &inaccessible_paths,
                &cancelled,
                &active_pid,
            )
        };

        let sub = match exec_outcome {
            Ok(s) => s,
            Err(e) => {
                self.backend.destroy(&sandbox_id);
                self.write_stats_snapshot();
                return encode_operation_error(
                    &op_name,
                    RPC_INTERNAL,
                    &format!("failed to spawn command: {e}"),
                );
            }
        };

        if sub.was_cancelled {
            self.backend.destroy(&sandbox_id);
            self.write_stats_snapshot();
            return encode_operation_error(
                &op_name,
                RPC_CANCELLED,
                "Execution cancelled by client",
            );
        }

        // Post-condition verification (`AbstractSandboxSpawnRunner.verifyPostCondition`): check
        // that no hardlinked input file was modified in-place during action execution.
        if self.store.is_verified_mode() {
            let input_digests =
                tree::collect_file_digests(&action.input_root_digest.0, &self.store);
            if let Err(msg) = self.store.verify_post_condition(&input_digests) {
                if let Some(ref hl) = self.hardlink {
                    hl.invalidate_slot_for(&sandbox_id);
                }
                self.backend.destroy(&sandbox_id);
                self.write_stats_snapshot();
                return encode_operation_error(&op_name, RPC_INTERNAL, &msg);
            }
        } else if self.options.linux_sandbox.is_some() && self.store.has_cas_root() {
            let input_files =
                tree::collect_file_digests_with_sizes(&action.input_root_digest.0, &self.store);
            if let Err(msg) = self.store.verify_cas_post_condition(&input_files) {
                if let Some(ref hl) = self.hardlink {
                    hl.invalidate_slot_for(&sandbox_id);
                }
                self.backend.destroy(&sandbox_id);
                self.write_stats_snapshot();
                return encode_operation_error(&op_name, RPC_INTERNAL, &msg);
            }
        }

        // Scan produced outputs in `slot_root` to populate `ActionResult`.
        // In shared `--disk_cache` CAS mode (`self.store.cas_root().is_some()` and
        // `output_staging_dir.is_empty()`), outputs are captured directly into
        // `<cas_root>/<hash[0..2]>/<hash>` (including `Tree` protos for output directories) and
        // removed from `slot_root` without touching `exec_root`, so `SandboxBackendSpawnRunner`
        // can verify and link/clone them into `exec_root` after winning `context.lockOutputFiles`.
        let mut output_files: Vec<Vec<u8>> = Vec::new();
        let mut output_symlinks: Vec<Vec<u8>> = Vec::new();
        let mut output_directories: Vec<Vec<u8>> = Vec::new();
        let cas_root_opt = self.store.cas_root();

        if !sub.timed_out {
            if let (Some(ref cas_root), true) = (&cas_root_opt, output_staging_dir.is_empty()) {
                let collect_t0 = Instant::now();
                for (rel_path, _, _) in &declared_outputs {
                    let clean_rel = rel_path.trim_start_matches('/');
                    let candidate = slot_root.join(clean_rel);
                    let Ok(meta) = fs::symlink_metadata(&candidate) else { continue };
                    let ft = meta.file_type();
                    if ft.is_symlink() {
                        if let Ok(target) = fs::read_link(&candidate) {
                            let mut sym = Writer::default();
                            sym.str(1, clean_rel);
                            sym.str(2, &target.to_string_lossy());
                            output_symlinks.push(sym.out);
                        }
                        let _ = fs::remove_file(&candidate);
                    } else if ft.is_dir() {
                        match self.capture_output_dir_to_cas(&candidate, cas_root) {
                            Ok((tree_hash, tree_size)) => {
                                let mut dir_msg = Writer::default();
                                dir_msg.str(1, clean_rel);
                                dir_msg.msg(3, &encode_digest(&tree_hash, tree_size));
                                output_directories.push(dir_msg.out);
                            }
                            Err(e) => {
                                self.backend.destroy(&sandbox_id);
                                self.write_stats_snapshot();
                                return encode_operation_error(
                                    &op_name,
                                    RPC_INTERNAL,
                                    &format!("sandboxfs CAS output directory capture failed: {e}"),
                                );
                            }
                        }
                        let _ = backend_hardlink::fsops::remove(&candidate);
                    } else if ft.is_file() {
                        let is_exec = (meta.mode() & 0o111) != 0;
                        match self.capture_output_file_to_cas(&candidate, &meta, is_exec, cas_root)
                        {
                            Ok((digest_hex, size)) => {
                                let mut of = Writer::default();
                                of.str(1, clean_rel);
                                of.msg(2, &encode_digest(&digest_hex, size));
                                of.bool(4, is_exec);
                                output_files.push(of.out);
                            }
                            Err(e) => {
                                self.backend.destroy(&sandbox_id);
                                self.write_stats_snapshot();
                                return encode_operation_error(
                                    &op_name,
                                    RPC_INTERNAL,
                                    &format!("sandboxfs CAS output file capture failed: {e}"),
                                );
                            }
                        }
                        let _ = fs::remove_file(&candidate);
                    }
                }
                stats::COLLECT_T.record(0, collect_t0.elapsed().as_nanos() as u64, 0);
            } else {
                for (rel_path, _, _) in &declared_outputs {
                    let clean_rel = rel_path.trim_start_matches('/');
                    let candidate = slot_root.join(clean_rel);
                    let Ok(meta) = fs::symlink_metadata(&candidate) else { continue };
                    let ft = meta.file_type();
                    if ft.is_symlink() {
                        if let Ok(target) = fs::read_link(&candidate) {
                            let mut sym = Writer::default();
                            sym.str(1, clean_rel);
                            sym.str(2, &target.to_string_lossy());
                            output_symlinks.push(sym.out);
                        }
                    } else if ft.is_dir() {
                        let mut dir_msg = Writer::default();
                        dir_msg.str(1, clean_rel);
                        dir_msg.msg(3, &encode_digest(EMPTY_DIRECTORY_DIGEST, 0));
                        output_directories.push(dir_msg.out);
                    } else if ft.is_file() {
                        let is_exec = (meta.mode() & 0o111) != 0;
                        let size = meta.len();
                        let digest_hex = fs::read(&candidate)
                            .map(|b| sha256_hex(&b))
                            .unwrap_or_else(|_| EMPTY_DIRECTORY_DIGEST.to_string());
                        let mut of = Writer::default();
                        of.str(1, clean_rel);
                        of.msg(2, &encode_digest(&digest_hex, size));
                        of.bool(4, is_exec);
                        output_files.push(of.out);
                    }
                }

                let collect_target =
                    if !output_staging_dir.is_empty() { &output_staging_dir } else { &exec_root };
                if !collect_target.is_empty() {
                    let collect_t0 = Instant::now();
                    if let Err(e) = self.backend.collect(&sandbox_id, collect_target) {
                        self.backend.destroy(&sandbox_id);
                        self.write_stats_snapshot();
                        return encode_operation_error(
                            &op_name,
                            RPC_INTERNAL,
                            &format!("sandboxfs collect failed: {e}"),
                        );
                    }
                    stats::COLLECT_T.record(0, collect_t0.elapsed().as_nanos() as u64, 0);
                }
            }
        }

        let destroy_t0 = Instant::now();
        self.backend.destroy(&sandbox_id);
        stats::DESTROY_T.record(0, destroy_t0.elapsed().as_nanos() as u64, 0);
        self.write_stats_snapshot();

        // Build ActionResult
        let mut action_result = Writer::default();
        for of in output_files {
            action_result.msg(2, &of);
        }
        for od in output_directories {
            action_result.msg(3, &od);
        }
        action_result.uint(4, sub.exit_code as i64 as u64);
        if !sub.stdout.is_empty() {
            let stdout_hash = sha256_hex(&sub.stdout);
            let stdout_len = sub.stdout.len() as u64;
            if let Some(ref cas_root) = cas_root_opt {
                let _ = self.write_blob_to_cas(cas_root, &stdout_hash, &sub.stdout, false);
            } else {
                self.raw_blobs.lock().unwrap().insert(stdout_hash.clone(), sub.stdout.clone());
            }
            action_result.bytes(5, &sub.stdout);
            action_result.msg(6, &encode_digest(&stdout_hash, stdout_len));
        }
        if !sub.stderr.is_empty() {
            let stderr_hash = sha256_hex(&sub.stderr);
            let stderr_len = sub.stderr.len() as u64;
            if let Some(ref cas_root) = cas_root_opt {
                let _ = self.write_blob_to_cas(cas_root, &stderr_hash, &sub.stderr, false);
            } else {
                self.raw_blobs.lock().unwrap().insert(stderr_hash.clone(), sub.stderr.clone());
            }
            action_result.bytes(7, &sub.stderr);
            action_result.msg(8, &encode_digest(&stderr_hash, stderr_len));
        }

        // ExecutedActionMetadata (field 9): worker (field 1), virtual_execution_duration (field 12)
        let mut exec_meta = Writer::default();
        exec_meta.str(1, self.backend.name());
        let mut dur = Writer::default();
        dur.uint(1, sub.user_time.as_secs());
        dur.uint(2, sub.user_time.subsec_nanos() as u64);
        exec_meta.msg(12, &dur.out);
        action_result.msg(9, &exec_meta.out);

        for os in output_symlinks {
            action_result.msg(12, &os);
        }

        let mut exec_resp = Writer::default();
        exec_resp.msg(1, &action_result.out);
        if sub.timed_out {
            exec_resp.msg(3, &encode_rpc_status(RPC_DEADLINE_EXCEEDED, "Action timed out", &[]));
        } else {
            exec_resp.msg(3, &encode_rpc_status(RPC_OK, "", &[]));
        }

        encode_operation_done(&op_name, &exec_resp.out)
    }

    fn get_raw_blob(&self, hash: &str) -> Option<Vec<u8>> {
        if hash.is_empty() || hash == EMPTY_DIRECTORY_DIGEST {
            return Some(Vec::new());
        }
        if let Some(b) = self.raw_blobs.lock().unwrap().get(hash).cloned() {
            return Some(b);
        }
        self.store.dir(hash).map(|b| b.to_vec())
    }

    fn write_blob_to_cas(
        &self,
        cas_root: &Path,
        hash: &str,
        bytes: &[u8],
        executable: bool,
    ) -> std::io::Result<PathBuf> {
        let prefix = if hash.len() >= 2 { &hash[..2] } else { "00" };
        let shard_dir = cas_root.join(prefix);
        let target = shard_dir.join(hash);
        if let Ok(tmeta) = fs::symlink_metadata(&target) {
            let t_exec = (tmeta.mode() & 0o111) != 0;
            let t_ro = (tmeta.mode() & 0o200) == 0;
            if t_exec != executable || (!executable && t_ro) {
                let _ = fs::set_permissions(
                    &target,
                    fs::Permissions::from_mode(if executable { 0o755 } else { 0o644 }),
                );
            }
            return Ok(target);
        }
        let tmp = shard_dir.join(format!(
            ".tmp-{}-{}",
            std::process::id(),
            self.op_seq.fetch_add(1, Ordering::Relaxed)
        ));
        if let Err(e) = fs::write(&tmp, bytes) {
            if e.kind() == std::io::ErrorKind::NotFound {
                fs::create_dir_all(&shard_dir)?;
                fs::write(&tmp, bytes)?;
            } else {
                return Err(e);
            }
        }
        if executable {
            let _ = fs::set_permissions(&tmp, fs::Permissions::from_mode(0o755));
        }
        let res = match fs::hard_link(&tmp, &target) {
            Ok(()) => Ok(target),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(target),
            Err(_) => match fs::rename(&tmp, &target) {
                Ok(()) => return Ok(target),
                Err(e) => {
                    let _ = fs::remove_file(&tmp);
                    return if target.exists() { Ok(target) } else { Err(e) };
                }
            },
        };
        let _ = fs::remove_file(&tmp);
        res
    }

    fn capture_output_file_to_cas(
        &self,
        file_path: &Path,
        meta: &fs::Metadata,
        executable: bool,
        cas_root: &Path,
    ) -> std::io::Result<(String, u64)> {
        let size = meta.len();
        if size == 0 {
            return Ok((EMPTY_DIRECTORY_DIGEST.to_string(), 0));
        }
        let (hash, _) = sha256_file(file_path)?;
        let prefix = if hash.len() >= 2 { &hash[..2] } else { "00" };
        let shard_dir = cas_root.join(prefix);
        let target = shard_dir.join(&hash);
        if let Ok(tmeta) = fs::symlink_metadata(&target) {
            let t_exec = (tmeta.mode() & 0o111) != 0;
            let t_ro = (tmeta.mode() & 0o200) == 0;
            if t_exec != executable || (!executable && t_ro) {
                let _ = fs::set_permissions(
                    &target,
                    fs::Permissions::from_mode(if executable { 0o755 } else { 0o644 }),
                );
            }
            return Ok((hash, size));
        }
        if meta.nlink() == 1 {
            let is_ro = (meta.mode() & 0o200) == 0;
            if executable || is_ro {
                let _ = fs::set_permissions(
                    file_path,
                    fs::Permissions::from_mode(if executable { 0o755 } else { 0o644 }),
                );
            }
            // Move the freshly produced output file from the ephemeral sandbox slot into CAS via
            // `link + unlink` (the caller immediately removes the slot file) so the CAS entry ends
            // up with `nlink == 1` without acquiring the kernel's cross-directory `s_vfs_rename_mutex`.
            match fs::hard_link(file_path, &target) {
                Ok(()) => {
                    let _ = fs::remove_file(file_path);
                    return Ok((hash, size));
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                    let _ = fs::remove_file(file_path);
                    return Ok((hash, size));
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    let _ = fs::create_dir_all(&shard_dir);
                    if fs::hard_link(file_path, &target).is_ok() {
                        let _ = fs::remove_file(file_path);
                        return Ok((hash, size));
                    }
                }
                Err(_) => {}
            }
        }
        let tmp = shard_dir.join(format!(
            ".tmp-{}-{}",
            std::process::id(),
            self.op_seq.fetch_add(1, Ordering::Relaxed)
        ));
        if let Err(e) = fs::copy(file_path, &tmp) {
            if e.kind() == std::io::ErrorKind::NotFound {
                fs::create_dir_all(&shard_dir)?;
                fs::copy(file_path, &tmp)?;
            } else {
                return Err(e);
            }
        }
        let is_ro = (meta.mode() & 0o200) == 0;
        if executable || is_ro {
            let _ = fs::set_permissions(
                &tmp,
                fs::Permissions::from_mode(if executable { 0o755 } else { 0o644 }),
            );
        }
        let res = match fs::hard_link(&tmp, &target) {
            Ok(()) => Ok((hash, size)),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok((hash, size)),
            Err(_) => match fs::rename(&tmp, &target) {
                Ok(()) => return Ok((hash, size)),
                Err(e) => {
                    let _ = fs::remove_file(&tmp);
                    return if target.exists() { Ok((hash, size)) } else { Err(e) };
                }
            },
        };
        let _ = fs::remove_file(&tmp);
        res
    }

    fn capture_output_dir_to_cas(
        &self,
        dir_path: &Path,
        cas_root: &Path,
    ) -> std::io::Result<(String, u64)> {
        let mut children_dirs: Vec<Vec<u8>> = Vec::new();
        let root_dir_bytes =
            self.build_cas_directory_proto(dir_path, cas_root, &mut children_dirs)?;
        let mut tree_writer = Writer::default();
        tree_writer.msg(1, &root_dir_bytes);
        for child in &children_dirs {
            tree_writer.msg(2, child);
        }
        let tree_bytes = tree_writer.out;
        let tree_size = tree_bytes.len() as u64;
        if tree_size == 0 {
            return Ok((EMPTY_DIRECTORY_DIGEST.to_string(), 0));
        }
        let tree_hash = sha256_hex(&tree_bytes);
        self.write_blob_to_cas(cas_root, &tree_hash, &tree_bytes, false)?;
        self.store.insert_dirs([(tree_hash.clone(), tree_bytes)]);
        Ok((tree_hash, tree_size))
    }

    fn build_cas_directory_proto(
        &self,
        dir_path: &Path,
        cas_root: &Path,
        children_dirs: &mut Vec<Vec<u8>>,
    ) -> std::io::Result<Vec<u8>> {
        let mut entries: Vec<(String, PathBuf, fs::Metadata)> = Vec::new();
        for entry in fs::read_dir(dir_path)? {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().into_owned();
            let path = entry.path();
            let meta = fs::symlink_metadata(&path)?;
            entries.push((name, path, meta));
        }
        entries.sort_by(|a, b| a.0.cmp(&b.0));

        let mut file_nodes: Vec<Vec<u8>> = Vec::new();
        let mut dir_nodes: Vec<Vec<u8>> = Vec::new();
        let mut symlink_nodes: Vec<Vec<u8>> = Vec::new();

        for (name, path, meta) in entries {
            let ft = meta.file_type();
            let mode = meta.mode();
            if ft.is_symlink() {
                let target = fs::read_link(&path)?;
                let mut sn = Writer::default();
                sn.str(1, &name);
                sn.str(2, &target.to_string_lossy());
                symlink_nodes.push(sn.out);
            } else if ft.is_dir() {
                let child_bytes = self.build_cas_directory_proto(&path, cas_root, children_dirs)?;
                let child_size = child_bytes.len() as u64;
                let child_hash = if child_size == 0 {
                    EMPTY_DIRECTORY_DIGEST.to_string()
                } else {
                    let h = sha256_hex(&child_bytes);
                    self.write_blob_to_cas(cas_root, &h, &child_bytes, false)?;
                    self.store.insert_dirs([(h.clone(), child_bytes.clone())]);
                    h
                };
                children_dirs.push(child_bytes);
                let mut dn = Writer::default();
                dn.str(1, &name);
                dn.msg(2, &encode_digest(&child_hash, child_size));
                dir_nodes.push(dn.out);
            } else if ft.is_file() {
                let is_exec = (mode & 0o111) != 0;
                let (f_hash, f_size) =
                    self.capture_output_file_to_cas(&path, &meta, is_exec, cas_root)?;
                let mut fn_writer = Writer::default();
                fn_writer.str(1, &name);
                fn_writer.msg(2, &encode_digest(&f_hash, f_size));
                fn_writer.bool(4, is_exec);
                file_nodes.push(fn_writer.out);
            }
        }

        let mut dir_writer = Writer::default();
        for f in file_nodes {
            dir_writer.msg(1, &f);
        }
        for d in dir_nodes {
            dir_writer.msg(2, &d);
        }
        for s in symlink_nodes {
            dir_writer.msg(3, &s);
        }
        Ok(dir_writer.out)
    }

    fn encode_missing_blobs_operation(&self, op_name: &str, missing_hashes: &[String]) -> Vec<u8> {
        let mut pf = Writer::default();
        for h in missing_hashes {
            let mut v = Writer::default();
            v.str(1, "MISSING");
            v.str(2, &format!("blobs/{h}/0"));
            v.str(3, "Missing blob or invalidated host file");
            pf.msg(1, &v.out);
        }
        let mut any = Writer::default();
        any.str(1, "type.googleapis.com/google.rpc.PreconditionFailure");
        any.bytes(2, &pf.out);

        let status = encode_rpc_status(
            RPC_FAILED_PRECONDITION,
            "Missing required blobs or invalidated host files",
            &[any.out],
        );

        let mut exec_resp = Writer::default();
        exec_resp.msg(3, &status);
        encode_operation_done(op_name, &exec_resp.out)
    }

    #[allow(clippy::too_many_arguments)]
    fn run_subprocess(
        &self,
        cmd_proto: &ParsedCommand,
        slot_root: &Path,
        work_dir: &Path,
        timeout: Option<Duration>,
        allow_network: bool,
        writable_paths: &[String],
        tmpfs_paths: &[String],
        inaccessible_paths: &[String],
        cancelled: &Arc<AtomicBool>,
        active_pid: &Arc<AtomicI32>,
    ) -> std::io::Result<SubprocessResult> {
        if cmd_proto.arguments.is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Empty command arguments",
            ));
        }

        let mut command = if let Some(ref ls_bin) = self.options.linux_sandbox {
            let mut c = Command::new(ls_bin);
            c.arg("-W").arg(work_dir);
            c.arg("-w").arg(slot_root);
            if Path::new("/tmp").exists() {
                c.arg("-w").arg("/tmp");
            }
            if let Ok(dev_shm) = fs::canonicalize("/dev/shm") {
                c.arg("-w").arg(dev_shm);
            }
            for wp in writable_paths {
                let p = if wp.starts_with('/') { PathBuf::from(wp) } else { slot_root.join(wp) };
                let _ = fs::create_dir_all(&p);
                c.arg("-w").arg(p);
            }
            for tp in tmpfs_paths {
                if tp.starts_with('/') {
                    c.arg("-e").arg(tp);
                }
            }
            for ip in inaccessible_paths {
                let p = Path::new(ip);
                if p.exists() {
                    if p.is_dir() {
                        c.arg("-M").arg(&self.inaccessible_dir).arg("-m").arg(p);
                    } else {
                        c.arg("-M").arg(&self.inaccessible_file).arg("-m").arg(p);
                    }
                }
            }
            if !allow_network {
                c.arg("-N");
            }
            c.arg("--");
            for arg in &cmd_proto.arguments {
                c.arg(arg);
            }
            c
        } else {
            let mut c = Command::new(&cmd_proto.arguments[0]);
            for arg in &cmd_proto.arguments[1..] {
                c.arg(arg);
            }
            c
        };

        command
            .current_dir(work_dir)
            .env_clear()
            .envs(cmd_proto.env.iter().map(|(k, v)| (k.as_str(), v.as_str())))
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        {
            use std::os::unix::process::CommandExt;
            command.process_group(0);
        }

        let mut child = command.spawn()?;
        let pid = child.id() as libc::pid_t;
        active_pid.store(pid, Ordering::Release);
        if cancelled.load(Ordering::Acquire) {
            unsafe {
                libc::kill(-pid, libc::SIGKILL);
                libc::kill(pid, libc::SIGKILL);
            }
        }
        let mut stdout_pipe = child.stdout.take().unwrap();
        let mut stderr_pipe = child.stderr.take().unwrap();

        let start = Instant::now();
        let mut timed_out = false;
        let mut was_cancelled = false;
        let mut raw_status: libc::c_int = 0;
        let mut rusage: libc::rusage = unsafe { std::mem::zeroed() };

        let (stdout, stderr) = if let Some(limit) = timeout {
            let stdout_handle = std::thread::spawn(move || {
                let mut buf = Vec::new();
                let _ = stdout_pipe.read_to_end(&mut buf);
                buf
            });
            let stderr_handle = std::thread::spawn(move || {
                let mut buf = Vec::new();
                let _ = stderr_pipe.read_to_end(&mut buf);
                buf
            });
            loop {
                let waited =
                    unsafe { libc::wait4(pid, &mut raw_status, libc::WNOHANG, &mut rusage) };
                if waited == pid {
                    break;
                }
                if waited < 0 {
                    let err = std::io::Error::last_os_error();
                    if err.kind() != std::io::ErrorKind::Interrupted {
                        break;
                    }
                }
                if cancelled.load(Ordering::Acquire) {
                    was_cancelled = true;
                    unsafe {
                        libc::kill(-pid, libc::SIGKILL);
                        libc::kill(pid, libc::SIGKILL);
                        libc::wait4(pid, &mut raw_status, 0, &mut rusage);
                    }
                    break;
                }
                if start.elapsed() >= limit {
                    timed_out = true;
                    unsafe {
                        libc::kill(-pid, libc::SIGKILL);
                        libc::kill(pid, libc::SIGKILL);
                        libc::wait4(pid, &mut raw_status, 0, &mut rusage);
                    }
                    break;
                }
                std::thread::sleep(Duration::from_millis(2));
            }
            (
                stdout_handle.join().unwrap_or_default(),
                stderr_handle.join().unwrap_or_default(),
            )
        } else {
            // Common path (`timeout.is_none()`): read both stdout and stderr pipes on the current
            // RPC thread via `poll(2)` and block in `wait4(pid, ..., 0, ...)` with zero helper
            // threads.
            let (stdout_buf, stderr_buf) = read_two_pipes_to_end(stdout_pipe, stderr_pipe);
            loop {
                let waited = unsafe { libc::wait4(pid, &mut raw_status, 0, &mut rusage) };
                if waited == pid || waited >= 0 {
                    break;
                }
                let err = std::io::Error::last_os_error();
                if err.kind() != std::io::ErrorKind::Interrupted {
                    break;
                }
            }
            if cancelled.load(Ordering::Acquire) {
                was_cancelled = true;
            }
            (stdout_buf, stderr_buf)
        };
        active_pid.store(0, Ordering::Release);

        let exit_code = if timed_out {
            142
        } else if libc::WIFEXITED(raw_status) {
            libc::WEXITSTATUS(raw_status)
        } else if libc::WIFSIGNALED(raw_status) {
            128 + libc::WTERMSIG(raw_status)
        } else {
            1
        };

        let utime_us = (rusage.ru_utime.tv_sec as u64)
            .saturating_mul(1_000_000)
            .saturating_add(rusage.ru_utime.tv_usec as u64)
            .saturating_add(
                (rusage.ru_stime.tv_sec as u64)
                    .saturating_mul(1_000_000)
                    .saturating_add(rusage.ru_stime.tv_usec as u64),
            );
        let user_time = Duration::from_micros(utime_us.max(1_000));

        Ok(SubprocessResult { exit_code, stdout, stderr, timed_out, was_cancelled, user_time })
    }
}

struct SubprocessResult {
    exit_code: i32,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    timed_out: bool,
    was_cancelled: bool,
    user_time: Duration,
}

fn read_two_pipes_to_end(
    mut stdout_pipe: std::process::ChildStdout,
    mut stderr_pipe: std::process::ChildStderr,
) -> (Vec<u8>, Vec<u8>) {
    use std::os::unix::io::AsRawFd;
    let out_fd = stdout_pipe.as_raw_fd();
    let err_fd = stderr_pipe.as_raw_fd();
    let mut stdout_buf = Vec::new();
    let mut stderr_buf = Vec::new();
    let mut fds = [
        libc::pollfd { fd: out_fd, events: libc::POLLIN, revents: 0 },
        libc::pollfd { fd: err_fd, events: libc::POLLIN, revents: 0 },
    ];
    let mut tmp = [0u8; 8192];
    while fds[0].fd >= 0 || fds[1].fd >= 0 {
        let rc = unsafe { libc::poll(fds.as_mut_ptr(), 2, -1) };
        if rc < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            break;
        }
        if fds[0].fd >= 0
            && (fds[0].revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR)) != 0
        {
            match stdout_pipe.read(&mut tmp) {
                Ok(0) => fds[0].fd = -1,
                Ok(n) => stdout_buf.extend_from_slice(&tmp[..n]),
                Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(_) => fds[0].fd = -1,
            }
        } else if fds[0].fd >= 0 && (fds[0].revents & libc::POLLNVAL) != 0 {
            fds[0].fd = -1;
        }
        if fds[1].fd >= 0
            && (fds[1].revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR)) != 0
        {
            match stderr_pipe.read(&mut tmp) {
                Ok(0) => fds[1].fd = -1,
                Ok(n) => stderr_buf.extend_from_slice(&tmp[..n]),
                Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(_) => fds[1].fd = -1,
            }
        } else if fds[1].fd >= 0 && (fds[1].revents & libc::POLLNVAL) != 0 {
            fds[1].fd = -1;
        }
    }
    (stdout_buf, stderr_buf)
}

struct ParsedAction {
    command_digest: (String, u64),
    input_root_digest: (String, u64),
    timeout: Option<Duration>,
    platform_props: Vec<(String, String)>,
}

struct ParsedCommand {
    arguments: Vec<String>,
    env: Vec<(String, String)>,
    output_files: Vec<String>,
    output_directories: Vec<String>,
    output_paths: Vec<String>,
    platform_props: Vec<(String, String)>,
    working_directory: String,
}

fn parse_update_request(b: &[u8]) -> Option<(String, u64, Vec<u8>)> {
    let mut r = Reader::new(b);
    let mut dg = None;
    let mut data = Vec::new();
    while let Some((field, wire)) = r.next_key() {
        match (field, wire) {
            (1, 2) => dg = parse_digest(r.len_slice()?),
            (2, 2) => data = r.len_slice()?.to_vec(),
            (_, w) => r.skip(w),
        }
    }
    let (h, s) = dg?;
    Some((h, s, data))
}

fn parse_execute_request(b: &[u8]) -> Option<(String, u64)> {
    let mut r = Reader::new(b);
    let mut dg = None;
    while let Some((field, wire)) = r.next_key() {
        match (field, wire) {
            (6, 2) => dg = parse_digest(r.len_slice()?),
            (_, w) => r.skip(w),
        }
    }
    dg
}

fn parse_action(b: &[u8]) -> Option<ParsedAction> {
    let mut r = Reader::new(b);
    let mut command_digest = None;
    let mut input_root_digest = (String::new(), 0);
    let mut timeout = None;
    let mut platform_props = Vec::new();
    while let Some((field, wire)) = r.next_key() {
        match (field, wire) {
            (1, 2) => command_digest = parse_digest(r.len_slice()?),
            (2, 2) => {
                if let Some(d) = parse_digest(r.len_slice()?) {
                    input_root_digest = d;
                }
            }
            (6, 2) => timeout = parse_duration(r.len_slice()?),
            (10, 2) => parse_platform(r.len_slice()?, &mut platform_props),
            (_, w) => r.skip(w),
        }
    }
    Some(ParsedAction {
        command_digest: command_digest?,
        input_root_digest,
        timeout,
        platform_props,
    })
}

fn parse_command(b: &[u8]) -> Option<ParsedCommand> {
    let mut r = Reader::new(b);
    let mut cmd = ParsedCommand {
        arguments: Vec::new(),
        env: Vec::new(),
        output_files: Vec::new(),
        output_directories: Vec::new(),
        output_paths: Vec::new(),
        platform_props: Vec::new(),
        working_directory: String::new(),
    };
    while let Some((field, wire)) = r.next_key() {
        match (field, wire) {
            (1, 2) => cmd.arguments.push(string(r.len_slice()?)),
            (2, 2) => {
                if let Some(kv) = parse_map_entry(r.len_slice()?) {
                    cmd.env.push(kv);
                }
            }
            (3, 2) => cmd.output_files.push(string(r.len_slice()?)),
            (4, 2) => cmd.output_directories.push(string(r.len_slice()?)),
            (5, 2) => parse_platform(r.len_slice()?, &mut cmd.platform_props),
            (6, 2) => cmd.working_directory = string(r.len_slice()?),
            (7, 2) => cmd.output_paths.push(string(r.len_slice()?)),
            (_, w) => r.skip(w),
        }
    }
    Some(cmd)
}

fn parse_platform(b: &[u8], out: &mut Vec<(String, String)>) {
    let mut r = Reader::new(b);
    while let Some((field, wire)) = r.next_key() {
        match (field, wire) {
            (1, 2) => {
                if let Some(s) = r.len_slice() {
                    if let Some(kv) = parse_map_entry(s) {
                        out.push(kv);
                    }
                }
            }
            (_, w) => r.skip(w),
        }
    }
}

fn parse_duration(b: &[u8]) -> Option<Duration> {
    let mut r = Reader::new(b);
    let mut secs = 0u64;
    let mut nanos = 0u32;
    while let Some((field, wire)) = r.next_key() {
        match (field, wire) {
            (1, 0) => secs = r.varint(),
            (2, 0) => nanos = r.varint() as u32,
            (_, w) => r.skip(w),
        }
    }
    if secs == 0 && nanos == 0 {
        None
    } else {
        Some(Duration::new(secs, nanos))
    }
}

fn encode_digest(hash: &str, size: u64) -> Vec<u8> {
    let mut w = Writer::default();
    w.str(1, hash);
    w.uint(2, size);
    w.out
}

fn encode_rpc_status(code: u64, message: &str, details: &[Vec<u8>]) -> Vec<u8> {
    let mut w = Writer::default();
    if code != 0 {
        w.uint(1, code);
    }
    if !message.is_empty() {
        w.str(2, message);
    }
    for d in details {
        w.msg(3, d);
    }
    w.out
}

fn encode_operation_done(name: &str, execute_response_bytes: &[u8]) -> Vec<u8> {
    let mut any = Writer::default();
    any.str(1, "type.googleapis.com/build.bazel.remote.execution.v2.ExecuteResponse");
    any.bytes(2, execute_response_bytes);

    let mut op = Writer::default();
    op.str(1, name);
    op.bool(3, true); // done = true
    op.msg(5, &any.out); // response = Any(ExecuteResponse)
    op.out
}

fn encode_operation_error(name: &str, code: u64, message: &str) -> Vec<u8> {
    let mut op = Writer::default();
    op.str(1, name);
    op.bool(3, true); // done = true
    op.msg(4, &encode_rpc_status(code, message, &[])); // error = google.rpc.Status
    op.out
}
