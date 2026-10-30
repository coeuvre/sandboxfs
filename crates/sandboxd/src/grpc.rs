//! Minimal, dependency-free HTTP/2 cleartext (h2c) + gRPC server over Unix domain socket (`std`
//! only).
//!
//! Implements RFC 7540 HTTP/2 framing and RFC 7541 HPACK (static table, dynamic table, and
//! Appendix B canonical Huffman decoding) to serve REAPI v2 RPCs (`Capabilities`, `CAS`, and
//! `Execution`) to Bazel's `ReapiSandboxedSpawnRunner`.

use crate::reapi::ReapiState;
use rustc_hash::FxHashMap;
use std::collections::VecDeque;
use std::io::{self, Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;

const H2_PREFACE: &[u8; 24] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

const FRAME_DATA: u8 = 0x0;
const FRAME_HEADERS: u8 = 0x1;
const FRAME_RST_STREAM: u8 = 0x3;
const FRAME_SETTINGS: u8 = 0x4;
const FRAME_PING: u8 = 0x6;
const FRAME_GOAWAY: u8 = 0x7;
const FRAME_WINDOW_UPDATE: u8 = 0x8;
const FRAME_CONTINUATION: u8 = 0x9;

const FLAG_END_STREAM: u8 = 0x1;
const FLAG_ACK: u8 = 0x1;
const FLAG_END_HEADERS: u8 = 0x4;
const FLAG_PADDED: u8 = 0x8;
const FLAG_PRIORITY: u8 = 0x20;

const MAX_OUT_DATA_CHUNK: usize = 16_384;

pub fn serve_unix(socket_path: &Path, state: Arc<ReapiState>) -> io::Result<()> {
    let _ = std::fs::remove_file(socket_path);
    if let Some(parent) = socket_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let listener = UnixListener::bind(socket_path)?;
    for incoming in listener.incoming() {
        match incoming {
            Ok(stream) => {
                let st = state.clone();
                thread::spawn(move || {
                    let _ = handle_connection(stream, st);
                });
            }
            Err(e) => {
                eprintln!("sandboxfs grpc accept error: {e}");
            }
        }
    }
    Ok(())
}

struct StreamState {
    path: String,
    header_block: Vec<u8>,
    data: Vec<u8>,
    headers_done: bool,
    end_stream: bool,
    cancelled: Arc<AtomicBool>,
    active_pid: Arc<AtomicI32>,
    window_consumed: u32,
}

impl StreamState {
    fn new() -> Self {
        Self {
            path: String::new(),
            header_block: Vec::new(),
            data: Vec::new(),
            headers_done: false,
            end_stream: false,
            cancelled: Arc::new(AtomicBool::new(false)),
            active_pid: Arc::new(AtomicI32::new(0)),
            window_consumed: 0,
        }
    }

    fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
        let pid = self.active_pid.load(Ordering::Acquire);
        if pid > 0 {
            unsafe {
                libc::kill(-pid, libc::SIGKILL);
                libc::kill(pid, libc::SIGKILL);
            }
        }
    }
}

fn handle_connection(mut reader: UnixStream, state: Arc<ReapiState>) -> io::Result<()> {
    let writer = Arc::new(Mutex::new(reader.try_clone()?));

    let mut preface = [0u8; 24];
    reader.read_exact(&mut preface)?;
    if &preface != H2_PREFACE {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid HTTP/2 preface"));
    }

    // Send initial server SETTINGS:
    //   SETTINGS_INITIAL_WINDOW_SIZE (0x4) = 1_073_741_824
    //   SETTINGS_MAX_FRAME_SIZE (0x5)      = 16_777_215
    // Plus a connection-level WINDOW_UPDATE on stream 0.
    {
        let mut w = writer.lock().unwrap();
        let mut settings = Vec::with_capacity(12);
        settings.extend_from_slice(&4u16.to_be_bytes());
        settings.extend_from_slice(&1_073_741_824u32.to_be_bytes());
        settings.extend_from_slice(&5u16.to_be_bytes());
        settings.extend_from_slice(&16_777_215u32.to_be_bytes());
        write_frame(&mut *w, FRAME_SETTINGS, 0, 0, &settings)?;
        write_frame(&mut *w, FRAME_WINDOW_UPDATE, 0, 0, &1_073_741_824u32.to_be_bytes())?;
        w.flush()?;
    }

    let mut hpack = HpackDecoder::new();
    let mut streams: FxHashMap<u32, StreamState> = FxHashMap::default();
    let mut active_streams: FxHashMap<u32, (Arc<AtomicBool>, Arc<AtomicI32>)> =
        FxHashMap::default();
    let mut conn_window_consumed: u32 = 0;

    loop {
        let mut hdr = [0u8; 9];
        match reader.read_exact(&mut hdr) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e),
        }
        let len = ((hdr[0] as usize) << 16) | ((hdr[1] as usize) << 8) | (hdr[2] as usize);
        let ftype = hdr[3];
        let flags = hdr[4];
        let stream_id = u32::from_be_bytes([hdr[5] & 0x7f, hdr[6], hdr[7], hdr[8]]);

        let mut payload = vec![0u8; len];
        if len > 0 {
            reader.read_exact(&mut payload)?;
        }

        match ftype {
            FRAME_SETTINGS => {
                if flags & FLAG_ACK == 0 {
                    let mut w = writer.lock().unwrap();
                    write_frame(&mut *w, FRAME_SETTINGS, FLAG_ACK, 0, &[])?;
                    w.flush()?;
                }
            }
            FRAME_PING => {
                if flags & FLAG_ACK == 0 && payload.len() == 8 {
                    let mut w = writer.lock().unwrap();
                    write_frame(&mut *w, FRAME_PING, FLAG_ACK, 0, &payload)?;
                    w.flush()?;
                }
            }
            FRAME_GOAWAY => break,
            FRAME_RST_STREAM => {
                if let Some(st) = streams.remove(&stream_id) {
                    st.cancel();
                }
                if let Some((cancelled, active_pid)) = active_streams.remove(&stream_id) {
                    cancelled.store(true, Ordering::Release);
                    let pid = active_pid.load(Ordering::Acquire);
                    if pid > 0 {
                        unsafe {
                            libc::kill(-pid, libc::SIGKILL);
                            libc::kill(pid, libc::SIGKILL);
                        }
                    }
                }
            }
            FRAME_HEADERS => {
                let slice = strip_padding_and_priority(&payload, flags)?;
                let st = streams.entry(stream_id).or_insert_with(StreamState::new);
                st.header_block.extend_from_slice(slice);
                if flags & FLAG_END_STREAM != 0 {
                    st.end_stream = true;
                }
                if flags & FLAG_END_HEADERS != 0 {
                    for (k, v) in hpack.decode(&st.header_block) {
                        if k == ":path" {
                            st.path = v;
                        }
                    }
                    st.header_block.clear();
                    st.headers_done = true;
                    if st.end_stream {
                        if let Some(done_st) = streams.remove(&stream_id) {
                            active_streams.insert(
                                stream_id,
                                (done_st.cancelled.clone(), done_st.active_pid.clone()),
                            );
                            dispatch_rpc(stream_id, done_st, state.clone(), writer.clone());
                        }
                    }
                }
            }
            FRAME_CONTINUATION => {
                if let Some(st) = streams.get_mut(&stream_id) {
                    st.header_block.extend_from_slice(&payload);
                    if flags & FLAG_END_HEADERS != 0 {
                        for (k, v) in hpack.decode(&st.header_block) {
                            if k == ":path" {
                                st.path = v;
                            }
                        }
                        st.header_block.clear();
                        st.headers_done = true;
                        if st.end_stream {
                            if let Some(done_st) = streams.remove(&stream_id) {
                                active_streams.insert(
                                    stream_id,
                                    (done_st.cancelled.clone(), done_st.active_pid.clone()),
                                );
                                dispatch_rpc(stream_id, done_st, state.clone(), writer.clone());
                            }
                        }
                    }
                }
            }
            FRAME_DATA => {
                let inc = (payload.len() as u32) & 0x7fff_ffff;
                conn_window_consumed = conn_window_consumed.saturating_add(inc);
                let slice = strip_padding_and_priority(&payload, flags & FLAG_PADDED)?;
                let mut stream_window_update = 0u32;
                if let Some(st) = streams.get_mut(&stream_id) {
                    st.window_consumed = st.window_consumed.saturating_add(inc);
                    if st.window_consumed >= 16 * 1024 * 1024 && flags & FLAG_END_STREAM == 0 {
                        stream_window_update = st.window_consumed;
                        st.window_consumed = 0;
                    }
                    st.data.extend_from_slice(slice);
                    if flags & FLAG_END_STREAM != 0 {
                        st.end_stream = true;
                        if st.headers_done {
                            if let Some(done_st) = streams.remove(&stream_id) {
                                active_streams.insert(
                                    stream_id,
                                    (done_st.cancelled.clone(), done_st.active_pid.clone()),
                                );
                                dispatch_rpc(stream_id, done_st, state.clone(), writer.clone());
                            }
                        }
                    }
                }
                if conn_window_consumed >= 16 * 1024 * 1024 || stream_window_update > 0 {
                    let mut w = writer.lock().unwrap();
                    if conn_window_consumed >= 16 * 1024 * 1024 {
                        let inc_bytes = (conn_window_consumed & 0x7fff_ffff).to_be_bytes();
                        let _ = write_frame(&mut *w, FRAME_WINDOW_UPDATE, 0, 0, &inc_bytes);
                        conn_window_consumed = 0;
                    }
                    if stream_window_update > 0 && stream_id != 0 {
                        let inc_bytes = (stream_window_update & 0x7fff_ffff).to_be_bytes();
                        let _ = write_frame(&mut *w, FRAME_WINDOW_UPDATE, 0, stream_id, &inc_bytes);
                    }
                    let _ = w.flush();
                }
            }
            _ => {}
        }
    }
    for (_, st) in streams {
        st.cancel();
    }
    for (_, (cancelled, active_pid)) in active_streams {
        cancelled.store(true, Ordering::Release);
        let pid = active_pid.load(Ordering::Acquire);
        if pid > 0 {
            unsafe {
                libc::kill(-pid, libc::SIGKILL);
                libc::kill(pid, libc::SIGKILL);
            }
        }
    }
    Ok(())
}

fn strip_padding_and_priority(payload: &[u8], flags: u8) -> io::Result<&[u8]> {
    let mut start = 0usize;
    let mut end = payload.len();
    if flags & FLAG_PADDED != 0 {
        if payload.is_empty() {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "empty padded frame"));
        }
        let pad_len = payload[0] as usize;
        start += 1;
        if start + pad_len > end {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid frame padding"));
        }
        end -= pad_len;
    }
    if flags & FLAG_PRIORITY != 0 {
        if start + 5 > end {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid priority header"));
        }
        start += 5;
    }
    Ok(&payload[start..end])
}

fn dispatch_rpc(
    stream_id: u32,
    st: StreamState,
    state: Arc<ReapiState>,
    writer: Arc<Mutex<UnixStream>>,
) {
    thread::spawn(move || {
        // Parse gRPC length-prefixed frame: 1 byte compressed flag + 4 byte big-endian length.
        let req_msg = if st.data.len() >= 5 {
            let msg_len =
                u32::from_be_bytes([st.data[1], st.data[2], st.data[3], st.data[4]]) as usize;
            let end = (5 + msg_len).min(st.data.len());
            &st.data[5..end]
        } else {
            &[][..]
        };

        let (grpc_status, resp_msg) = match st.path.as_str() {
            "/build.bazel.remote.execution.v2.Capabilities/GetCapabilities" => {
                (0u8, Some(state.handle_get_capabilities()))
            }
            "/build.bazel.remote.execution.v2.ContentAddressableStorage/FindMissingBlobs" => {
                (0u8, Some(state.handle_find_missing_blobs(req_msg)))
            }
            "/build.bazel.remote.execution.v2.ContentAddressableStorage/BatchUpdateBlobs" => {
                (0u8, Some(state.handle_batch_update_blobs(req_msg)))
            }
            "/build.bazel.remote.execution.v2.ContentAddressableStorage/BatchReadBlobs" => {
                (0u8, Some(state.handle_batch_read_blobs(req_msg)))
            }
            "/build.bazel.remote.execution.v2.Execution/Execute" => {
                let out = state.handle_execute(
                    req_msg,
                    st.cancelled.clone(),
                    st.active_pid.clone(),
                );
                if st.cancelled.load(Ordering::Acquire) {
                    return;
                }
                (0u8, Some(out))
            }
            _ => (12u8, None), // UNIMPLEMENTED (12)
        };

        let mut w = writer.lock().unwrap();
        // Initial HEADERS: `:status: 200` (0x88) + `content-type: application/grpc`
        let mut resp_hdr = vec![0x88];
        encode_literal_header(&mut resp_hdr, "content-type", "application/grpc");
        if write_frame(&mut *w, FRAME_HEADERS, FLAG_END_HEADERS, stream_id, &resp_hdr).is_err() {
            return;
        }

        if let Some(body) = resp_msg {
            let mut framed = Vec::with_capacity(5 + body.len());
            framed.push(0u8); // uncompressed
            framed.extend_from_slice(&(body.len() as u32).to_be_bytes());
            framed.extend_from_slice(&body);

            if framed.is_empty() {
                let _ = write_frame(&mut *w, FRAME_DATA, 0, stream_id, &[]);
            } else {
                for chunk in framed.chunks(MAX_OUT_DATA_CHUNK) {
                    if write_frame(&mut *w, FRAME_DATA, 0, stream_id, chunk).is_err() {
                        return;
                    }
                }
            }
        }

        // Trailers: `grpc-status: <code_str>` with END_STREAM | END_HEADERS
        let mut trailers = Vec::new();
        encode_literal_header(&mut trailers, "grpc-status", &grpc_status.to_string());
        let _ = write_frame(
            &mut *w,
            FRAME_HEADERS,
            FLAG_END_STREAM | FLAG_END_HEADERS,
            stream_id,
            &trailers,
        );
        let _ = w.flush();
    });
}

fn write_frame<W: Write>(
    w: &mut W,
    ftype: u8,
    flags: u8,
    stream_id: u32,
    payload: &[u8],
) -> io::Result<()> {
    let len = payload.len();
    let sid = (stream_id & 0x7fff_ffff).to_be_bytes();
    let hdr = [
        ((len >> 16) & 0xff) as u8,
        ((len >> 8) & 0xff) as u8,
        (len & 0xff) as u8,
        ftype,
        flags,
        sid[0],
        sid[1],
        sid[2],
        sid[3],
    ];
    w.write_all(&hdr)?;
    if !payload.is_empty() {
        w.write_all(payload)?;
    }
    Ok(())
}

fn encode_literal_header(out: &mut Vec<u8>, name: &str, value: &str) {
    out.push(0x00); // literal header field without indexing — new name
    encode_hpack_int(out, 0, 7, name.len());
    out.extend_from_slice(name.as_bytes());
    encode_hpack_int(out, 0, 7, value.len());
    out.extend_from_slice(value.as_bytes());
}

fn encode_hpack_int(out: &mut Vec<u8>, first_mask: u8, prefix_bits: u8, mut val: usize) {
    let max_prefix = (1usize << prefix_bits) - 1;
    if val < max_prefix {
        out.push(first_mask | (val as u8));
    } else {
        out.push(first_mask | (max_prefix as u8));
        val -= max_prefix;
        while val >= 128 {
            out.push(((val & 0x7f) as u8) | 0x80);
            val >>= 7;
        }
        out.push(val as u8);
    }
}

/// RFC 7541 HPACK decoder with static + dynamic tables and canonical Huffman decoding.
struct HpackDecoder {
    dynamic: VecDeque<(String, String)>,
    dynamic_size: usize,
    max_size: usize,
}

impl HpackDecoder {
    fn new() -> Self {
        Self { dynamic: VecDeque::new(), dynamic_size: 0, max_size: 4096 }
    }

    fn decode(&mut self, block: &[u8]) -> Vec<(String, String)> {
        let mut out = Vec::new();
        let mut pos = 0usize;
        while pos < block.len() {
            let b = block[pos];
            if b & 0x80 != 0 {
                // 6.1 Indexed Header Field Representation (prefix 7)
                let Some(idx) = decode_hpack_int(block, &mut pos, 7) else { break };
                if let Some(kv) = self.get_index(idx) {
                    out.push(kv);
                }
            } else if b & 0xc0 == 0x40 {
                // 6.2.1 Literal Header Field with Incremental Indexing (prefix 6)
                let Some(name_idx) = decode_hpack_int(block, &mut pos, 6) else { break };
                let name = if name_idx > 0 {
                    self.get_index(name_idx).map(|(k, _)| k).unwrap_or_default()
                } else {
                    let Some(s) = decode_hpack_str(block, &mut pos) else { break };
                    s
                };
                let Some(val) = decode_hpack_str(block, &mut pos) else { break };
                self.insert_dynamic(name.clone(), val.clone());
                out.push((name, val));
            } else if b & 0xe0 == 0x20 {
                // 6.3 Dynamic Table Size Update (prefix 5)
                let Some(new_max) = decode_hpack_int(block, &mut pos, 5) else { break };
                self.max_size = new_max;
                self.evict_to_max();
            } else {
                // 6.2.2 / 6.2.3 Literal Header Field without Indexing / Never Indexed (prefix 4)
                let Some(name_idx) = decode_hpack_int(block, &mut pos, 4) else { break };
                let name = if name_idx > 0 {
                    self.get_index(name_idx).map(|(k, _)| k).unwrap_or_default()
                } else {
                    let Some(s) = decode_hpack_str(block, &mut pos) else { break };
                    s
                };
                let Some(val) = decode_hpack_str(block, &mut pos) else { break };
                out.push((name, val));
            }
        }
        out
    }

    fn get_index(&self, idx: usize) -> Option<(String, String)> {
        if idx == 0 {
            return None;
        }
        if idx <= STATIC_TABLE.len() {
            let (k, v) = STATIC_TABLE[idx - 1];
            return Some((k.to_string(), v.to_string()));
        }
        let dyn_idx = idx - STATIC_TABLE.len() - 1;
        self.dynamic.get(dyn_idx).cloned()
    }

    fn insert_dynamic(&mut self, name: String, value: String) {
        let entry_size = name.len() + value.len() + 32;
        if entry_size > self.max_size {
            self.dynamic.clear();
            self.dynamic_size = 0;
            return;
        }
        self.dynamic.push_front((name, value));
        self.dynamic_size += entry_size;
        self.evict_to_max();
    }

    fn evict_to_max(&mut self) {
        while self.dynamic_size > self.max_size {
            if let Some((k, v)) = self.dynamic.pop_back() {
                self.dynamic_size = self.dynamic_size.saturating_sub(k.len() + v.len() + 32);
            } else {
                break;
            }
        }
    }
}

fn decode_hpack_int(buf: &[u8], pos: &mut usize, prefix_bits: u8) -> Option<usize> {
    if *pos >= buf.len() {
        return None;
    }
    let mask = (1usize << prefix_bits) - 1;
    let mut val = (buf[*pos] as usize) & mask;
    *pos += 1;
    if val < mask {
        return Some(val);
    }
    let mut shift = 0usize;
    loop {
        if *pos >= buf.len() {
            return None;
        }
        let b = buf[*pos] as usize;
        *pos += 1;
        val = val.checked_add((b & 0x7f).checked_shl(shift as u32)?)?;
        if b & 0x80 == 0 {
            return Some(val);
        }
        shift += 7;
        if shift > 56 {
            return None;
        }
    }
}

fn decode_hpack_str(buf: &[u8], pos: &mut usize) -> Option<String> {
    if *pos >= buf.len() {
        return None;
    }
    let huffman = (buf[*pos] & 0x80) != 0;
    let len = decode_hpack_int(buf, pos, 7)?;
    if *pos + len > buf.len() {
        return None;
    }
    let raw = &buf[*pos..*pos + len];
    *pos += len;
    if huffman {
        let decoded = huffman_decode(raw)?;
        Some(String::from_utf8_lossy(&decoded).into_owned())
    } else {
        Some(String::from_utf8_lossy(raw).into_owned())
    }
}

/// RFC 7541 Appendix A Static Table (indices 1..=61).
const STATIC_TABLE: [(&str, &str); 61] = [
    (":authority", ""),
    (":method", "GET"),
    (":method", "POST"),
    (":path", "/"),
    (":path", "/index.html"),
    (":scheme", "http"),
    (":scheme", "https"),
    (":status", "200"),
    (":status", "204"),
    (":status", "206"),
    (":status", "304"),
    (":status", "400"),
    (":status", "404"),
    (":status", "500"),
    ("accept-charset", ""),
    ("accept-encoding", "gzip, deflate"),
    ("accept-language", ""),
    ("accept-ranges", ""),
    ("accept", ""),
    ("access-control-allow-origin", ""),
    ("age", ""),
    ("allow", ""),
    ("authorization", ""),
    ("cache-control", ""),
    ("content-disposition", ""),
    ("content-encoding", ""),
    ("content-language", ""),
    ("content-length", ""),
    ("content-location", ""),
    ("content-range", ""),
    ("content-type", ""),
    ("cookie", ""),
    ("date", ""),
    ("etag", ""),
    ("expect", ""),
    ("expires", ""),
    ("from", ""),
    ("host", ""),
    ("if-match", ""),
    ("if-modified-since", ""),
    ("if-none-match", ""),
    ("if-range", ""),
    ("if-unmodified-since", ""),
    ("last-modified", ""),
    ("link", ""),
    ("location", ""),
    ("max-forwards", ""),
    ("proxy-authenticate", ""),
    ("proxy-authorization", ""),
    ("range", ""),
    ("referer", ""),
    ("refresh", ""),
    ("retry-after", ""),
    ("server", ""),
    ("set-cookie", ""),
    ("strict-transport-security", ""),
    ("transfer-encoding", ""),
    ("user-agent", ""),
    ("vary", ""),
    ("via", ""),
    ("www-authenticate", ""),
];

/// RFC 7541 Appendix B Huffman Code Table (code, bit_len) for symbols 0..=256.
const HUFFMAN_CODES: [(u32, u8); 257] = [
    (0x1ff8, 13),
    (0x7fffd8, 23),
    (0xfffffe2, 28),
    (0xfffffe3, 28),
    (0xfffffe4, 28),
    (0xfffffe5, 28),
    (0xfffffe6, 28),
    (0xfffffe7, 28),
    (0xfffffe8, 28),
    (0xffffea, 24),
    (0x3ffffffc, 30),
    (0xfffffe9, 28),
    (0xfffffea, 28),
    (0x3ffffffd, 30),
    (0xfffffeb, 28),
    (0xfffffec, 28),
    (0xfffffed, 28),
    (0xfffffee, 28),
    (0xfffffef, 28),
    (0xffffff0, 28),
    (0xffffff1, 28),
    (0xffffff2, 28),
    (0x3ffffffe, 30),
    (0xffffff3, 28),
    (0xffffff4, 28),
    (0xffffff5, 28),
    (0xffffff6, 28),
    (0xffffff7, 28),
    (0xffffff8, 28),
    (0xffffff9, 28),
    (0xffffffa, 28),
    (0xffffffb, 28),
    (0x14, 6),
    (0x3f8, 10),
    (0x3f9, 10),
    (0xffa, 12),
    (0x1ff9, 13),
    (0x15, 6),
    (0xf8, 8),
    (0x7fa, 11),
    (0x3fa, 10),
    (0x3fb, 10),
    (0xf9, 8),
    (0x7fb, 11),
    (0xfa, 8),
    (0x16, 6),
    (0x17, 6),
    (0x18, 6),
    (0x0, 5),
    (0x1, 5),
    (0x2, 5),
    (0x19, 6),
    (0x1a, 6),
    (0x1b, 6),
    (0x1c, 6),
    (0x1d, 6),
    (0x1e, 6),
    (0x1f, 6),
    (0x5c, 7),
    (0xfb, 8),
    (0x7ffc, 15),
    (0x20, 6),
    (0xffb, 12),
    (0x3fc, 10),
    (0x1ffa, 13),
    (0x21, 6),
    (0x5d, 7),
    (0x5e, 7),
    (0x5f, 7),
    (0x60, 7),
    (0x61, 7),
    (0x62, 7),
    (0x63, 7),
    (0x64, 7),
    (0x65, 7),
    (0x66, 7),
    (0x67, 7),
    (0x68, 7),
    (0x69, 7),
    (0x6a, 7),
    (0x6b, 7),
    (0x6c, 7),
    (0x6d, 7),
    (0x6e, 7),
    (0x6f, 7),
    (0x70, 7),
    (0x71, 7),
    (0x72, 7),
    (0xfc, 8),
    (0x73, 7),
    (0xfd, 8),
    (0x1ffb, 13),
    (0x7fff0, 19),
    (0x1ffc, 13),
    (0x3ffc, 14),
    (0x22, 6),
    (0x7ffd, 15),
    (0x3, 5),
    (0x23, 6),
    (0x4, 5),
    (0x24, 6),
    (0x5, 5),
    (0x25, 6),
    (0x26, 6),
    (0x27, 6),
    (0x6, 5),
    (0x74, 7),
    (0x75, 7),
    (0x28, 6),
    (0x29, 6),
    (0x2a, 6),
    (0x7, 5),
    (0x2b, 6),
    (0x76, 7),
    (0x2c, 6),
    (0x8, 5),
    (0x9, 5),
    (0x2d, 6),
    (0x77, 7),
    (0x78, 7),
    (0x79, 7),
    (0x7a, 7),
    (0x7b, 7),
    (0x7ffe, 15),
    (0x7fc, 11),
    (0x3ffd, 14),
    (0x1ffd, 13),
    (0xffffffc, 28),
    (0xfffe6, 20),
    (0x3fffd2, 22),
    (0xfffe7, 20),
    (0xfffe8, 20),
    (0x3fffd3, 22),
    (0x3fffd4, 22),
    (0x3fffd5, 22),
    (0x7fffd9, 23),
    (0x3fffd6, 22),
    (0x7fffda, 23),
    (0x7fffdb, 23),
    (0x7fffdc, 23),
    (0x7fffdd, 23),
    (0x7fffde, 23),
    (0xffffeb, 24),
    (0x7fffdf, 23),
    (0xffffec, 24),
    (0xffffed, 24),
    (0x3fffd7, 22),
    (0x7fffe0, 23),
    (0xffffee, 24),
    (0x7fffe1, 23),
    (0x7fffe2, 23),
    (0x7fffe3, 23),
    (0x7fffe4, 23),
    (0x1fffdc, 21),
    (0x3fffd8, 22),
    (0x7fffe5, 23),
    (0x3fffd9, 22),
    (0x7fffe6, 23),
    (0x7fffe7, 23),
    (0xffffef, 24),
    (0x3fffda, 22),
    (0x1fffdd, 21),
    (0xfffe9, 20),
    (0x3fffdb, 22),
    (0x3fffdc, 22),
    (0x7fffe8, 23),
    (0x7fffe9, 23),
    (0x1fffde, 21),
    (0x7fffea, 23),
    (0x3fffdd, 22),
    (0x3fffde, 22),
    (0xfffff0, 24),
    (0x1fffdf, 21),
    (0x3fffdf, 22),
    (0x7fffeb, 23),
    (0x7fffec, 23),
    (0x1fffe0, 21),
    (0x1fffe1, 21),
    (0x3fffe0, 22),
    (0x1fffe2, 21),
    (0x7fffed, 23),
    (0x3fffe1, 22),
    (0x7fffee, 23),
    (0x7fffef, 23),
    (0xfffea, 20),
    (0x3fffe2, 22),
    (0x3fffe3, 22),
    (0x3fffe4, 22),
    (0x7ffff0, 23),
    (0x3fffe5, 22),
    (0x3fffe6, 22),
    (0x7ffff1, 23),
    (0x3ffffe0, 26),
    (0x3ffffe1, 26),
    (0xfffeb, 20),
    (0x7fff1, 19),
    (0x3fffe7, 22),
    (0x7ffff2, 23),
    (0x3fffe8, 22),
    (0x1ffffec, 25),
    (0x3ffffe2, 26),
    (0x3ffffe3, 26),
    (0x3ffffe4, 26),
    (0x7ffffde, 27),
    (0x7ffffdf, 27),
    (0x3ffffe5, 26),
    (0xfffff1, 24),
    (0x1ffffed, 25),
    (0x7fff2, 19),
    (0x1fffe3, 21),
    (0x3ffffe6, 26),
    (0x7ffffe0, 27),
    (0x7ffffe1, 27),
    (0x3ffffe7, 26),
    (0x7ffffe2, 27),
    (0xfffff2, 24),
    (0x1fffe4, 21),
    (0x1fffe5, 21),
    (0x3ffffe8, 26),
    (0x3ffffe9, 26),
    (0xffffffd, 28),
    (0x7ffffe3, 27),
    (0x7ffffe4, 27),
    (0x7ffffe5, 27),
    (0xfffec, 20),
    (0xfffff3, 24),
    (0xfffed, 20),
    (0x1fffe6, 21),
    (0x3fffe9, 22),
    (0x1fffe7, 21),
    (0x1fffe8, 21),
    (0x7ffff3, 23),
    (0x3fffea, 22),
    (0x3fffeb, 22),
    (0x1ffffee, 25),
    (0x1ffffef, 25),
    (0xfffff4, 24),
    (0xfffff5, 24),
    (0x3ffffea, 26),
    (0x7ffff4, 23),
    (0x3ffffeb, 26),
    (0x7ffffe6, 27),
    (0x3ffffec, 26),
    (0x3ffffed, 26),
    (0x7ffffe7, 27),
    (0x7ffffe8, 27),
    (0x7ffffe9, 27),
    (0x7ffffea, 27),
    (0x7ffffeb, 27),
    (0xffffffe, 28),
    (0x7ffffec, 27),
    (0x7ffffed, 27),
    (0x7ffffee, 27),
    (0x7ffffef, 27),
    (0x7fffff0, 27),
    (0x3ffffee, 26),
    (0x3fffffff, 30),
];

fn huffman_decode(bytes: &[u8]) -> Option<Vec<u8>> {
    // Build a binary trie once (lazy via OnceLock).
    use std::sync::OnceLock;
    static TRIE: OnceLock<Vec<[i32; 2]>> = OnceLock::new();
    let trie = TRIE.get_or_init(|| {
        let mut nodes = vec![[-1i32, -1i32]];
        for (sym, &(code, len)) in HUFFMAN_CODES.iter().enumerate() {
            let mut cur = 0usize;
            for bit_idx in (0..len).rev() {
                let bit = ((code >> bit_idx) & 1) as usize;
                if bit_idx == 0 {
                    nodes[cur][bit] = -1000 - (sym as i32);
                } else {
                    let next = nodes[cur][bit];
                    if next < 0 {
                        let new_idx = nodes.len();
                        nodes.push([-1, -1]);
                        nodes[cur][bit] = new_idx as i32;
                        cur = new_idx;
                    } else {
                        cur = next as usize;
                    }
                }
            }
        }
        nodes
    });

    let mut out = Vec::with_capacity(bytes.len() * 2);
    let mut cur = 0usize;
    for &b in bytes {
        for bit_idx in (0..8).rev() {
            let bit = ((b >> bit_idx) & 1) as usize;
            let next = trie[cur][bit];
            if next <= -1000 {
                let sym = (-next - 1000) as usize;
                if sym == 256 {
                    return Some(out);
                }
                out.push(sym as u8);
                cur = 0;
            } else if next >= 0 {
                cur = next as usize;
            } else {
                return None;
            }
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hpack_decodes_indexed_and_huffman_headers() {
        let mut dec = HpackDecoder::new();
        // 0x83 = :method: POST, 0x86 = :scheme: http, plus literal :path with Huffman for
        // "www.example.com" From RFC 7541 C.4.1: f1e3 c2e5 f23a 6ba0 ab90 f4ff =
        // "www.example.com" (12 bytes, huffman bit 0x8c)
        let block = [
            0x83, 0x86, 0x44, // literal with incremental indexing, name index 4 (:path)
            0x8c, 0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff,
        ];
        let headers = dec.decode(&block);
        assert_eq!(
            headers,
            vec![
                (":method".to_string(), "POST".to_string()),
                (":scheme".to_string(), "http".to_string()),
                (":path".to_string(), "www.example.com".to_string()),
            ]
        );
        // Dynamic table entry 62 should now be (:path, www.example.com)
        let headers2 = dec.decode(&[0xbe]); // 0x80 | 62 = 0xbe
        assert_eq!(headers2, vec![(":path".to_string(), "www.example.com".to_string())]);
    }
}
