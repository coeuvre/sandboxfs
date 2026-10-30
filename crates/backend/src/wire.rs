// proto3 wire primitives: the reader/writer every codec in this crate is built from, plus the two
// leaf messages (`Digest`, map entries) that appear in all of them.

/// SHA-256 via the platform's CommonCrypto on macOS (native; no crate, no hand-rolled crypto), or
/// portable streaming SHA-256 elsewhere.
#[cfg(target_os = "macos")]
mod cc {
    extern "C" {
        pub fn CC_SHA256(data: *const u8, len: u32, md: *mut u8) -> *mut u8;
    }
}

#[cfg(target_os = "macos")]
pub fn sha256_bytes(b: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    unsafe { cc::CC_SHA256(b.as_ptr(), b.len() as u32, out.as_mut_ptr()) };
    out
}

#[cfg(not(target_os = "macos"))]
#[derive(Clone)]
pub struct Sha256 {
    h: [u32; 8],
    tail: [u8; 64],
    tail_len: usize,
    total_len: u64,
}

#[cfg(not(target_os = "macos"))]
impl Default for Sha256 {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(not(target_os = "macos"))]
impl Sha256 {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];

    pub fn new() -> Self {
        Self {
            h: [
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c,
                0x1f83d9ab, 0x5be0cd19,
            ],
            tail: [0u8; 64],
            tail_len: 0,
            total_len: 0,
        }
    }

    #[inline]
    fn compress_block(h: &mut [u32; 8], chunk: &[u8; 64]) {
        let mut w = [0u32; 64];
        for (i, word) in chunk.chunks_exact(4).enumerate() {
            w[i] = u32::from_be_bytes([word[0], word[1], word[2], word[3]]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16].wrapping_add(s0).wrapping_add(w[i - 7]).wrapping_add(s1);
        }
        let [mut a, mut b0, mut c, mut d, mut e, mut f, mut g, mut hh] = *h;
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 =
                hh.wrapping_add(s1).wrapping_add(ch).wrapping_add(Self::K[i]).wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b0) ^ (a & c) ^ (b0 & c);
            let temp2 = s0.wrapping_add(maj);

            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b0;
            b0 = a;
            a = temp1.wrapping_add(temp2);
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b0);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }

    pub fn update(&mut self, mut data: &[u8]) {
        self.total_len += data.len() as u64;
        if self.tail_len > 0 {
            let need = 64 - self.tail_len;
            if data.len() < need {
                self.tail[self.tail_len..self.tail_len + data.len()].copy_from_slice(data);
                self.tail_len += data.len();
                return;
            }
            self.tail[self.tail_len..64].copy_from_slice(&data[..need]);
            Self::compress_block(&mut self.h, &self.tail);
            self.tail_len = 0;
            data = &data[need..];
        }
        let mut chunks = data.chunks_exact(64);
        for chunk in &mut chunks {
            Self::compress_block(&mut self.h, chunk.try_into().unwrap());
        }
        let rem = chunks.remainder();
        if !rem.is_empty() {
            self.tail[..rem.len()].copy_from_slice(rem);
            self.tail_len = rem.len();
        }
    }

    pub fn finalize(mut self) -> [u8; 32] {
        let bit_len = self.total_len * 8;
        self.tail[self.tail_len] = 0x80;
        self.tail_len += 1;
        if self.tail_len > 56 {
            self.tail[self.tail_len..64].fill(0);
            Self::compress_block(&mut self.h, &self.tail);
            self.tail_len = 0;
        }
        self.tail[self.tail_len..56].fill(0);
        self.tail[56..64].copy_from_slice(&bit_len.to_be_bytes());
        Self::compress_block(&mut self.h, &self.tail);

        let mut out = [0u8; 32];
        for (i, word) in self.h.iter().enumerate() {
            out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
        }
        out
    }
}

#[cfg(not(target_os = "macos"))]
pub fn sha256_bytes(b: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b);
    hasher.finalize()
}

pub fn sha256_file(path: &std::path::Path) -> std::io::Result<(String, u64)> {
    use std::io::Read;
    let mut file = std::fs::File::open(path)?;
    #[cfg(not(target_os = "macos"))]
    {
        let mut hasher = Sha256::new();
        let mut buf = [0u8; 65536];
        loop {
            let n = file.read(&mut buf)?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
        }
        let size = hasher.total_len;
        Ok((hex_of(&hasher.finalize()), size))
    }
    #[cfg(target_os = "macos")]
    {
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)?;
        let size = bytes.len() as u64;
        Ok((sha256_hex(&bytes), size))
    }
}

pub fn sha256_hex(b: &[u8]) -> String {
    hex_of(&sha256_bytes(b))
}

pub fn hex_of(b: &[u8]) -> String {
    const D: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(b.len() * 2);
    for &x in b {
        s.push(D[(x >> 4) as usize] as char);
        s.push(D[(x & 0xf) as usize] as char);
    }
    s
}

pub struct Reader<'a> {
    pub(crate) b: &'a [u8],
    pub(crate) i: usize,
    /// False once a frame turned out to be truncated or malformed. A parser drives the loop with
    /// `next_key` and checks this once at the end.
    pub ok: bool,
}

impl<'a> Reader<'a> {
    pub fn new(b: &'a [u8]) -> Self {
        Reader { b, i: 0, ok: true }
    }

    pub fn varint(&mut self) -> u64 {
        let mut shift = 0u64;
        let mut v = 0u64;
        while self.i < self.b.len() {
            let byte = self.b[self.i];
            self.i += 1;
            v |= ((byte & 0x7f) as u64) << shift;
            if byte & 0x80 == 0 {
                return v;
            }
            shift += 7;
            if shift > 63 {
                break;
            }
        }
        self.ok = false;
        0
    }

    /// Length-delimited payload slice; None (and ok=false) on truncation.
    pub fn len_slice(&mut self) -> Option<&'a [u8]> {
        let n = self.varint() as usize;
        if !self.ok || self.b.len().checked_sub(self.i).map_or(true, |rem| rem < n) {
            self.ok = false;
            return None;
        }
        let s = &self.b[self.i..self.i + n];
        self.i += n;
        Some(s)
    }

    /// The next (field number, wire type), or None at the end of the frame -- and on a malformed
    /// one, which is why a parser checks `ok` once at the end instead of after every field.
    pub fn next_key(&mut self) -> Option<(u64, u64)> {
        if !self.ok || self.i >= self.b.len() {
            return None;
        }
        let key = self.varint();
        self.ok.then(|| (key >> 3, key & 7))
    }

    /// The next varint in a packed field, or None at the end / on a malformed one.
    pub fn next_varint(&mut self) -> Option<u64> {
        if !self.ok || self.i >= self.b.len() {
            return None;
        }
        let v = self.varint();
        self.ok.then_some(v)
    }

    pub fn skip(&mut self, wire: u64) {
        match wire {
            0 => {
                self.varint();
            }
            1 => {
                self.i += 8;
                if self.i > self.b.len() {
                    self.ok = false;
                }
            }
            2 => {
                self.len_slice();
            }
            5 => {
                self.i += 4;
                if self.i > self.b.len() {
                    self.ok = false;
                }
            }
            _ => self.ok = false,
        }
    }
}

pub fn string(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

/// `Digest{ string hash = 1; int64 size_bytes = 2; }`.
pub fn parse_digest(b: &[u8]) -> Option<(String, u64)> {
    let (mut hash, mut size) = (String::new(), 0u64);
    let mut r = Reader::new(b);
    while let Some((field, wire)) = r.next_key() {
        match (field, wire) {
            (1, 2) => hash = string(r.len_slice()?),
            (2, 0) => size = r.varint(),
            (_, w) => r.skip(w),
        }
    }
    r.ok.then_some((hash, size))
}

/// Just the hash half, for the many callers that ignore size.
pub fn digest_hash(b: &[u8]) -> Option<String> {
    parse_digest(b).map(|(h, _)| h)
}

/// `map<string, string>` entry: {1: key, 2: value}. Also the shape of any two-string message.
pub fn parse_map_entry(b: &[u8]) -> Option<(String, String)> {
    let (mut k, mut v) = (String::new(), String::new());
    let mut r = Reader::new(b);
    while let Some((field, wire)) = r.next_key() {
        match (field, wire) {
            (1, 2) => k = string(r.len_slice()?),
            (2, 2) => v = string(r.len_slice()?),
            (_, w) => r.skip(w),
        }
    }
    r.ok.then_some((k, v))
}

#[derive(Default)]
pub struct Writer {
    pub out: Vec<u8>,
}

impl Writer {
    pub fn varint(&mut self, mut v: u64) {
        while v >= 0x80 {
            self.out.push((v as u8 & 0x7f) | 0x80);
            v >>= 7;
        }
        self.out.push(v as u8);
    }
    pub fn key(&mut self, field: u32, wire: u32) {
        self.varint(((field << 3) | wire) as u64);
    }
    pub fn bytes(&mut self, field: u32, b: &[u8]) {
        self.key(field, 2);
        self.varint(b.len() as u64);
        self.out.extend_from_slice(b);
    }
    pub fn str(&mut self, field: u32, s: &str) {
        self.bytes(field, s.as_bytes());
    }
    pub fn msg(&mut self, field: u32, b: &[u8]) {
        self.bytes(field, b);
    }
    pub fn uint(&mut self, field: u32, v: u64) {
        self.key(field, 0);
        self.varint(v);
    }
    pub fn bool(&mut self, field: u32, v: bool) {
        self.uint(field, if v { 1 } else { 0 });
    }
}
