//! Decode a manifest the fskit backend wrote and print the tree around a path.
//! `cargo run -p backend-fskit --example probe -- <file.pb> <path/prefix>`

use backend::tree::{self, Dir};
use backend::wire::Reader;

fn field<'a>(bytes: &'a [u8], want: u64) -> Option<&'a [u8]> {
    let mut r = Reader::new(bytes);
    while let Some((f, wire)) = r.next_key() {
        if (f, wire) == (want, 2) {
            return r.len_slice();
        }
        r.skip(wire);
    }
    None
}

fn walk(d: &Dir, path: &str, want: &str) {
    for f in d.files.iter() {
        let p = format!("{path}/{}", f.name);
        if p.contains(want) {
            println!("FILE {p}\n     digest={} size={} exec={} host={:?}", &f.digest[..12.min(f.digest.len())], f.size, f.executable, f.host_path);
        }
    }
    for s in d.symlinks.iter() {
        let p = format!("{path}/{}", s.name);
        if p.contains(want) {
            println!("LINK {p} -> {}", s.target);
        }
    }
    for sub in d.directories.iter() {
        let p = format!("{path}/{}", sub.name);
        if p.contains(want) && sub.files.is_empty() && sub.directories.is_empty() && sub.symlinks.is_empty() {
            println!("DIR  {p} (EMPTY) digest={} host={:?} speculative={:?}", &sub.digest[..12.min(sub.digest.len())], sub.host_path, sub.speculative_host_path);
        }
        walk(sub, &p, want);
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let bytes = std::fs::read(&args[1]).expect("read manifest");
    let want = args.get(2).cloned().unwrap_or_default();
    println!("exec_root: {:?}", field(&bytes, 1).map(|b| String::from_utf8_lossy(b).into_owned()));
    let mut r = Reader::new(&bytes);
    while let Some((f, wire)) = r.next_key() {
        match (f, wire) {
            (3, 2) | (4, 2) => {
                let entry = r.len_slice().unwrap_or_default();
                let mut e = Reader::new(entry);
                let (mut k, mut v) = (String::new(), String::new());
                while let Some((ef, ew)) = e.next_key() {
                    match (ef, ew) {
                        (1, 2) => k = String::from_utf8_lossy(e.len_slice().unwrap_or_default()).into_owned(),
                        (2, 2) => v = String::from_utf8_lossy(e.len_slice().unwrap_or_default()).into_owned(),
                        (_, w) => e.skip(w),
                    }
                }
                println!("{} {k}\n   -> {v}", if f == 3 { "OUT " } else { "WDIR" });
            }
            (_, w) => r.skip(w),
        }
    }
    let root = field(&bytes, 2).and_then(tree::decode).expect("decode tree");
    walk(&root, "", &want);
}
