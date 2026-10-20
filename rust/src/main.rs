//! File integrity checker. Store v2: "<sha256>\t<size>\t<mtime>\t<path>" per line.
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use std::borrow::Cow;
use std::collections::BTreeMap;
use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Component, Path, PathBuf};
use std::process::exit;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::UNIX_EPOCH;

const HEADER: &str = "#integrity-check v2";
const SIGTAG: &str = "#hmac-sha256 ";

/// (sha256 hex, size, mtime seconds). `Cow`: a parsed baseline borrows from the store
/// text, a fresh scan owns its strings.
type Entry<'a> = (Cow<'a, str>, u64, i64);
type Store<'a> = BTreeMap<Cow<'a, str>, Entry<'a>>;

fn die(msg: &str) -> ! {
    eprintln!("error: {}", msg);
    exit(2)
}

/// Unwrap or die with "<path>: <os error>", matching bash/python.
fn or_die<T, E: std::fmt::Display>(r: Result<T, E>, p: &Path) -> T {
    r.unwrap_or_else(|e| die(&format!("{}: {}", p.display(), e)))
}

/// Whether `p` is `prefix` itself or sits inside it. One definition for check and prune.
fn under(p: &str, prefix: &str) -> bool {
    p == prefix || (p.starts_with(prefix) && p.as_bytes().get(prefix.len()) == Some(&b'/'))
}

/// The store key for a path: UTF-8, or it is not representable in the store.
fn utf8(p: &Path) -> String {
    p.to_str()
        .unwrap_or_else(|| die(&format!("non-UTF-8 filename unsupported: {}", p.display())))
        .to_owned()
}

/// Reject names a line-based, tab-separated store cannot hold; matches bash/python.
fn check_name(name: &str) {
    if name.contains('\t') || name.contains('\n') {
        die(&format!("unsupported filename (tab or newline): {}", name));
    }
}

fn db_path() -> PathBuf {
    abspath(Path::new(
        &env::var_os("INTEGRITY_DB").unwrap_or_else(|| ".integrity.db".into()),
    ))
}

fn abspath(p: &Path) -> PathBuf {
    let abs = if p.is_absolute() {
        p.to_path_buf()
    } else {
        env::current_dir().unwrap().join(p)
    };
    // Lexical only, like bash/python; popping on ".." keeps symlinks unresolved.
    let mut out = PathBuf::new();
    for c in abs.components() {
        match c {
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            c => out.push(c),
        }
    }
    out
}

/// The regular files under `target` with their metadata, or `target` itself if it is one.
fn collect(target: &Path) -> Vec<(PathBuf, fs::Metadata)> {
    let root = abspath(target);
    let md = or_die(fs::metadata(&root), &root);
    if !md.is_dir() {
        if !md.is_file() {
            die(&format!("not a regular file: {}", root.display()));
        }
        return vec![(root, md)];
    }
    let mut out = Vec::new();
    let mut stack = vec![root];
    while let Some(dir) = stack.pop() {
        for entry in or_die(fs::read_dir(&dir), &dir) {
            let entry = or_die(entry, &dir);
            let p = entry.path();
            // file_type comes from readdir's d_type: free, and does not follow symlinks
            let ft = or_die(entry.file_type(), &p);
            if ft.is_dir() {
                stack.push(p);
            } else if ft.is_file() {
                let md = or_die(entry.metadata(), &p); // symlinks, fifos, sockets, devices: skipped
                out.push((p, md));
            }
        }
    }
    out
}

/// `md` is the file's metadata from the walk.
fn sha256(path: &Path, md: &fs::Metadata) -> String {
    let mut file = or_die(File::open(path), path);
    // A save-by-rename swaps the inode after the walk, which is fine while the path
    // still names the regular file we opened; anything else (a symlink) is refused.
    let now = or_die(file.metadata(), path);
    if (now.dev(), now.ino()) != (md.dev(), md.ino()) {
        let cur = or_die(fs::symlink_metadata(path), path);
        if !cur.file_type().is_file() || (cur.dev(), cur.ino()) != (now.dev(), now.ino()) {
            die(&format!("{}: replaced during scan", path.display()));
        }
    }
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 1 << 20];
    loop {
        let n = or_die(file.read(&mut buf), path);
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    format!("{:x}", hasher.finalize())
}

/// Hash `paths` in parallel, in order. Workers pull indices off a shared cursor so one
/// huge file among small ones cannot pin a whole chunk to a single thread.
fn hash_many(paths: &[(&Path, &fs::Metadata)]) -> Vec<String> {
    let jobs = std::thread::available_parallelism()
        .map_or(4, |n| n.get())
        .min(paths.len());
    let next = AtomicUsize::new(0);
    let mut out = vec![String::new(); paths.len()];
    std::thread::scope(|s| {
        let workers: Vec<_> = (0..jobs)
            .map(|_| {
                s.spawn(|| {
                    let mut done = Vec::new();
                    loop {
                        let i = next.fetch_add(1, Ordering::Relaxed);
                        match paths.get(i) {
                            Some((p, md)) => done.push((i, sha256(p, md))),
                            None => return done,
                        }
                    }
                })
            })
            .collect();
        for w in workers {
            for (i, hash) in w.join().unwrap() {
                out[i] = hash;
            }
        }
    });
    out
}

/// Current state of `target`. With a baseline, reuse its hash when size+mtime match.
fn scan<'a>(target: &Path, db: &Path, baseline: Option<&Store<'a>>) -> Store<'a> {
    let mut store = Store::new();
    let mut todo = Vec::new(); // (name, mtime, path, metadata) for the files that need hashing
    for (path, md) in collect(target) {
        if path == db {
            continue;
        }
        let mtime = match or_die(md.modified(), &path).duration_since(UNIX_EPOCH) {
            Ok(d) => d.as_secs() as i64,
            Err(e) => -(e.duration().as_secs() as i64),
        };
        let name = utf8(&path);
        check_name(&name);
        let reuse = baseline
            .and_then(|b| b.get(name.as_str()))
            .filter(|old| old.1 == md.len() && old.2 == mtime);
        match reuse {
            Some(old) => {
                // clone of a Cow::Borrowed is a pointer copy
                store.insert(Cow::Owned(name), (old.0.clone(), md.len(), mtime));
            }
            None => todo.push((name, mtime, path, md)),
        }
    }
    let hashes = hash_many(
        &todo
            .iter()
            .map(|t| (t.2.as_path(), &t.3))
            .collect::<Vec<_>>(),
    );
    for ((name, mtime, _, md), hash) in todo.into_iter().zip(hashes) {
        store.insert(Cow::Owned(name), (Cow::Owned(hash), md.len(), mtime));
    }
    store
}

// --- signing -------------------------------------------------------------------
fn read_key(create: bool) -> Option<Vec<u8>> {
    let path = PathBuf::from(env::var_os("INTEGRITY_KEY")?);
    if !path.exists() {
        if !create {
            die(&format!("key file not found: {}", path.display()));
        }
        let mut key = [0u8; 32];
        File::open("/dev/urandom")
            .unwrap()
            .read_exact(&mut key)
            .unwrap();
        or_die(
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&path),
            &path,
        )
        .write_all(&key)
        .unwrap();
        println!(
            "Generated signing key {}. Keep it off the monitored host.",
            path.display()
        );
    }
    Some(or_die(fs::read(&path), &path))
}

/// Hex HMAC-SHA256 of a store body.
fn mac(key: &[u8], body: &str) -> String {
    let mut m = <Hmac<Sha256>>::new_from_slice(key).unwrap();
    m.update(body.as_bytes());
    format!("{:x}", m.finalize().into_bytes())
}

// --- store ---------------------------------------------------------------------
/// Read and authenticate the store; None when it does not exist yet. Returns text rather
/// than a parsed map so `parse` can borrow the entries from it.
fn load_text(db: &Path) -> Option<String> {
    let text = match fs::read_to_string(db) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return None,
        // say what InvalidData means here, in the wording bash and python use
        Err(e) if e.kind() == std::io::ErrorKind::InvalidData => {
            die(&format!("store is not valid UTF-8: {}", db.display()))
        }
        Err(e) => die(&format!("{}: {}", db.display(), e)),
    };
    if text.lines().next() != Some(HEADER) {
        die(&format!(
            "unsupported store: expected \"{}\" header",
            HEADER
        ));
    }
    // an empty signature is no signature, as in bash and python
    let sig = text
        .lines()
        .last()
        .and_then(|l| l.strip_prefix(SIGTAG))
        .filter(|s| !s.is_empty());
    let key = read_key(false);
    match (sig, &key) {
        (Some(_), None) => die("store is signed but INTEGRITY_KEY is not set"),
        (None, Some(_)) => die("INTEGRITY_KEY is set but the store is unsigned; re-run init"),
        (Some(sig), Some(key)) => {
            // The signature covers the raw bytes of every line but its own; rebuilding from
            // parsed lines would rewrite \r\n as \n and accept a line-ending change.
            let end = text.strip_suffix('\n').unwrap_or(&text);
            let body = &text[..end.rfind('\n').map_or(0, |i| i + 1)];
            if !subtle_eq(sig.as_bytes(), mac(key, body).as_bytes()) {
                die("store signature mismatch: the baseline itself was tampered with");
            }
        }
        (None, None) => {}
    }
    Some(text)
}

/// Parse authenticated store text, validating every line. Entries borrow from `text` (no
/// allocation per line); the caller filters before collect() bulk-builds the tree.
fn parse(text: &str) -> impl Iterator<Item = (Cow<'_, str>, Entry<'_>)> {
    text.lines()
        .filter(|l| !l.starts_with('#') && !l.is_empty())
        .map(|line| {
            let malformed = || die(&format!("malformed store line: {}", line));
            let mut f = line.splitn(4, '\t');
            let (Some(h), Some(size), Some(mtime), Some(path)) =
                (f.next(), f.next(), f.next(), f.next())
            else {
                malformed()
            };
            // ASCII digits only, as in bash and python: parse() also takes a leading '+'
            let digits = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit());
            if !digits(size) || !digits(mtime.strip_prefix('-').unwrap_or(mtime)) {
                malformed()
            }
            let size = size.parse().unwrap_or_else(|_| malformed());
            let mtime = mtime.parse().unwrap_or_else(|_| malformed());
            (Cow::Borrowed(path), (Cow::Borrowed(h), size, mtime))
        })
}

fn save(store: &Store<'_>, db: &Path) {
    use std::fmt::Write as _;
    let mut body = format!("{}\n", HEADER);
    for (path, (hash, size, mtime)) in store {
        let _ = writeln!(body, "{}\t{}\t{}\t{}", hash, size, mtime, path);
    }
    if let Some(key) = read_key(true) {
        let sig = mac(&key, &body); // ends the borrow of body before it grows
        body.push_str(SIGTAG);
        body.push_str(&sig);
        body.push('\n');
    }
    let name = db
        .file_name()
        .unwrap_or_else(|| die(&format!("invalid store path: {}", db.display())));
    let tmp = db.with_file_name(format!(
        "{}.{}.tmp",
        name.to_string_lossy(),
        std::process::id()
    ));
    let _ = fs::remove_file(&tmp); // stale leftover from a crashed run
    let write = || -> std::io::Result<()> {
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp)?
            .write_all(body.as_bytes())?;
        fs::rename(&tmp, db)
    };
    write().unwrap_or_else(|e| {
        let _ = fs::remove_file(&tmp);
        die(&format!("{}: {}", db.display(), e));
    });
}

/// Constant-time comparison, so verification does not leak the expected digest.
fn subtle_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

// --- commands ------------------------------------------------------------------
fn cmd_store(action: &str, target: &Path, db: &Path) -> i32 {
    let text = load_text(db);
    let mut store: Store = text
        .as_deref()
        .map(|t| parse(t).collect())
        .unwrap_or_default();
    let fresh = scan(target, db, None);
    let prefix = utf8(&abspath(target));
    // drop vanished entries under the target (else Missing forever); keep the rest
    store.retain(|p, _| fresh.contains_key(&**p) || !under(p, &prefix));
    store.extend(fresh);
    save(&store, db);
    let msg = if action == "init" {
        "Hashes stored successfully."
    } else {
        "Hash updated successfully."
    };
    println!("{} ({} tracked, {})", msg, store.len(), db.display());
    0
}

fn cmd_check(target: &Path, db: &Path, fast: bool) -> i32 {
    let text = load_text(db).unwrap_or_else(|| {
        die(&format!(
            "no baseline at {}, run 'init' first",
            db.display()
        ))
    });
    let prefix = utf8(&abspath(target));
    // A scan only finds paths under the target, so the rest of the store is never looked up.
    let stored: Store = parse(&text).filter(|(p, _)| under(p, &prefix)).collect();
    let current = scan(target, db, if fast { Some(&stored) } else { None });

    let mut lines = Vec::new();
    let mut bad = 0;
    for (path, entry) in &current {
        match stored.get(path) {
            None => {
                lines.push(format!("{}: Untracked", path));
                bad += 1;
            }
            Some(old) if old.0 == entry.0 => lines.push(format!("{}: Unmodified", path)),
            Some(_) => {
                lines.push(format!("{}: Modified (hash mismatch)", path));
                bad += 1;
            }
        }
    }
    for path in stored.keys().filter(|p| !current.contains_key(*p)) {
        lines.push(format!("{}: Missing (file deleted)", path));
        bad += 1;
    }
    lines.sort();
    if !lines.is_empty() {
        println!("{}", lines.join("\n"));
    }
    i32::from(bad > 0)
}

fn main() {
    let usage = "usage: integrity-check {init|update} <file|dir>\n       \
                 integrity-check check [--fast] <file|dir>";
    let mut args: Vec<String> = env::args().skip(1).collect();
    let fast = args.len() >= 2 && args[1] == "--fast";
    if fast {
        args.remove(1);
    }
    if args.len() != 2
        || !["init", "check", "update"].contains(&args[0].as_str())
        || (fast && args[0] != "check")
    {
        eprintln!("{}", usage);
        exit(2);
    }
    let target = PathBuf::from(&args[1]);
    if !target.exists() {
        die(&format!("no such file or directory: {}", target.display()));
    }
    let db = db_path();
    exit(match args[0].as_str() {
        "check" => cmd_check(&target, &db, fast),
        action => cmd_store(action, &target, &db),
    })
}
