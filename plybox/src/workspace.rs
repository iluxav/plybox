//! The copy-on-write workspace: `plybox diff` and `plybox apply`.
//!
//! With `workspace_mode = "overlay"` the box's /work is an overlay whose
//! lower layer is the real directory and whose upper layer lives in the
//! session. The box can write anything; nothing reaches the real directory
//! until `apply`. `diff` lists what the box changed.
//!
//! Upper-layer conventions of an unprivileged overlayfs: a deleted file is a
//! character device 0:0 ("whiteout"); a directory replaced wholesale carries
//! the xattr `user.overlay.opaque=y`.

use std::ffi::CString;
use std::fs::{File, OpenOptions};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

#[derive(Debug, PartialEq)]
pub enum Change {
    Added(PathBuf),
    Modified(PathBuf),
    Deleted(PathBuf),
    /// A directory the box replaced entirely (opaque).
    Replaced(PathBuf),
}

impl Change {
    pub fn path(&self) -> &Path {
        match self {
            Change::Added(p) | Change::Modified(p) | Change::Deleted(p) | Change::Replaced(p) => p,
        }
    }
}

// ------------------------------------------------------------ session meta

/// `meta.json`: what a session is, kept beside its record and upper layer.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Meta {
    pub workspace: PathBuf,
    pub workspace_mode: String,
    #[serde(default)]
    pub isolation: String,
    #[serde(default)]
    pub cmd: Vec<String>,
    /// First start, unix seconds.
    pub started: u64,
    /// The same, in nanoseconds: orders sessions started within one second.
    #[serde(default)]
    pub started_ns: u64,
    #[serde(default)]
    pub last_started: u64,
    #[serde(default)]
    pub ended: Option<u64>,
    #[serde(default)]
    pub exit_code: Option<i32>,
    /// How many boxes have run on this session (resumes included).
    #[serde(default)]
    pub runs: u32,
    /// When `plybox apply` copied the changes onto the workspace.
    #[serde(default)]
    pub applied: Option<u64>,
    /// The workspace's git HEAD when the session first started, if a repo.
    #[serde(default)]
    pub git_head: Option<String>,
    #[serde(default)]
    pub image: Option<serde_json::Value>,
}

pub fn now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

pub fn read_meta(dir: &Path) -> Result<Meta, String> {
    let text = std::fs::read_to_string(dir.join("meta.json")).map_err(|e| format!("{}/meta.json: {e}", dir.display()))?;
    serde_json::from_str(&text).map_err(|e| format!("{}/meta.json: {e}", dir.display()))
}

/// Write atomically (temp + rename): a crash never leaves half a meta.json.
pub fn write_meta(dir: &Path, meta: &Meta) -> Result<(), String> {
    let tmp = dir.join(".meta.json.tmp");
    std::fs::write(&tmp, serde_json::to_string_pretty(meta).unwrap()).map_err(|e| format!("meta.json: {e}"))?;
    std::fs::rename(&tmp, dir.join("meta.json")).map_err(|e| format!("meta.json: {e}"))
}

// ------------------------------------------------------------ session names

/// Session names are two words, `quiet-heron`: easy to read back, say and
/// type, and any unique prefix of 3+ characters selects one.
const ADJECTIVES: &[&str] = &[
    "amber", "brave", "brisk", "calm", "clever", "cosmic", "crisp", "dusty", "eager", "early", "fancy", "gentle",
    "glad", "golden", "happy", "hidden", "humble", "icy", "jolly", "kind", "lively", "lucky", "mellow", "misty",
    "noble", "plain", "polite", "proud", "quick", "quiet", "rapid", "rosy", "rusty", "shiny", "silent", "silver",
    "sleepy", "snowy", "solar", "steady", "sunny", "swift", "tidy", "vivid", "warm", "wild", "witty", "zesty",
];
const NOUNS: &[&str] = &[
    "badger", "beaver", "bison", "comet", "coral", "crane", "dingo", "eagle", "ember", "falcon", "fern", "finch",
    "fox", "gecko", "hawk", "heron", "ibis", "koala", "lark", "lemur", "lynx", "maple", "mole", "moose",
    "newt", "oak", "orca", "otter", "owl", "panda", "pebble", "pine", "quail", "raven", "robin", "salmon",
    "seal", "sparrow", "stork", "tiger", "toad", "trout", "tulip", "walrus", "willow", "wren", "yak", "zebra",
];

fn random_u32() -> u32 {
    let mut b = [0u8; 4];
    let r = unsafe { libc::getrandom(b.as_mut_ptr() as *mut libc::c_void, b.len(), 0) };
    if r != b.len() as isize {
        let t = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.subsec_nanos()).unwrap_or(0);
        return t ^ std::process::id().rotate_left(16);
    }
    u32::from_le_bytes(b)
}

/// Create and return a new session directory with a free name. The name is
/// claimed with a plain `mkdir`, which fails if it exists — so two runs
/// starting at the same moment can never end up sharing one session.
pub fn new_session_dir() -> Result<PathBuf, String> {
    let base = sessions_base();
    std::fs::create_dir_all(&base).map_err(|e| format!("{}: {e}", base.display()))?;
    for attempt in 0..200u32 {
        let r = random_u32();
        let mut name = format!("{}-{}", ADJECTIVES[(r & 0xffff) as usize % ADJECTIVES.len()], NOUNS[(r >> 16) as usize % NOUNS.len()]);
        if attempt >= 40 {
            name.push_str(&format!("-{}", 2 + attempt % 98)); // the words are running out: add a number
        }
        let dir = base.join(&name);
        match std::fs::create_dir(&dir) {
            Ok(()) => return Ok(dir),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(format!("{}: {e}", dir.display())),
        }
    }
    Err("could not find a free session name — `plybox sessions --prune` clears old ones".into())
}

/// The session's name: the last component of its directory.
pub fn session_name(dir: &Path) -> String {
    dir.file_name().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default()
}

/// `--last` (the most recently started session), a name, a unique prefix of
/// a name (3+ characters), or a session directory.
pub fn resolve(arg: &str) -> Result<PathBuf, String> {
    if arg == "--last" {
        return list()
            .into_iter()
            .max_by_key(|i| i.order())
            .map(|i| i.dir)
            .ok_or_else(|| "no sessions yet".into());
    }
    let p = PathBuf::from(arg);
    if p.join("meta.json").is_file() {
        return Ok(p);
    }
    let exact = sessions_base().join(arg);
    if !arg.contains('/') && exact.join("meta.json").is_file() {
        return Ok(exact);
    }
    if arg.len() >= 3 && !arg.contains('/') {
        let mut hits: Vec<PathBuf> = session_dirs().into_iter().filter(|d| session_name(d).starts_with(arg)).collect();
        hits.sort();
        match hits.len() {
            1 => return Ok(hits.remove(0)),
            0 => {}
            _ => {
                let names: Vec<String> = hits.iter().map(|d| session_name(d)).collect();
                return Err(format!("`{arg}` matches {} sessions: {} — type more of the name", names.len(), names.join(", ")));
            }
        }
    }
    Err(format!("no session `{arg}` (see `plybox sessions`)"))
}

fn session_dirs() -> Vec<PathBuf> {
    std::fs::read_dir(sessions_base())
        .map(|rd| rd.filter_map(|e| e.ok().map(|e| e.path())).filter(|p| p.join("meta.json").is_file()).collect())
        .unwrap_or_default()
}

// --------------------------------------------------------------- the lock

/// Held by the supervisor while a box runs on the session. Two boxes on one
/// upper layer corrupt it, and an `apply` or `discard` under a running box
/// races it — all three take this lock. Released by the kernel when the
/// holder exits, however it exits.
pub struct Lock {
    _file: File,
}

pub fn lock(dir: &Path) -> Result<Lock, String> {
    let path = dir.join("lock");
    let file = OpenOptions::new().create(true).read(true).write(true).truncate(false).open(&path).map_err(|e| format!("{}: {e}", path.display()))?;
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        let holder = std::fs::read_to_string(&path).unwrap_or_default();
        return Err(format!(
            "session {} is in use by a running box{} — wait for it to exit",
            dir.file_name().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default(),
            if holder.trim().is_empty() { String::new() } else { format!(" (plybox pid {})", holder.trim()) }
        ));
    }
    let _ = file.set_len(0);
    let _ = std::io::Write::write_all(&mut &file, std::process::id().to_string().as_bytes());
    Ok(Lock { _file: file })
}

pub fn running(dir: &Path) -> bool {
    let Ok(file) = File::open(dir.join("lock")) else { return false };
    unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_SH | libc::LOCK_NB) != 0 }
}

// ------------------------------------------------------------- the list

pub struct Info {
    pub dir: PathBuf,
    pub id: String,
    pub meta: Meta,
    pub changes: usize,
    pub running: bool,
    /// When the session directory was created, ns: orders sessions started
    /// within the same second (meta times are whole seconds).
    pub created_ns: u128,
}

impl Info {
    /// Chronological order. Nanosecond start time where recorded (older
    /// sessions have whole seconds only), then directory creation time, which
    /// some filesystems (tmpfs) do not report.
    pub fn order(&self) -> (u64, u128) {
        let secs = self.meta.last_started.max(self.meta.started).saturating_mul(1_000_000_000);
        (self.meta.started_ns.max(secs), self.created_ns)
    }
}

impl Info {
    pub fn status(&self) -> String {
        if self.running {
            "running".into()
        } else if self.meta.workspace_mode != "overlay" {
            "no copy (bind)".into()
        } else if self.meta.applied.is_some() {
            "applied".into()
        } else if self.changes == 0 {
            "no changes".into()
        } else {
            format!("PENDING {}", self.changes)
        }
    }

    pub fn pending(&self) -> bool {
        !self.running && self.meta.workspace_mode == "overlay" && self.meta.applied.is_none() && self.changes > 0
    }
}

pub fn list() -> Vec<Info> {
    let mut out: Vec<Info> = session_dirs()
        .into_iter()
        .filter_map(|dir| {
            let meta = read_meta(&dir).ok()?;
            let changes = if meta.workspace_mode == "overlay" && dir.join("upper").is_dir() {
                Session { dir: dir.clone(), workspace: meta.workspace.clone() }.changes().map(|c| c.len()).unwrap_or(0)
            } else {
                0
            };
            let id = dir.file_name()?.to_string_lossy().into_owned();
            let running = running(&dir);
            let created_ns = std::fs::metadata(&dir)
                .and_then(|m| m.created())
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_nanos())
                .unwrap_or(0);
            Some(Info { dir, id, meta, changes, running, created_ns })
        })
        .collect();
    // Oldest first, by when a box last ran on it (names do not sort by time).
    out.sort_by_key(|i| i.order());
    out
}

/// Delete a session. Refuses a running one, and anything that is not a
/// session directory (it must hold both meta.json and record.jsonl).
pub fn discard(dir: &Path) -> Result<(), String> {
    if !(dir.join("meta.json").is_file() && dir.join("record.jsonl").is_file()) {
        return Err(format!("{} is not a plybox session", dir.display()));
    }
    let _guard = lock(dir)?; // fails if a box is running on it
    make_removable(dir);
    std::fs::remove_dir_all(dir).map_err(|e| format!("remove {}: {e}", dir.display()))
}

/// Remove every session with nothing left to apply: applied ones and ones
/// that changed nothing. Pending and running sessions are kept.
pub fn prune() -> Vec<(String, String)> {
    let mut removed = vec![];
    for i in list() {
        if i.running || i.pending() {
            continue;
        }
        let why = i.status();
        if discard(&i.dir).is_ok() {
            removed.push((i.id, why));
        }
    }
    removed
}

/// The overlay's scratch dir (`work/work`) is created mode 000 by the
/// kernel; restore owner rights so the tree can be removed.
fn make_removable(dir: &Path) {
    use std::os::unix::fs::PermissionsExt;
    if let Ok(md) = std::fs::symlink_metadata(dir) {
        if md.is_dir() {
            let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(md.permissions().mode() | 0o700));
            if let Ok(rd) = std::fs::read_dir(dir) {
                for e in rd.flatten() {
                    make_removable(&e.path());
                }
            }
        }
    }
}

// ------------------------------------------------------------- the session

pub struct Session {
    pub dir: PathBuf,
    pub workspace: PathBuf,
}

impl Session {
    /// `--last`, a session id, or a session directory — one with a copy.
    pub fn open(arg: &str) -> Result<Session, String> {
        let dir = resolve(arg)?;
        let meta = read_meta(&dir)?;
        if meta.workspace_mode != "overlay" {
            return Err("this session used a bind workspace: changes went straight to the directory".into());
        }
        Ok(Session { dir, workspace: meta.workspace })
    }

    pub fn upper(&self) -> PathBuf {
        self.dir.join("upper")
    }

    /// Everything the box changed, relative paths, sorted.
    pub fn changes(&self) -> Result<Vec<Change>, String> {
        let mut out = vec![];
        walk(&self.upper(), Path::new(""), &self.workspace, &mut out)?;
        out.sort_by_key(|c| match c {
            Change::Added(p) | Change::Modified(p) | Change::Deleted(p) | Change::Replaced(p) => p.clone(),
        });
        Ok(out)
    }

    /// Copy the upper layer onto the real workspace.
    ///
    /// The upper layer is the box's work, so it is treated as untrusted: no
    /// change may write or delete through a path whose parent leads out of
    /// the workspace (a symlink in the repo pointing elsewhere), and a
    /// destination that is a symlink is replaced, never written through.
    /// Checked for every change before the first one is applied.
    pub fn apply(&self) -> Result<Vec<Change>, String> {
        let _guard = lock(&self.dir)?;
        let root = std::fs::canonicalize(&self.workspace).map_err(|e| format!("workspace {}: {e}", self.workspace.display()))?;
        let changes = self.changes()?;
        for c in &changes {
            let dest = self.workspace.join(c.path());
            let mut parent = dest.parent().map(Path::to_path_buf).unwrap_or_else(|| root.clone());
            // The nearest existing ancestor decides where a write would land.
            let resolved = loop {
                match std::fs::canonicalize(&parent) {
                    Ok(p) => break p,
                    Err(_) if parent.pop() => continue,
                    Err(e) => return Err(format!("{}: {e}", dest.display())),
                }
            };
            if !resolved.starts_with(&root) {
                return Err(format!(
                    "refusing to apply: {} would be written outside the workspace (through {})",
                    c.path().display(),
                    resolved.display()
                ));
            }
        }
        for c in &changes {
            match c {
                Change::Deleted(rel) => {
                    let t = self.workspace.join(rel);
                    if t.is_dir() {
                        std::fs::remove_dir_all(&t).map_err(|e| format!("remove {}: {e}", t.display()))?;
                    } else if t.exists() || t.symlink_metadata().is_ok() {
                        std::fs::remove_file(&t).map_err(|e| format!("remove {}: {e}", t.display()))?;
                    }
                }
                Change::Replaced(rel) => {
                    let t = self.workspace.join(rel);
                    if t.exists() {
                        std::fs::remove_dir_all(&t).map_err(|e| format!("remove {}: {e}", t.display()))?;
                    }
                    copy_tree(&self.upper().join(rel), &t)?;
                }
                Change::Added(rel) | Change::Modified(rel) => {
                    copy_entry(&self.upper().join(rel), &self.workspace.join(rel))?;
                }
            }
        }
        let mut meta = read_meta(&self.dir)?;
        meta.applied = Some(now());
        write_meta(&self.dir, &meta)?;
        Ok(changes)
    }
}

pub fn sessions_base() -> PathBuf {
    let state = std::env::var_os("XDG_STATE_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".local/state")))
        .unwrap_or_else(|| PathBuf::from("/tmp"));
    state.join("plybox/sessions")
}

fn is_whiteout(meta: &std::fs::Metadata) -> bool {
    meta.file_type().is_char_device() && meta.rdev() == 0
}

fn is_opaque(path: &Path) -> bool {
    let Ok(c) = CString::new(path.as_os_str().as_encoded_bytes()) else { return false };
    let name = CString::new("user.overlay.opaque").unwrap();
    let mut buf = [0u8; 8];
    let n = unsafe { libc::getxattr(c.as_ptr(), name.as_ptr(), buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
    n > 0 && buf[0] == b'y'
}

fn walk(upper: &Path, rel: &Path, real: &Path, out: &mut Vec<Change>) -> Result<(), String> {
    let dir = upper.join(rel);
    for entry in std::fs::read_dir(&dir).map_err(|e| format!("{}: {e}", dir.display()))? {
        let entry = entry.map_err(|e| e.to_string())?;
        let name = entry.file_name();
        let rel_path = rel.join(&name);
        let meta = entry.metadata().map_err(|e| e.to_string())?;
        if is_whiteout(&meta) {
            out.push(Change::Deleted(rel_path));
        } else if meta.is_dir() {
            if is_opaque(&entry.path()) {
                out.push(Change::Replaced(rel_path));
            } else {
                if !real.join(&rel_path).is_dir() && !out.iter().any(|c| matches!(c, Change::Added(p) if p == &rel_path)) {
                    // a directory the box created: its files are reported below
                }
                walk(upper, &rel_path, real, out)?;
            }
        } else if real.join(&rel_path).symlink_metadata().is_ok() {
            out.push(Change::Modified(rel_path));
        } else {
            out.push(Change::Added(rel_path));
        }
    }
    Ok(())
}

fn copy_entry(from: &Path, to: &Path) -> Result<(), String> {
    if let Some(parent) = to.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("mkdir {}: {e}", parent.display()))?;
    }
    let meta = from.symlink_metadata().map_err(|e| format!("{}: {e}", from.display()))?;
    // A destination that is a symlink is replaced, not written through:
    // std::fs::copy would follow it and land outside the workspace.
    if to.symlink_metadata().map(|m| m.file_type().is_symlink()).unwrap_or(false) {
        std::fs::remove_file(to).map_err(|e| format!("replace symlink {}: {e}", to.display()))?;
    }
    if meta.file_type().is_symlink() {
        let target = std::fs::read_link(from).map_err(|e| e.to_string())?;
        let _ = std::fs::remove_file(to);
        std::os::unix::fs::symlink(target, to).map_err(|e| format!("symlink {}: {e}", to.display()))?;
    } else {
        std::fs::copy(from, to).map_err(|e| format!("copy {} → {}: {e}", from.display(), to.display()))?;
    }
    Ok(())
}

fn copy_tree(from: &Path, to: &Path) -> Result<(), String> {
    std::fs::create_dir_all(to).map_err(|e| format!("mkdir {}: {e}", to.display()))?;
    for entry in std::fs::read_dir(from).map_err(|e| format!("{}: {e}", from.display()))? {
        let entry = entry.map_err(|e| e.to_string())?;
        let meta = entry.metadata().map_err(|e| e.to_string())?;
        let dest = to.join(entry.file_name());
        if is_whiteout(&meta) {
            continue;
        }
        if meta.is_dir() {
            copy_tree(&entry.path(), &dest)?;
        } else {
            copy_entry(&entry.path(), &dest)?;
        }
    }
    Ok(())
}

/// Print a diff listing the way `git status --short` does.
pub fn print_changes(changes: &[Change]) {
    for c in changes {
        match c {
            Change::Added(p) => println!("A  {}", p.display()),
            Change::Modified(p) => println!("M  {}", p.display()),
            Change::Deleted(p) => println!("D  {}", p.display()),
            Change::Replaced(p) => println!("R  {}/", p.display()),
        }
    }
    if changes.is_empty() {
        println!("(the box changed nothing)");
    }
}
