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
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::path::{Path, PathBuf};

#[derive(Debug, PartialEq)]
pub enum Change {
    Added(PathBuf),
    Modified(PathBuf),
    Deleted(PathBuf),
    /// A directory the box replaced entirely (opaque).
    Replaced(PathBuf),
}

pub struct Session {
    pub dir: PathBuf,
    pub workspace: PathBuf,
}

impl Session {
    /// `--last`, or a session directory.
    pub fn open(arg: &str) -> Result<Session, String> {
        let dir = if arg == "--last" {
            let base = sessions_base();
            let mut dirs: Vec<PathBuf> = std::fs::read_dir(&base)
                .map_err(|e| format!("{}: {e}", base.display()))?
                .filter_map(|e| e.ok().map(|e| e.path()))
                .filter(|p| p.join("meta.json").is_file())
                .collect();
            dirs.sort();
            dirs.pop().ok_or("no sessions yet")?
        } else {
            PathBuf::from(arg)
        };
        let meta: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(dir.join("meta.json")).map_err(|e| format!("{}/meta.json: {e}", dir.display()))?,
        )
        .map_err(|e| format!("meta.json: {e}"))?;
        let workspace = meta.get("workspace").and_then(|v| v.as_str()).ok_or("meta.json has no workspace")?;
        if meta.get("workspace_mode").and_then(|v| v.as_str()) != Some("overlay") {
            return Err("this session used a bind workspace: changes went straight to the directory".into());
        }
        Ok(Session { dir, workspace: PathBuf::from(workspace) })
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
    pub fn apply(&self) -> Result<Vec<Change>, String> {
        let changes = self.changes()?;
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
