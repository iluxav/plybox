//! Landlock: the filesystem is restricted to declared paths, as a second
//! lock behind the mount namespace. Best-effort on the kernel's ABI; the
//! status is returned so a weaker-than-asked enforcement is reported, never
//! silent.

use landlock::{
    Access, AccessFs, PathBeneath, PathFd, Ruleset, RulesetAttr, RulesetCreated, RulesetCreatedAttr, RulesetStatus,
    ABI,
};

const ABI_WANTED: ABI = ABI::V5;

/// Build the ruleset (opens the path fds). Done before fork; applied after.
pub fn build(ro: &[&str], rw: &[&str]) -> Result<RulesetCreated, String> {
    let mut rs = Ruleset::default()
        .handle_access(AccessFs::from_all(ABI_WANTED))
        .map_err(|e| format!("landlock: {e}"))?
        .create()
        .map_err(|e| format!("landlock create: {e}"))?;
    for p in ro {
        if let Ok(fd) = PathFd::new(p) {
            rs = rs.add_rule(PathBeneath::new(fd, AccessFs::from_read(ABI_WANTED))).map_err(|e| format!("landlock ro {p}: {e}"))?;
        }
    }
    for p in rw {
        if let Ok(fd) = PathFd::new(p) {
            rs = rs.add_rule(PathBeneath::new(fd, AccessFs::from_all(ABI_WANTED))).map_err(|e| format!("landlock rw {p}: {e}"))?;
        }
    }
    Ok(rs)
}

pub fn apply(rs: RulesetCreated) -> Result<RulesetStatus, String> {
    rs.restrict_self().map(|s| s.ruleset).map_err(|e| format!("landlock restrict_self: {e}"))
}
