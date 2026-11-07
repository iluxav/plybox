//! Operator rules: the ceiling a machine's owner puts over every run, whatever
//! the policy file or the flags say. For hosting other people's agents, where
//! users supply (part of) the policy and the operator must not trust it.
//!
//! Read from `$PLYBOX_OPERATOR` if set, else `/etc/plybox/operator.toml` if it
//! exists. No file = no ceiling (one person's own machine). Any problem with
//! the file — unreadable, unknown key, bad value — refuses the run.
//!
//! The lists are allowlists: absent or empty allows nothing. `[max]` caps each
//! limit: a policy asking for more is refused; a policy silent on one gets
//! the maximum, and the run is refused if the limits cannot be enforced.

use crate::limits::parse_size;
use crate::policy::{Policy, SecretSpec};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

pub const DEFAULT_PATH: &str = "/etc/plybox/operator.toml";

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Operator {
    /// Force this tier (`"gvisor"` for untrusted code).
    pub isolation: Option<String>,
    /// The `runsc` every gVisor run uses; a policy may not name its own.
    pub runsc: Option<String>,
    /// Allow the host's /usr and basic /etc files as the box's tools.
    #[serde(default)]
    pub host_rootfs: bool,
    /// Approved images: exact references or a prefix ending in `*`.
    #[serde(default)]
    pub images: Vec<String>,
    /// Host directories the workspace, `ro_bind` sources and a rootfs
    /// directory may come from (each resolved, symlinks and all).
    #[serde(default)]
    pub paths: Vec<PathBuf>,
    /// Every `net.allow` entry must fall inside this list.
    #[serde(default)]
    pub hosts: Vec<String>,
    /// Where `--session` may point. Absent: only the default location.
    pub sessions: Option<PathBuf>,
    /// Allow `--resume`.
    #[serde(default)]
    pub resume: bool,
    /// The only secrets read from a file or plybox's environment; a policy
    /// names one and gets exactly this source and host.
    #[serde(default)]
    pub secrets: BTreeMap<String, SecretSpec>,
    #[serde(default)]
    pub max: Max,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Max {
    pub mem: Option<String>,
    pub pids: Option<u32>,
    pub cpu: Option<f64>,
    pub file_size: Option<String>,
    pub tmpfs: Option<String>,
    pub disk: Option<String>,
    pub bytes_out: Option<String>,
    pub bytes_in: Option<String>,
}

/// What a run needs to know after the rules were applied.
#[derive(Debug)]
pub struct Applied {
    pub path: PathBuf,
    /// A cgroup limit came from `[max]`: the run must not go ahead unenforced.
    pub limits_required: bool,
    sessions: Option<PathBuf>,
}

impl Applied {
    /// The session directory, once created and resolved, is still under the
    /// operator's sessions root (a symlink on the way could have moved it).
    pub fn check_session(&self, real: &Path) -> Result<(), String> {
        let root = self.sessions.as_deref().and_then(|r| std::fs::canonicalize(r).ok());
        match root {
            Some(r) if real.starts_with(&r) => Ok(()),
            _ => Err(format!("operator rules ({}): session {} is outside the sessions root", self.path.display(), real.display())),
        }
    }
}

/// The operator file in force, if any.
pub fn load() -> Result<Option<(PathBuf, Operator)>, String> {
    let path = match std::env::var_os("PLYBOX_OPERATOR") {
        Some(p) if p.is_empty() => return Err("PLYBOX_OPERATOR is set but empty".into()),
        Some(p) => PathBuf::from(p),
        None => {
            let p = PathBuf::from(DEFAULT_PATH);
            match p.symlink_metadata() {
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
                Err(e) => return Err(format!("operator rules {}: {e}", p.display())),
                Ok(_) => p,
            }
        }
    };
    let text = std::fs::read_to_string(&path).map_err(|e| format!("operator rules {}: {e}", path.display()))?;
    let op: Operator = toml::from_str(&text).map_err(|e| format!("operator rules {}: {e}", path.display()))?;
    Ok(Some((path, op)))
}

/// What the run was asked to do outside the policy.
pub struct Request<'a> {
    pub learn: bool,
    pub session: Option<&'a Path>,
    pub resume: bool,
}

/// Bring `pol` under the operator's rules, or say which one it breaks.
/// `pol` has absolute paths already (`Policy::absolute_paths`).
pub fn apply(op: &Operator, path: &Path, pol: &mut Policy, req: &Request) -> Result<Applied, String> {
    let fail = |why: String| format!("operator rules ({}): {why}", path.display());

    // Asked-for extras that only the operator's own tooling should use.
    if req.learn {
        return Err(fail("--learn is not allowed (it opens the network)".into()));
    }
    if req.resume && !op.resume {
        return Err(fail("--resume is not allowed".into()));
    }
    if let Some(s) = req.session {
        let root = op.sessions.as_deref().ok_or_else(|| fail("--session is not allowed".into()))?;
        if !lexically_inside(s, root) || !existing_part_inside(s, root) {
            return Err(fail(format!("--session {} is outside {}", s.display(), root.display())));
        }
    }
    if !pol.net.map.is_empty() {
        return Err(fail("net.map is not allowed".into()));
    }
    if !pol.net.trust_ca.is_empty() {
        return Err(fail("net.trust_ca is not allowed".into()));
    }

    // The tier.
    if pol.runsc.is_some() {
        return Err(fail("a policy may not choose its runsc".into()));
    }
    if let Some(iso) = &op.isolation {
        pol.isolation = iso.clone();
    }
    pol.runsc = op.runsc.clone();

    // Files: the root, the workspace, every read-only bind.
    let roots: Vec<PathBuf> = op.paths.iter().filter_map(|p| std::fs::canonicalize(p).ok()).collect();
    let inside = |what: &str, p: &Path| -> Result<PathBuf, String> {
        let real = std::fs::canonicalize(p).map_err(|e| fail(format!("{what} {}: {e}", p.display())))?;
        if roots.iter().any(|r| real.starts_with(r)) {
            Ok(real)
        } else {
            Err(fail(format!("{what} {} is outside the allowed paths", real.display())))
        }
    };
    let rootfs = pol.fs.rootfs.clone();
    match (&pol.image, rootfs.as_str()) {
        (Some(img), _) => {
            if !crate::image::approved(img, &op.images)? {
                return Err(fail(format!("image {img} is not approved")));
            }
        }
        (None, "host") if op.host_rootfs => {}
        (None, "host") => return Err(fail("the host's /usr is not allowed as the box's tools; use an approved image".into())),
        (None, dir) => pol.fs.rootfs = inside("rootfs", Path::new(dir))?.to_string_lossy().into_owned(),
    }
    pol.fs.workspace = inside("workspace", &pol.fs.workspace)?;
    for pair in &mut pol.fs.ro_bind {
        let (host, dest) = pair.split_once(':').ok_or("ro_bind: expected HOST:BOX")?;
        // Mount what was checked: the resolved path, not a symlink that
        // could be swapped before the box starts.
        *pair = format!("{}:{dest}", inside("ro_bind", Path::new(host))?.display());
    }

    // Network.
    let ceiling = crate::proxy::Allow::parse(&op.hosts).map_err(|e| fail(format!("hosts: {e}")))?;
    let asked = crate::proxy::Allow::parse(&pol.net.allow)?;
    if let Some(out) = ceiling.first_outside(&asked) {
        return Err(fail(format!("net.allow {out} is outside the operator's hosts")));
    }

    // Secrets: a file or environment source only as the operator declared
    // it; a value the user typed may go only to a host they could reach.
    for (name, spec) in pol.secrets.iter_mut() {
        if let Some(theirs) = op.secrets.get(name) {
            *spec = theirs.clone();
            continue;
        }
        if spec.value.is_none() {
            return Err(fail(format!("secret {name}: only the operator's secrets may come from a file or the environment")));
        }
        let one = crate::proxy::Allow::parse(std::slice::from_ref(&spec.only))?;
        if ceiling.first_outside(&one).is_some() {
            return Err(fail(format!("secret {name}: host {} is outside the operator's hosts", spec.only)));
        }
    }

    // Limits.
    let m = &op.max;
    let l = &mut pol.limits;
    let mut limits_required = false;
    for (name, asked, max) in [
        ("mem", &mut l.mem, &m.mem),
        ("file_size", &mut l.file_size, &m.file_size),
        ("tmpfs", &mut l.tmpfs, &m.tmpfs),
        ("disk", &mut l.disk, &m.disk),
        ("bytes_out", &mut l.bytes_out, &m.bytes_out),
        ("bytes_in", &mut l.bytes_in, &m.bytes_in),
    ] {
        let Some(max) = max else { continue };
        let cap = parse_size(max).map_err(|e| fail(format!("max.{name}: {e}")))?;
        match asked {
            Some(v) if parse_size(v)? > cap => return Err(fail(format!("{name} {v} is over the maximum {max}"))),
            Some(_) => {}
            None => *asked = Some(max.clone()),
        }
        limits_required |= name == "mem";
    }
    if let Some(cap) = m.pids {
        match l.pids {
            Some(v) if v > cap => return Err(fail(format!("pids {v} is over the maximum {cap}"))),
            Some(_) => {}
            None => l.pids = Some(cap),
        }
        limits_required = true;
    }
    if let Some(cap) = m.cpu {
        match l.cpu {
            Some(v) if v > cap => return Err(fail(format!("cpu {v} is over the maximum {cap}"))),
            Some(_) => {}
            None => l.cpu = Some(cap),
        }
        limits_required = true;
    }
    Ok(Applied { path: path.to_path_buf(), limits_required, sessions: op.sessions.clone() })
}

/// `p` is under `root` by its components alone (no `..`, no `.`), for paths
/// that do not exist yet; the run checks the real path again once made.
fn lexically_inside(p: &Path, root: &Path) -> bool {
    use std::path::Component;
    p.is_absolute() && p.components().all(|c| matches!(c, Component::RootDir | Component::Normal(_))) && p.starts_with(root)
}

/// The deepest part of `p` that exists already resolves inside `root`, so
/// creating the rest (plain components only) cannot land anywhere else.
fn existing_part_inside(p: &Path, root: &Path) -> bool {
    let Ok(root) = std::fs::canonicalize(root) else { return false };
    let mut probe = p;
    loop {
        match probe.symlink_metadata() {
            Ok(_) => return std::fs::canonicalize(probe).is_ok_and(|real| real.starts_with(&root)),
            Err(_) => match probe.parent() {
                Some(up) => probe = up,
                None => return false,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn op(text: &str) -> Operator {
        toml::from_str(text).unwrap()
    }
    fn apply_to(o: &Operator, p: &mut Policy) -> Result<Applied, String> {
        apply(o, Path::new("/test/operator.toml"), p, &Request { learn: false, session: None, resume: false })
    }

    #[test]
    fn forced_tier_precedes_workspace_defaults_and_storage_validation() {
        let mut p = Policy::default();
        p.limits.tmpfs = Some("3M".into());
        apply_to(&op("host_rootfs = true\npaths = ['/']\nisolation = 'ns'"), &mut p).unwrap();
        p.resolve_workspace_mode().unwrap();
        assert_eq!(p.isolation, "ns");
        assert_eq!(p.fs.workspace_mode, "overlay");
        assert!(crate::storage::Caps::parse(&p).is_ok());
        apply_to(&op("host_rootfs = true\npaths = ['/']\nisolation = 'gvisor'"), &mut p).unwrap();
        assert_eq!(p.isolation, "gvisor");
        assert!(p.resolve_workspace_mode().unwrap_err().contains("--isolation ns"));
        p.fs.workspace_mode = "auto".into();
        p.resolve_workspace_mode().unwrap();
        assert!(crate::storage::Caps::parse(&p).unwrap_err().contains("--isolation ns"));
    }

    #[test]
    fn hosts_must_be_inside_the_ceiling() {
        let o = op("host_rootfs = true\npaths = ['/']\nhosts = ['*.example.com', 'api.other.com']");
        for ok in [vec!["a.example.com"], vec!["*.b.example.com"], vec!["api.other.com"], vec![]] {
            let mut p = Policy::default();
            p.net.allow = ok.iter().map(|s| s.to_string()).collect();
            assert!(apply_to(&o, &mut p).is_ok(), "refused {ok:?}");
        }
        for bad in ["example.com", "*.com", "evil.com", "api.other.com:8443", "x.other.com"] {
            let mut p = Policy::default();
            p.net.allow = vec![bad.into()];
            assert!(apply_to(&o, &mut p).is_err(), "accepted {bad}");
        }
    }

    #[test]
    fn absent_lists_allow_nothing_and_max_fills_in() {
        let mut p = Policy::default();
        assert!(apply_to(&op(""), &mut p).unwrap_err().contains("host's /usr"));
        let mut p = Policy::default();
        assert!(apply_to(&op("host_rootfs = true"), &mut p).unwrap_err().contains("outside the allowed paths"));
        let o = op("host_rootfs = true\npaths = ['/']\n[max]\nmem = '1G'\npids = 64");
        let mut p = Policy::default();
        let a = apply_to(&o, &mut p).unwrap();
        assert_eq!((p.limits.mem.as_deref(), p.limits.pids, a.limits_required), (Some("1G"), Some(64), true));
        let mut p = Policy::default();
        p.limits.mem = Some("2G".into());
        assert!(apply_to(&o, &mut p).unwrap_err().contains("over the maximum"));
    }

    #[test]
    fn secrets_from_host_sources_only_as_the_operator_declared() {
        let o = op("host_rootfs = true\npaths = ['/']\nhosts = ['api.a.com']\n[secrets]\nK = { only = 'api.a.com', file = '/etc/plybox/k' }");
        let mut p = Policy::default();
        p.secrets.insert("K".into(), SecretSpec { only: "evil.com".into(), value: None, file: Some("/home/u/.ssh/id_rsa".into()) });
        apply_to(&o, &mut p).unwrap();
        assert_eq!((p.secrets["K"].only.as_str(), p.secrets["K"].file.as_deref()), ("api.a.com", Some("/etc/plybox/k")));
        for spec in [SecretSpec { only: "api.a.com".into(), value: None, file: Some("/x".into()) },
                     SecretSpec { only: "api.a.com".into(), value: None, file: None },
                     SecretSpec { only: "evil.com".into(), value: Some("v".into()), file: None }] {
            let mut p = Policy::default();
            p.secrets.insert("OTHER".into(), spec);
            assert!(apply_to(&o, &mut p).is_err());
        }
        let mut p = Policy::default();
        p.secrets.insert("MINE".into(), SecretSpec { only: "api.a.com".into(), value: Some("v".into()), file: None });
        assert!(apply_to(&o, &mut p).is_ok());
    }

    #[test]
    fn sessions_stay_under_the_operator_root() {
        let root = Path::new("/srv/s");
        assert!(lexically_inside(Path::new("/srv/s/a"), root));
        for bad in ["/srv/s/../x", "/srv/other", "srv/s/a", "/srv/sx"] {
            assert!(!lexically_inside(Path::new(bad), root), "accepted {bad}");
        }
    }
}
