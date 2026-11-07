//! What the box may do. A TOML file, overridden by command-line flags.
//!
//! ```toml
//! [fs]
//! rootfs    = "host"              # the host's /usr, read-only — or a directory
//! workspace = "."                 # mounted read-write at /work
//! ro_bind   = ["/home/me/.local/share/mise/installs/node:/opt/node"]
//!
//! [net]
//! allow = ["api.anthropic.com", "*.anthropic.com", "registry.npmjs.org:443"]
//!
//! [env]
//! PATH = "/opt/node/latest/bin:/usr/local/bin:/usr/bin:/bin"
//! ```
//!
//! Absent sections mean the tightest default: no network, host tools,
//! the current directory as the workspace.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    #[serde(default)]
    pub fs: Fs,
    #[serde(default)]
    pub net: Net,
    /// Environment inside the box. Values here win over the defaults.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub env: BTreeMap<String, String>,
    /// Secrets the box must never hold: `NAME = { only = "host" }` takes the
    /// value from the caller's environment variable NAME; add `value = "…"`
    /// for a literal. The box gets a placeholder under NAME; the proxy swaps
    /// it for the value only toward `only`.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub secrets: BTreeMap<String, SecretSpec>,
    /// Per-box limits: `mem = "512M"`, `pids = 512`, `cpu = 1.5` (cores).
    #[serde(default)]
    pub limits: LimitsSpec,
    /// `"ns"` (default): namespaces via bubblewrap. `"gvisor"`: gVisor's
    /// user-space kernel in between, for code you do not trust.
    #[serde(default = "default_isolation")]
    pub isolation: String,
    /// Path to gVisor's `runsc` (default: found on PATH).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runsc: Option<String>,
    /// An OCI image used as the box's root filesystem, e.g. "python:3.13-slim".
    /// Pulled on first use (no Docker needed); overrides `fs.rootfs`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image: Option<String>,
}

fn default_isolation() -> String {
    "ns".into()
}

// By hand, so `Policy::default()` agrees with the serde defaults (a derived
// Default would leave `isolation` empty).
impl Default for Policy {
    fn default() -> Self {
        Policy {
            fs: Fs::default(),
            net: Net::default(),
            env: BTreeMap::new(),
            secrets: BTreeMap::new(),
            limits: LimitsSpec::default(),
            isolation: default_isolation(),
            runsc: None,
            image: None,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
#[serde(deny_unknown_fields)]
pub struct LimitsSpec {
    /// Persistent session volume capacity, verified before starting.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disk: Option<String>,
    /// Total scratch capacity, split equally across /tmp, /home, /dev/shm.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tmpfs: Option<String>,
    /// Maximum logical size of any single workload file (RLIMIT_FSIZE).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file_size: Option<String>,
    /// Run-wide upstream TCP payload budgets (including TLS records).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bytes_out: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bytes_in: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mem: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pids: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpu: Option<f64>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SecretSpec {
    pub only: String,
    /// A literal value. Never written back out by `--learn`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    /// Read the value from this file (`~/` expanded; trailing newline
    /// dropped). How Kubernetes hands secrets over, and how a value reaches
    /// plybox without passing through a shell or an environment.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Fs {
    /// `"host"` or a directory to use as `/`.
    #[serde(default = "default_rootfs")]
    pub rootfs: String,
    /// Mounted at /work; the box starts there.
    #[serde(default = "default_workspace")]
    pub workspace: PathBuf,
    /// `"overlay"` (default): the box writes to a copy; changes reach the
    /// real directory only with `plybox apply`. `"bind"`: writes go straight
    /// to the directory.
    #[serde(default = "default_workspace_mode")]
    pub workspace_mode: String,
    /// Extra read-only binds, `HOSTPATH:BOXPATH`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ro_bind: Vec<String>,
}

impl Default for Fs {
    fn default() -> Self {
        Fs { rootfs: default_rootfs(), workspace: default_workspace(), workspace_mode: default_workspace_mode(), ro_bind: vec![] }
    }
}

fn default_workspace_mode() -> String {
    "overlay".into()
}

fn default_rootfs() -> String {
    "host".into()
}
fn default_workspace() -> PathBuf {
    PathBuf::from(".")
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
#[serde(deny_unknown_fields)]
pub struct Net {
    /// Hostnames the proxy will connect to: `host`, `*.suffix`, `host:port`.
    /// Empty = the box reaches nothing.
    #[serde(default)]
    pub allow: Vec<String>,
    /// Extra PEM roots the proxy trusts when it talks to upstreams (test
    /// servers with their own CA). Normal use needs none.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub trust_ca: Vec<String>,
    /// `host=ip:port`: resolve `host` to a fixed address instead of DNS, and
    /// skip the public-address rule for it. For test upstreams only.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub map: Vec<String>,
}

/// What `run` was asked to do beyond the policy.
#[derive(Debug, Default)]
pub struct RunOpts {
    pub session: Option<PathBuf>,
    pub resume: Option<crate::workspace::Resume>,
    pub quiet: bool,
    /// Learn mode: allow every public destination, record each, and write
    /// the resulting policy here at exit (default `<session>/learned.toml`).
    pub learn: Option<Option<PathBuf>>,
}

impl Policy {
    /// Resolve host paths now, so a resumed run works from another cwd.
    pub fn absolute_paths(&mut self) -> Result<(), String> {
        fn absolute(path: &str) -> Result<String, String> {
            let p = match path.strip_prefix("~/") {
                Some(rest) => PathBuf::from(std::env::var("HOME").unwrap_or_default()).join(rest),
                None => PathBuf::from(path),
            };
            // Anchor relative paths without resolving symlinks: secret files
            // may rotate by replacing a symlink between runs.
            let p = if p.is_absolute() { p } else {
                std::env::current_dir().map_err(|e| format!("current directory: {e}"))?.join(p)
            };
            Ok(p.to_string_lossy().into_owned())
        }
        self.fs.workspace = self.workspace_abs()?;
        if self.image.is_none() && self.fs.rootfs != "host" {
            self.fs.rootfs = absolute(&self.fs.rootfs)?;
        }
        for pair in &mut self.fs.ro_bind {
            let (host, dest) = pair.split_once(':').ok_or("ro_bind: expected HOST:BOX")?;
            *pair = format!("{}:{dest}", absolute(host)?);
        }
        for path in &mut self.net.trust_ca {
            *path = absolute(path)?;
        }
        for spec in self.secrets.values_mut() {
            if let Some(path) = &mut spec.file {
                *path = absolute(path)?;
            }
        }
        if let Some(path) = &mut self.runsc {
            *path = absolute(path)?;
        }
        Ok(())
    }

    /// Persist references, never secret values. Literal secrets must be
    /// supplied again on resume (or provided via the named environment var).
    pub fn for_resume(&self) -> Self {
        let mut p = self.clone();
        for (name, spec) in &mut p.secrets {
            if spec.value.take().is_some() {
                spec.file = None; // a literal took precedence over this file
            }
            p.env.remove(name); // the runtime replaces this with a placeholder
        }
        p
    }

    /// The policy as a file: secrets keep only their host (never a value).
    pub fn to_toml(&self) -> String {
        let mut p = self.clone();
        for s in p.secrets.values_mut() {
            s.value = None;
        }
        toml::to_string_pretty(&p).unwrap_or_default()
    }

    /// Secrets as `NAME@HOST` / `NAME=VALUE@HOST` specs for `secrets::parse`.
    pub fn secret_specs(&self) -> Result<Vec<String>, String> {
        self.secrets
            .iter()
            .map(|(name, s)| match (&s.value, &s.file) {
                (Some(v), _) => Ok(format!("{name}={v}@{}", s.only)),
                (None, Some(f)) => Ok(format!("{name}={}@{}", read_secret_file(f)?, s.only)),
                (None, None) => Ok(format!("{name}@{}", s.only)),
            })
            .collect()
    }

    pub fn load(path: &Path) -> Result<Policy, String> {
        let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
        toml::from_str(&text).map_err(|e| format!("{}: {e}", path.display()))
    }

    pub fn workspace_abs(&self) -> Result<PathBuf, String> {
        std::fs::canonicalize(&self.fs.workspace)
            .map_err(|e| format!("workspace {}: {e}", self.fs.workspace.display()))
    }
}

/// A secret's value from a file. Refuses a file other users can read (as ssh
/// does with keys), and never puts the value in an error message.
fn read_secret_file(path: &str) -> Result<String, String> {
    use std::os::unix::fs::PermissionsExt;
    let p = match path.strip_prefix("~/") {
        Some(rest) => PathBuf::from(std::env::var("HOME").unwrap_or_default()).join(rest),
        None => PathBuf::from(path),
    };
    let md = std::fs::metadata(&p).map_err(|e| format!("secret file {}: {e}", p.display()))?;
    if md.permissions().mode() & 0o077 != 0 {
        return Err(format!(
            "secret file {} is readable by other users (mode {:o}) — chmod 600 it",
            p.display(),
            md.permissions().mode() & 0o777
        ));
    }
    let text = std::fs::read_to_string(&p).map_err(|e| format!("secret file {}: {e}", p.display()))?;
    let value = text.trim_end_matches(['\n', '\r']).to_string();
    if value.is_empty() {
        return Err(format!("secret file {} is empty", p.display()));
    }
    if value.contains('\n') {
        return Err(format!("secret file {} has more than one line", p.display()));
    }
    Ok(value)
}

/// Parse `run`'s arguments. Returns the policy, the command and the run options.
pub fn from_args(args: &[String]) -> Result<(Policy, Vec<String>, RunOpts), String> {
    let mut pol: Option<Policy> = None;
    let (mut rootfs, mut work) = (None::<String>, None::<PathBuf>);
    let mut allow: Vec<String> = vec![];
    let mut ro_bind: Vec<String> = vec![];
    let mut env: BTreeMap<String, String> = BTreeMap::new();
    let mut secrets: Vec<String> = vec![];
    let mut secret_files: Vec<String> = vec![];
    let mut trust_ca: Vec<String> = vec![];
    let mut map: Vec<String> = vec![];
    let mut workspace_mode: Option<String> = None;
    let (mut mem, mut pids, mut cpu) = (None::<String>, None::<u32>, None::<f64>);
    let (mut isolation, mut runsc) = (None::<String>, None::<String>);
    let mut image: Option<String> = None;
    let mut caps = LimitsSpec::default();
    let mut opts = RunOpts::default();
    let mut resume_target = None;
    let mut cmd: Vec<String> = vec![];
    let mut command_given = false;

    let mut it = args.iter().peekable();
    while let Some(a) = it.next() {
        if a == "--learn" {
            // Optional path: the next argument, unless it is a flag or `--`.
            let path = match it.peek() {
                Some(n) if !n.starts_with("--") => it.next().map(PathBuf::from),
                _ => None,
            };
            opts.learn = Some(path);
            continue;
        }
        let mut need = |what: &str| -> Result<String, String> {
            it.next().cloned().ok_or_else(|| format!("{what} needs a value"))
        };
        match a.as_str() {
            "--policy" => pol = Some(Policy::load(Path::new(&need("--policy")?))?),
            "--rootfs" => rootfs = Some(need("--rootfs")?),
            "--work" => work = Some(PathBuf::from(need("--work")?)),
            "--allow" => allow.push(need("--allow")?),
            "--ro-bind" => ro_bind.push(need("--ro-bind")?),
            "--env" => {
                let kv = need("--env")?;
                match kv.split_once('=') {
                    Some((k, v)) => env.insert(k.to_string(), v.to_string()),
                    // `--env KEY`: pass the caller's value through.
                    None => match std::env::var(&kv) {
                        Ok(v) => env.insert(kv, v),
                        Err(_) => None,
                    },
                };
            }
            "--secret" => secrets.push(need("--secret")?),
            "--secret-file" => secret_files.push(need("--secret-file")?),
            "--trust-ca" => trust_ca.push(need("--trust-ca")?),
            "--map" => map.push(need("--map")?),
            "--workspace-mode" => workspace_mode = Some(need("--workspace-mode")?),
            "--isolation" => isolation = Some(need("--isolation")?),
            "--runsc" => runsc = Some(need("--runsc")?),
            "--image" => image = Some(need("--image")?),
            "--disk" => caps.disk = Some(need("--disk")?),
            "--tmpfs" => caps.tmpfs = Some(need("--tmpfs")?),
            "--file-size" => caps.file_size = Some(need("--file-size")?),
            "--bytes-out" => caps.bytes_out = Some(need("--bytes-out")?),
            "--bytes-in" => caps.bytes_in = Some(need("--bytes-in")?),
            "--mem" => mem = Some(need("--mem")?),
            "--pids" => pids = Some(need("--pids")?.parse().map_err(|_| "--pids: expected a number")?),
            "--cpu" => cpu = Some(need("--cpu")?.parse().map_err(|_| "--cpu: expected a number of cores")?),
            "--session" => opts.session = Some(PathBuf::from(need("--session")?)),
            "--resume" => {
                if resume_target.is_some() {
                    return Err("--resume may only be supplied once".into());
                }
                resume_target = Some(need("--resume")?);
            }
            "--quiet" => opts.quiet = true,
            "--" => {
                command_given = true;
                cmd = it.cloned().collect();
                break;
            }
            other => return Err(format!("unknown flag {other}")),
        }
    }
    if let Some(target) = resume_target {
        if opts.session.is_some() {
            return Err("--resume and --session cannot be combined".into());
        }
        let resumed = crate::workspace::Resume::open(&target)?;
        if pol.is_none() {
            pol = Some(resumed.meta.policy.clone().ok_or(
                "this older session has no saved policy; supply --policy FILE when resuming it (the policy will then be saved)"
            )?);
        }
        if work.is_none() && pol.as_ref().unwrap().fs.workspace == Path::new(".") {
            pol.as_mut().unwrap().fs.workspace = resumed.meta.workspace.clone();
        }
        if !command_given {
            cmd = resumed.meta.cmd.clone();
        }
        opts.resume = Some(resumed);
    }
    if cmd.is_empty() {
        return Err("nothing to run: expected `-- COMMAND [ARGS...]`".into());
    }

    let mut p = pol.unwrap_or_default();
    if let Some(r) = rootfs {
        p.fs.rootfs = r;
    }
    if let Some(w) = work {
        p.fs.workspace = w;
    }
    p.net.allow.extend(allow);
    p.net.trust_ca.extend(trust_ca);
    p.net.map.extend(map);
    p.fs.ro_bind.extend(ro_bind);
    if let Some(m) = workspace_mode {
        if m != "overlay" && m != "bind" {
            return Err(format!("--workspace-mode `{m}`: expected overlay or bind"));
        }
        p.fs.workspace_mode = m;
    }
    if let Some(i) = isolation {
        if i != "ns" && i != "gvisor" {
            return Err(format!("--isolation `{i}`: expected ns or gvisor"));
        }
        p.isolation = i;
    }
    if runsc.is_some() {
        p.runsc = runsc;
    }
    if image.is_some() {
        p.image = image;
    }
    if mem.is_some() {
        p.limits.mem = mem;
    }
    if pids.is_some() {
        p.limits.pids = pids;
    }
    if cpu.is_some() {
        p.limits.cpu = cpu;
    }
    if caps.disk.is_some() { p.limits.disk = caps.disk; }
    if caps.tmpfs.is_some() { p.limits.tmpfs = caps.tmpfs; }
    if caps.file_size.is_some() { p.limits.file_size = caps.file_size; }
    if caps.bytes_out.is_some() { p.limits.bytes_out = caps.bytes_out; }
    if caps.bytes_in.is_some() { p.limits.bytes_in = caps.bytes_in; }
    crate::storage::Caps::parse(&p)?;
    p.env.extend(env);
    for spec in secrets {
        // Never echo the spec back: it may hold the value.
        let name_only = spec.split(['=', '@']).next().unwrap_or("").to_string();
        let (lhs, host) = spec
            .rsplit_once('@')
            .ok_or_else(|| format!("--secret {name_only}…: expected NAME@HOST or NAME=VALUE@HOST"))?;
        let (name, value) = match lhs.split_once('=') {
            Some((n, v)) => (n.to_string(), Some(v.to_string())),
            None => (lhs.to_string(), None),
        };
        p.secrets.insert(name, SecretSpec { only: host.to_string(), value, file: None });
    }
    for spec in secret_files {
        let (lhs, host) = spec.rsplit_once('@').ok_or_else(|| format!("--secret-file `{spec}`: expected NAME=PATH@HOST"))?;
        let (name, path) = lhs.split_once('=').ok_or_else(|| format!("--secret-file `{spec}`: expected NAME=PATH@HOST"))?;
        p.secrets.insert(name.to_string(), SecretSpec { only: host.to_string(), value: None, file: Some(path.to_string()) });
    }
    Ok((p, cmd, opts))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn limit_flags_override_toml_and_survive_saved_policy() {
        let path = std::env::temp_dir().join(format!("plybox-policy-caps-{}.toml", std::process::id()));
        std::fs::write(&path, "[limits]\nfile_size='8K'\ntmpfs='3M'\nbytes_out='2M'\nbytes_in='1M'\n").unwrap();
        let args = vec!["--policy".into(), path.to_string_lossy().into_owned(), "--file-size".into(), "4K".into(),
            "--bytes-in".into(), "0".into(), "--".into(), "true".into()];
        let result = from_args(&args);
        let _ = std::fs::remove_file(path);
        let (p, _, _) = result.unwrap();
        let saved: Policy = serde_json::from_str(&serde_json::to_string(&p.for_resume()).unwrap()).unwrap();
        let caps = crate::storage::Caps::parse(&saved).unwrap();
        assert_eq!(caps.file_size, Some(4096));
        assert_eq!(caps.tmpfs, Some(3145728));
        assert_eq!(caps.bytes_out, Some(2097152));
        assert_eq!(caps.bytes_in, Some(0));
    }
}
