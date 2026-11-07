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

use serde::Deserialize;

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    #[serde(default)]
    pub fs: Fs,
    #[serde(default)]
    pub net: Net,
    /// Environment inside the box. Values here win over the defaults.
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    /// Secrets the box must never hold: `NAME = { only = "host" }` takes the
    /// value from the caller's environment variable NAME; add `value = "…"`
    /// for a literal. The box gets a placeholder under NAME; the proxy swaps
    /// it for the value only toward `only`.
    #[serde(default)]
    pub secrets: BTreeMap<String, SecretSpec>,
    /// Per-box limits: `mem = "512M"`, `pids = 512`, `cpu = 1.5` (cores).
    #[serde(default)]
    pub limits: LimitsSpec,
    /// `"ns"` (default): namespaces via bubblewrap. `"gvisor"`: gVisor's
    /// user-space kernel in between, for code you do not trust.
    #[serde(default = "default_isolation")]
    pub isolation: String,
    /// Path to gVisor's `runsc` (default: found on PATH).
    #[serde(default)]
    pub runsc: Option<String>,
}

fn default_isolation() -> String {
    "ns".into()
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct LimitsSpec {
    #[serde(default)]
    pub mem: Option<String>,
    #[serde(default)]
    pub pids: Option<u32>,
    #[serde(default)]
    pub cpu: Option<f64>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretSpec {
    pub only: String,
    #[serde(default)]
    pub value: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
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
    #[serde(default)]
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

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct Net {
    /// Hostnames the proxy will connect to: `host`, `*.suffix`, `host:port`.
    /// Empty = the box reaches nothing.
    #[serde(default)]
    pub allow: Vec<String>,
    /// Extra PEM roots the proxy trusts when it talks to upstreams (test
    /// servers with their own CA). Normal use needs none.
    #[serde(default)]
    pub trust_ca: Vec<String>,
    /// `host=ip:port`: resolve `host` to a fixed address instead of DNS, and
    /// skip the public-address rule for it. For test upstreams only.
    #[serde(default)]
    pub map: Vec<String>,
}

impl Policy {
    /// Secrets as `NAME@HOST` / `NAME=VALUE@HOST` specs for `secrets::parse`.
    pub fn secret_specs(&self) -> Vec<String> {
        self.secrets
            .iter()
            .map(|(name, s)| match &s.value {
                Some(v) => format!("{name}={v}@{}", s.only),
                None => format!("{name}@{}", s.only),
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

/// Parse `run`'s arguments. Returns the policy, the command, the session
/// directory (if given) and the quiet flag.
pub fn from_args(args: &[String]) -> Result<(Policy, Vec<String>, Option<PathBuf>, bool), String> {
    let mut pol: Option<Policy> = None;
    let (mut rootfs, mut work) = (None::<String>, None::<PathBuf>);
    let mut allow: Vec<String> = vec![];
    let mut ro_bind: Vec<String> = vec![];
    let mut env: BTreeMap<String, String> = BTreeMap::new();
    let mut secrets: Vec<String> = vec![];
    let mut trust_ca: Vec<String> = vec![];
    let mut map: Vec<String> = vec![];
    let mut workspace_mode: Option<String> = None;
    let (mut mem, mut pids, mut cpu) = (None::<String>, None::<u32>, None::<f64>);
    let (mut isolation, mut runsc) = (None::<String>, None::<String>);
    let mut session: Option<PathBuf> = None;
    let mut quiet = false;
    let mut cmd: Vec<String> = vec![];

    let mut it = args.iter();
    while let Some(a) = it.next() {
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
            "--trust-ca" => trust_ca.push(need("--trust-ca")?),
            "--map" => map.push(need("--map")?),
            "--workspace-mode" => workspace_mode = Some(need("--workspace-mode")?),
            "--isolation" => isolation = Some(need("--isolation")?),
            "--runsc" => runsc = Some(need("--runsc")?),
            "--mem" => mem = Some(need("--mem")?),
            "--pids" => pids = Some(need("--pids")?.parse().map_err(|_| "--pids: expected a number")?),
            "--cpu" => cpu = Some(need("--cpu")?.parse().map_err(|_| "--cpu: expected a number of cores")?),
            "--session" => session = Some(PathBuf::from(need("--session")?)),
            "--quiet" => quiet = true,
            "--" => {
                cmd = it.cloned().collect();
                break;
            }
            other => return Err(format!("unknown flag {other}")),
        }
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
    if mem.is_some() {
        p.limits.mem = mem;
    }
    if pids.is_some() {
        p.limits.pids = pids;
    }
    if cpu.is_some() {
        p.limits.cpu = cpu;
    }
    p.env.extend(env);
    for spec in secrets {
        let (lhs, host) = spec.rsplit_once('@').ok_or_else(|| format!("--secret `{spec}`: expected NAME@HOST or NAME=VALUE@HOST"))?;
        let (name, value) = match lhs.split_once('=') {
            Some((n, v)) => (n.to_string(), Some(v.to_string())),
            None => (lhs.to_string(), None),
        };
        p.secrets.insert(name, SecretSpec { only: host.to_string(), value });
    }
    Ok((p, cmd, session, quiet))
}
