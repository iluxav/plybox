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
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Fs {
    /// `"host"` or a directory to use as `/`.
    #[serde(default = "default_rootfs")]
    pub rootfs: String,
    /// Mounted read-write at /work; the box starts there.
    #[serde(default = "default_workspace")]
    pub workspace: PathBuf,
    /// Extra read-only binds, `HOSTPATH:BOXPATH`.
    #[serde(default)]
    pub ro_bind: Vec<String>,
}

impl Default for Fs {
    fn default() -> Self {
        Fs { rootfs: default_rootfs(), workspace: default_workspace(), ro_bind: vec![] }
    }
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
}

impl Policy {
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
    p.fs.ro_bind.extend(ro_bind);
    p.env.extend(env);
    Ok((p, cmd, session, quiet))
}
