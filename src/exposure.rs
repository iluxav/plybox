//! What a run exposes from the host: every host path the box can read,
//! where each secret's value comes from and where it may go, and every name
//! pinned to an address. Printed at startup (unless --quiet) and recorded in
//! the session's start event, so a policy that reaches into the host is
//! visible before the run and auditable after it.
//!
//! Values are never part of this: a secret is listed by name, source and
//! destination only.

use crate::policy::Policy;
use serde_json::{json, Value};
use std::path::Path;

/// Host files a `rootfs = "host"` box sees besides /usr, when they exist.
/// Both tiers mount exactly this list. `/etc/alternatives` is where Debian
/// and Ubuntu point commands such as `awk` and `editor`.
pub const HOST_ETC: [&str; 8] = [
    "/etc/ssl", "/etc/ca-certificates", "/etc/passwd", "/etc/group", "/etc/hosts", "/etc/ld.so.cache", "/etc/localtime",
    "/etc/alternatives",
];

/// The host root's top-level program and library directories.
const HOST_TOP: [&str; 6] = ["bin", "sbin", "lib", "lib64", "lib32", "libx32"];

#[derive(Debug, PartialEq)]
pub enum TopLevel {
    /// A merged-/usr link, recreated in the box with the same target.
    Link(String),
    /// A real directory (an older, unmerged layout), bound read-only.
    Dir,
}

/// How a `rootfs = "host"` box reproduces the host's `/bin`, `/lib`,
/// `/lib64`…: the same links, not one distribution's. Ubuntu links
/// `/lib64` to `usr/lib64` (where the ELF loader lives), Arch to `usr/lib`;
/// a wrong guess leaves every program without its loader ("No such file").
pub fn host_top_level(root: &Path) -> Vec<(&'static str, TopLevel)> {
    HOST_TOP
        .iter()
        .filter_map(|name| {
            let p = root.join(name);
            match std::fs::symlink_metadata(&p) {
                Ok(m) if m.file_type().is_symlink() => {
                    std::fs::read_link(&p).ok().map(|t| (*name, TopLevel::Link(t.to_string_lossy().into_owned())))
                }
                Ok(m) if m.is_dir() => Some((*name, TopLevel::Dir)),
                _ => None,
            }
        })
        .collect()
}

#[derive(Debug, PartialEq)]
pub struct Item {
    /// `system`, `rootfs`, `workspace`, `ro_bind`, `secret_file`,
    /// `secret_env`, `secret_inline`, `trust_ca`, `map`.
    pub kind: &'static str,
    /// The host side: a path, `$VAR`, or a host name (for `map`).
    pub host: String,
    /// Where it shows up in the box, or where it may be sent.
    pub to: String,
    /// The secret's name in the box (secrets only).
    pub name: Option<String>,
}

fn item(kind: &'static str, host: impl Into<String>, to: impl Into<String>) -> Item {
    Item { kind, host: host.into(), to: to.into(), name: None }
}

/// Everything the policy exposes. `pol` has absolute paths already;
/// `workspace` is how /work is mounted (`copy`, `read-write`, `read-only`).
pub fn of(pol: &Policy, work: &Path, workspace: &str, image: bool) -> Vec<Item> {
    let mut v = vec![];
    match pol.fs.rootfs.as_str() {
        "host" => {
            v.push(item("system", "/usr", "/usr"));
            for (name, kind) in host_top_level(Path::new("/")) {
                if kind == TopLevel::Dir {
                    v.push(item("system", format!("/{name}"), format!("/{name}")));
                }
            }
            for f in HOST_ETC {
                if Path::new(f).exists() {
                    v.push(item("system", f, f));
                }
            }
        }
        // An image is the registry's content, cached; its reference and
        // digest are already in the start event.
        _ if image => {}
        dir => v.push(item("rootfs", dir, "/")),
    }
    v.push(item("workspace", work.to_string_lossy(), format!("/work ({workspace})")));
    for pair in &pol.fs.ro_bind {
        if let Some((h, b)) = pair.split_once(':') {
            v.push(item("ro_bind", h, b));
        }
    }
    for (name, s) in &pol.secrets {
        let mut it = match (&s.value, &s.file) {
            (Some(_), _) => item("secret_inline", "(value given in the policy or flags)", &s.only),
            (None, Some(f)) => item("secret_file", f, &s.only),
            (None, None) => item("secret_env", format!("${name}"), &s.only),
        };
        it.name = Some(name.clone());
        v.push(it);
    }
    for f in &pol.net.trust_ca {
        v.push(item("trust_ca", f, "proxy upstream TLS"));
    }
    for m in &pol.net.map {
        if let Some((host, addr)) = m.split_once('=') {
            v.push(item("map", host.trim(), addr.trim()));
        }
    }
    v
}

pub fn to_json(items: &[Item]) -> Value {
    Value::Array(
        items
            .iter()
            .map(|i| {
                let mut o = json!({ "kind": i.kind, "host": i.host, "to": i.to });
                if let Some(n) = &i.name {
                    o["name"] = json!(n);
                }
                o
            })
            .collect(),
    )
}

/// Human lines for stderr, one per exposure; the host system files are
/// folded into one line (they are the same on every run).
pub fn lines(items: &[Item]) -> Vec<String> {
    let mut out = vec![];
    let system: Vec<&str> = items.iter().filter(|i| i.kind == "system").map(|i| i.host.as_str()).collect();
    if !system.is_empty() {
        out.push(format!("reads   {} (host system, read-only)", system.join(" ")));
    }
    for i in items.iter().filter(|i| i.kind != "system") {
        let name = i.name.as_deref().unwrap_or("");
        out.push(match i.kind {
            "rootfs" => format!("reads   {} as / (read-only)", i.host),
            "workspace" if i.to.contains("read-write") => format!("writes  {} at {}", i.host, i.to),
            "workspace" => format!("reads   {} at {}", i.host, i.to),
            "ro_bind" => format!("reads   {} at {} (read-only)", i.host, i.to),
            "secret_file" => format!("secret  {name} from file {} — sent only to {}", i.host, i.to),
            "secret_env" => format!("secret  {name} from plybox's environment {} — sent only to {}", i.host, i.to),
            "secret_inline" => format!("secret  {name} given inline — sent only to {}", i.to),
            "trust_ca" => format!("trusts  {} for upstream TLS (proxy side)", i.host),
            "map" => format!("maps    {} → {} (skips the public-address rule)", i.host, i.to),
            _ => format!("{} {} → {}", i.kind, i.host, i.to),
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::SecretSpec;

    #[test]
    fn lists_every_host_reach_and_never_a_secret_value() {
        let mut p = Policy::default();
        p.fs.rootfs = "/srv/root".into();
        p.fs.ro_bind = vec!["/home/u/.rustup:/opt/rustup".into()];
        p.secrets.insert("A".into(), SecretSpec { only: "a.example".into(), value: Some("s3cr3t-value".into()), file: None });
        p.secrets.insert("B".into(), SecretSpec { only: "b.example".into(), value: None, file: Some("/home/u/tok".into()) });
        p.secrets.insert("C".into(), SecretSpec { only: "c.example".into(), value: None, file: None });
        p.net.trust_ca = vec!["/home/u/ca.pem".into()];
        p.net.map = vec!["svc.test=10.0.0.5:8443".into()];
        let items = of(&p, Path::new("/home/u/proj"), "copy", false);
        let kinds: Vec<&str> = items.iter().map(|i| i.kind).collect();
        assert_eq!(kinds, ["rootfs", "workspace", "ro_bind", "secret_inline", "secret_file", "secret_env", "trust_ca", "map"]);
        assert_eq!(items[4], Item { kind: "secret_file", host: "/home/u/tok".into(), to: "b.example".into(), name: Some("B".into()) });
        assert_eq!(items[5].host, "$C");
        let all = format!("{}\n{}", to_json(&items), lines(&items).join("\n"));
        assert!(!all.contains("s3cr3t-value"), "a secret value leaked: {all}");
        for want in ["/srv/root", "/home/u/proj", "/home/u/.rustup", "/home/u/tok", "/home/u/ca.pem", "svc.test", "10.0.0.5:8443"] {
            assert!(all.contains(want), "missing {want}: {all}");
        }
    }

    #[test]
    fn host_top_level_mirrors_links_and_binds_real_dirs() {
        let root = std::env::temp_dir().join(format!("plybox-top-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("lib32")).unwrap();
        std::os::unix::fs::symlink("usr/bin", root.join("bin")).unwrap();
        std::os::unix::fs::symlink("usr/lib64", root.join("lib64")).unwrap(); // Ubuntu's
        let got = host_top_level(&root);
        let _ = std::fs::remove_dir_all(&root);
        assert_eq!(got, [("bin", TopLevel::Link("usr/bin".into())), ("lib64", TopLevel::Link("usr/lib64".into())), ("lib32", TopLevel::Dir)]);
    }

    #[test]
    fn image_root_is_not_a_host_path_and_host_root_folds_to_one_line() {
        let mut p = Policy::default();
        p.fs.rootfs = "/cache/images/abc/rootfs".into();
        assert!(of(&p, Path::new("/w"), "copy", true).iter().all(|i| i.kind != "rootfs"));
        p.fs.rootfs = "host".into();
        let items = of(&p, Path::new("/w"), "copy", false);
        assert!(items.iter().any(|i| i.kind == "system" && i.host == "/usr"));
        assert_eq!(lines(&items).iter().filter(|l| l.contains("host system")).count(), 1);
    }
}
