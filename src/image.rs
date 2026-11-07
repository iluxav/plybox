//! OCI images as the box's root filesystem: `plybox pull` and `--image`.
//!
//! No Docker, no daemon: the registry v2 API over HTTPS, then each layer is
//! downloaded, its sha256 checked against the manifest, and applied in order
//! to one directory (Docker's whiteout files honored). The result is cached
//! under `$XDG_DATA_HOME/plybox/images/<ref>/` as `rootfs/` + `image.json`
//! and mounted read-only as the box's `/`, with an in-memory layer on top.
//!
//! Based on ply's importer (`ply-core/src/oci.rs`), with three additions,
//! because an image is untrusted input:
//!   * every layer blob is verified against its digest before it is applied;
//!   * every path a layer names — entries, whiteouts, hardlink targets — is
//!     checked to stay inside the rootfs, including through symlinks that an
//!     earlier entry planted, before anything is created or deleted;
//!   * setuid/setgid bits are dropped and device nodes are skipped.

use std::collections::BTreeMap;
use std::fs::File;
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const ACCEPT: &str = "application/vnd.oci.image.index.v1+json, \
     application/vnd.oci.image.manifest.v1+json, \
     application/vnd.docker.distribution.manifest.list.v2+json, \
     application/vnd.docker.distribution.manifest.v2+json";

/// What `run` needs from a pulled image.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Meta {
    pub reference: String,
    /// sha256 of the platform manifest: the image's identity.
    pub digest: String,
    pub env: Vec<String>,
    pub entrypoint: Vec<String>,
    pub cmd: Vec<String>,
    pub working_dir: Option<String>,
    pub pulled: u64,
}

pub struct Image {
    pub rootfs: PathBuf,
    pub meta: Meta,
}

// ---------------------------------------------------------------- refs

struct Ref {
    registry: String,
    repository: String,
    /// A tag or a `sha256:` digest.
    reference: String,
}

fn parse_ref(spec: &str) -> Result<Ref, String> {
    let spec = spec.strip_prefix("docker://").unwrap_or(spec);
    if spec.is_empty() || spec.contains(char::is_whitespace) {
        return Err(format!("image `{spec}`: not a reference"));
    }
    let (name, reference) = if let Some((n, d)) = spec.split_once('@') {
        (n.to_string(), d.to_string())
    } else {
        match spec.rsplit_once(':') {
            Some((n, t)) if !t.contains('/') => (n.to_string(), t.to_string()),
            _ => (spec.to_string(), "latest".to_string()),
        }
    };
    let (registry, repository) = match name.split_once('/') {
        Some((host, path)) if host.contains('.') || host.contains(':') || host == "localhost" => {
            (host.to_string(), path.to_string())
        }
        Some(_) => ("registry-1.docker.io".to_string(), name.clone()),
        None => ("registry-1.docker.io".to_string(), format!("library/{name}")),
    };
    Ok(Ref { registry, repository, reference })
}

/// `registry/repository:tag` (or `@sha256:…`): the form an operator's
/// approved-image list is compared in, so `python:3.13-slim` and
/// `docker.io/library/python:3.13-slim` are the same image.
pub fn canonical(spec: &str) -> Result<String, String> {
    let r = parse_ref(spec)?;
    let sep = if r.reference.starts_with("sha256:") { '@' } else { ':' };
    Ok(format!("{}/{}{sep}{}", docker_hub(&r.registry), r.repository, r.reference))
}

fn docker_hub(registry: &str) -> &str {
    if ["docker.io", "index.docker.io"].contains(&registry) { "registry-1.docker.io" } else { registry }
}

/// Whether `spec` is on `list`: exact references, or a prefix ending in `*`
/// (`python:*` = every python tag, `ghcr.io/acme/*` = everything under it).
pub fn approved(spec: &str, list: &[String]) -> Result<bool, String> {
    let want = canonical(spec)?;
    for entry in list {
        let hit = match entry.strip_suffix('*') {
            Some(prefix) => {
                let prefix = prefix.strip_prefix("docker://").unwrap_or(prefix);
                let full = match prefix.split_once('/') {
                    Some((host, rest)) if host.contains('.') || host.contains(':') || host == "localhost" => {
                        format!("{}/{rest}", docker_hub(host))
                    }
                    Some(_) => format!("registry-1.docker.io/{prefix}"),
                    None => format!("registry-1.docker.io/library/{prefix}"),
                };
                want.starts_with(&full)
            }
            None => canonical(entry)? == want,
        };
        if hit {
            return Ok(true);
        }
    }
    Ok(false)
}

pub fn slug(spec: &str) -> String {
    spec.strip_prefix("docker://")
        .unwrap_or(spec)
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '.' { c } else { '-' })
        .collect()
}

pub fn images_base() -> PathBuf {
    let data = std::env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".local/share")))
        .unwrap_or_else(|| PathBuf::from("/tmp"));
    data.join("plybox/images")
}

// -------------------------------------------------------------- client

struct Client {
    agent: ureq::Agent,
    registry: String,
    repository: String,
    token: Option<String>,
}

impl Client {
    fn new(r: &Ref) -> Client {
        let agent: ureq::Agent = ureq::Agent::config_builder()
            .http_status_as_error(false)
            .timeout_global(Some(std::time::Duration::from_secs(600)))
            .build()
            .into();
        Client { agent, registry: r.registry.clone(), repository: r.repository.clone(), token: None }
    }

    fn get(&mut self, path: &str, accept: &str) -> Result<ureq::http::Response<ureq::Body>, String> {
        let url = format!("https://{}/v2/{}/{path}", self.registry, self.repository);
        for attempt in 0..2 {
            let mut req = self.agent.get(&url).header("Accept", accept);
            if let Some(t) = &self.token {
                req = req.header("Authorization", &format!("Bearer {t}"));
            }
            let resp = req.call().map_err(|e| format!("{url}: {e}"))?;
            let status = resp.status().as_u16();
            if status == 401 && attempt == 0 {
                let challenge = resp
                    .headers()
                    .get("www-authenticate")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("")
                    .to_string();
                self.token = Some(self.fetch_token(&challenge)?);
                continue;
            }
            if !(200..300).contains(&status) {
                return Err(format!("{url}: HTTP {status}"));
            }
            return Ok(resp);
        }
        Err(format!("{url}: unauthorized"))
    }

    /// Anonymous pull token from the realm the registry names in its
    /// `WWW-Authenticate: Bearer realm=…,service=…` challenge.
    fn fetch_token(&self, challenge: &str) -> Result<String, String> {
        let params = parse_challenge(challenge);
        let realm = params.get("realm").ok_or_else(|| format!("{}: no token realm in `{challenge}`", self.registry))?;
        let mut url = format!("{realm}?scope=repository:{}:pull", self.repository);
        if let Some(service) = params.get("service") {
            url.push_str(&format!("&service={service}"));
        }
        let mut resp = self.agent.get(&url).call().map_err(|e| format!("token {url}: {e}"))?;
        if !resp.status().is_success() {
            return Err(format!("token {url}: HTTP {}", resp.status().as_u16()));
        }
        let body: serde_json::Value = serde_json::from_str(&resp.body_mut().read_to_string().map_err(|e| format!("token: {e}"))?)
            .map_err(|e| format!("token: {e}"))?;
        body.get("token")
            .or_else(|| body.get("access_token"))
            .and_then(|v| v.as_str())
            .map(str::to_string)
            .ok_or_else(|| "token response has no token".into())
    }

    fn json(&mut self, path: &str, accept: &str) -> Result<(Vec<u8>, serde_json::Value), String> {
        let mut resp = self.get(path, accept)?;
        let bytes = resp
            .body_mut()
            .with_config()
            .limit(16 * 1024 * 1024)
            .read_to_vec()
            .map_err(|e| format!("{path}: {e}"))?;
        let v = serde_json::from_slice(&bytes).map_err(|e| format!("{path}: {e}"))?;
        Ok((bytes, v))
    }

    /// Download a blob to `dest`, verifying its sha256 against `digest`.
    fn blob(&mut self, digest: &str, dest: &Path) -> Result<u64, String> {
        let want = digest.strip_prefix("sha256:").ok_or_else(|| format!("unsupported digest `{digest}`"))?;
        let resp = self.get(&format!("blobs/{digest}"), "*/*")?;
        let mut reader = resp.into_body().into_reader();
        let mut out = File::create(dest).map_err(|e| format!("{}: {e}", dest.display()))?;
        let mut hasher = Sha256::new();
        let mut buf = vec![0u8; 1 << 16];
        let mut total = 0u64;
        loop {
            let n = reader.read(&mut buf).map_err(|e| format!("blob {digest}: {e}"))?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
            out.write_all(&buf[..n]).map_err(|e| format!("{}: {e}", dest.display()))?;
            total += n as u64;
        }
        let got = hex(&hasher.finalize());
        if got != want {
            return Err(format!("blob {digest}: content hashes to sha256:{got} — refusing a tampered or corrupt layer"));
        }
        Ok(total)
    }
}

fn parse_challenge(h: &str) -> BTreeMap<String, String> {
    let mut m = BTreeMap::new();
    let rest = h.trim().strip_prefix("Bearer").unwrap_or(h).trim();
    for part in rest.split(',') {
        if let Some((k, v)) = part.split_once('=') {
            m.insert(k.trim().to_ascii_lowercase(), v.trim().trim_matches('"').to_string());
        }
    }
    m
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn host_arch() -> &'static str {
    match std::env::consts::ARCH {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        other => other,
    }
}

// ---------------------------------------------------------------- pull

/// The cached image for `spec`, pulling it if absent (or if `refresh`).
pub fn ensure(spec: &str, refresh: bool, quiet: bool) -> Result<Image, String> {
    let dir = images_base().join(slug(spec));
    let meta_path = dir.join("image.json");
    if !refresh {
        if let Ok(text) = std::fs::read_to_string(&meta_path) {
            if let Ok(meta) = serde_json::from_str::<Meta>(&text) {
                if dir.join("rootfs").is_dir() {
                    prepare_mountpoints(&dir.join("rootfs"));
                    return Ok(Image { rootfs: dir.join("rootfs"), meta });
                }
            }
        }
    }
    pull(spec, &dir, quiet)
}

/// The fixed places plybox mounts onto, created once in the image so that no
/// run has to: bubblewrap would create them in its in-memory layer, but
/// gVisor creates missing mount points in the image directory itself (the
/// lab saw `/work`, `/plybox`, `/run/plybox` appear in a cached image).
/// Empty directories and two empty files; idempotent.
pub fn prepare_mountpoints(rootfs: &Path) {
    for d in ["proc", "dev", "sys", "tmp", "home/box", "work", "run/plybox/sock", "etc"] {
        let _ = std::fs::create_dir_all(rootfs.join(d));
    }
    for f in ["plybox", "etc/passwd", "etc/group"] {
        let p = rootfs.join(f);
        if std::fs::symlink_metadata(&p).is_err() {
            let _ = std::fs::write(&p, b"");
        }
    }
}

pub fn pull(spec: &str, dir: &Path, quiet: bool) -> Result<Image, String> {
    let r = parse_ref(spec)?;
    let mut c = Client::new(&r);
    let say = |s: String| {
        if !quiet {
            eprintln!("plybox: {s}");
        }
    };

    // Manifest; an index resolves to this host's platform.
    let (mut bytes, mut doc) = c.json(&format!("manifests/{}", r.reference), ACCEPT)?;
    if let Some(list) = doc.get("manifests").and_then(|m| m.as_array()) {
        let want = host_arch();
        let chosen = list
            .iter()
            .find(|m| {
                let p = &m["platform"];
                p["os"] == "linux" && p["architecture"] == want
            })
            .and_then(|m| m["digest"].as_str())
            .ok_or_else(|| format!("{spec}: no linux/{want} image in the index"))?
            .to_string();
        let (b, d) = c.json(&format!("manifests/{chosen}"), ACCEPT)?;
        let got = format!("sha256:{}", hex(&Sha256::digest(&b)));
        if got != chosen {
            return Err(format!("{spec}: platform manifest hashes to {got}, index said {chosen}"));
        }
        bytes = b;
        doc = d;
    }
    let digest = format!("sha256:{}", hex(&Sha256::digest(&bytes)));
    let layers: Vec<String> = doc["layers"]
        .as_array()
        .ok_or_else(|| format!("{spec}: manifest has no layers"))?
        .iter()
        .filter_map(|l| l["digest"].as_str().map(str::to_string))
        .collect();
    if layers.is_empty() {
        return Err(format!("{spec}: manifest has no layers"));
    }

    // Build in a temp dir beside the cache entry; rename at the end, so an
    // interrupted pull never leaves a half-image that `ensure` would trust.
    let base = dir.parent().ok_or("bad image dir")?;
    std::fs::create_dir_all(base).map_err(|e| format!("{}: {e}", base.display()))?;
    let tmp = base.join(format!(".pull-{}-{}", slug(spec), std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    let rootfs = tmp.join("rootfs");
    let blobs = tmp.join("blobs");
    std::fs::create_dir_all(&rootfs).map_err(|e| format!("{}: {e}", rootfs.display()))?;
    std::fs::create_dir_all(&blobs).map_err(|e| format!("{}: {e}", blobs.display()))?;

    // Config: env, entrypoint, cmd, workdir.
    let mut meta = Meta {
        reference: spec.to_string(),
        digest: digest.clone(),
        env: vec![],
        entrypoint: vec![],
        cmd: vec![],
        working_dir: None,
        pulled: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0),
    };
    if let Some(cd) = doc["config"]["digest"].as_str() {
        let p = blobs.join("config.json");
        c.blob(cd, &p)?;
        let cfg: serde_json::Value = serde_json::from_slice(&std::fs::read(&p).map_err(|e| e.to_string())?).map_err(|e| format!("config: {e}"))?;
        let strs = |v: &serde_json::Value| -> Vec<String> {
            v.as_array().map(|a| a.iter().filter_map(|s| s.as_str().map(str::to_string)).collect()).unwrap_or_default()
        };
        let cc = &cfg["config"];
        meta.env = strs(&cc["Env"]);
        meta.entrypoint = strs(&cc["Entrypoint"]);
        meta.cmd = strs(&cc["Cmd"]);
        meta.working_dir = cc["WorkingDir"].as_str().filter(|s| s.starts_with('/')).map(str::to_string);
    }

    say(format!("pulling {spec} ({} layer(s), {})", layers.len(), &digest[..19]));
    let mut modes: BTreeMap<PathBuf, u32> = BTreeMap::new();
    let root_canon = std::fs::canonicalize(&rootfs).map_err(|e| e.to_string())?;
    for (i, ld) in layers.iter().enumerate() {
        let p = blobs.join(ld.replace(':', "-"));
        let n = c.blob(ld, &p)?;
        say(format!("  layer {}/{} {} ({:.1} MB, verified)", i + 1, layers.len(), &ld[..19], n as f64 / 1e6));
        apply_layer(&p, &root_canon, &mut modes).map_err(|e| format!("layer {ld}: {e}"))?;
        let _ = std::fs::remove_file(&p);
    }
    // Seal directory modes deepest first (a 0555 dir must not block its own
    // contents while later layers are still being written).
    for (d, m) in modes.iter().rev() {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(d, std::fs::Permissions::from_mode(*m));
    }
    let _ = std::fs::remove_dir_all(&blobs);
    prepare_mountpoints(&rootfs);
    std::fs::write(tmp.join("image.json"), serde_json::to_string_pretty(&meta).unwrap()).map_err(|e| e.to_string())?;

    if dir.exists() {
        make_removable(dir);
        std::fs::remove_dir_all(dir).map_err(|e| format!("replace {}: {e}", dir.display()))?;
    }
    std::fs::rename(&tmp, dir).map_err(|e| format!("{} → {}: {e}", tmp.display(), dir.display()))?;
    say(format!("{spec} ready: {}", dir.join("rootfs").display()));
    Ok(Image { rootfs: dir.join("rootfs"), meta })
}

/// Restore owner-write on every directory, so a sealed 0555 tree can be removed.
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

pub fn list() -> Vec<Meta> {
    let mut out = vec![];
    if let Ok(rd) = std::fs::read_dir(images_base()) {
        for e in rd.flatten() {
            if let Ok(t) = std::fs::read_to_string(e.path().join("image.json")) {
                if let Ok(m) = serde_json::from_str::<Meta>(&t) {
                    out.push(m);
                }
            }
        }
    }
    out.sort_by(|a, b| a.reference.cmp(&b.reference));
    out
}

// --------------------------------------------------------- extraction

/// A layer path made safe: relative, no `..`, no root, no prefix. Leading
/// `/` and `./` are stripped (both appear in real images). None = refuse.
fn clean(p: &Path) -> Option<PathBuf> {
    let mut out = PathBuf::new();
    for c in p.components() {
        match c {
            Component::Normal(s) => out.push(s),
            Component::CurDir | Component::RootDir => {}
            Component::ParentDir | Component::Prefix(_) => return None,
        }
    }
    Some(out)
}

/// `rel`'s parent, resolved through any symlinks, must still be inside the
/// rootfs. Defeats a layer that first plants `etc -> /home/me` and then
/// writes or deletes `etc/…`.
///
/// A parent that does not exist yet is judged by its nearest existing
/// ancestor: that is the directory the extractor would create it through.
fn parent_inside(root: &Path, rel: &Path) -> bool {
    let mut p = root.join(rel.parent().unwrap_or(Path::new("")));
    loop {
        match std::fs::canonicalize(&p) {
            Ok(c) => return c.starts_with(root),
            Err(_) => {
                if !p.pop() || !p.starts_with(root) {
                    return false;
                }
            }
        }
    }
}

fn remove_entry(path: &Path) {
    match std::fs::symlink_metadata(path) {
        Ok(md) if md.is_dir() => {
            make_removable(path);
            let _ = std::fs::remove_dir_all(path);
        }
        Ok(_) => {
            let _ = std::fs::remove_file(path);
        }
        Err(_) => {}
    }
}

fn open_layer(path: &Path) -> Result<Box<dyn Read>, String> {
    let mut f = File::open(path).map_err(|e| e.to_string())?;
    let mut magic = [0u8; 4];
    let n = f.read(&mut magic).map_err(|e| e.to_string())?;
    let f = File::open(path).map_err(|e| e.to_string())?;
    Ok(if n >= 2 && magic[..2] == [0x1f, 0x8b] {
        Box::new(flate2::read::GzDecoder::new(f))
    } else if n >= 4 && magic == [0x28, 0xb5, 0x2f, 0xfd] {
        Box::new(zstd::stream::read::Decoder::new(f).map_err(|e| format!("zstd: {e}"))?)
    } else {
        Box::new(f)
    })
}

/// Apply one layer: pass 1 performs its deletions (whiteouts and opaque
/// directories) against what lower layers left; pass 2 extracts its files.
/// Two passes because an opaque marker may come after same-layer entries.
fn apply_layer(blob: &Path, root: &Path, modes: &mut BTreeMap<PathBuf, u32>) -> Result<(), String> {
    // ---- pass 1: deletions
    let mut ar = tar::Archive::new(open_layer(blob)?);
    for e in ar.entries().map_err(|e| e.to_string())? {
        let e = e.map_err(|e| e.to_string())?;
        let raw = e.path().map_err(|e| e.to_string())?.into_owned();
        let Some(rel) = clean(&raw) else { return Err(format!("refusing path `{}`", raw.display())) };
        let name = rel.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
        if name == ".wh..wh..opq" {
            let dir = rel.parent().unwrap_or(Path::new("")).to_path_buf();
            if !parent_inside(root, &dir.join("x")) {
                return Err(format!("opaque marker escapes the rootfs: `{}`", raw.display()));
            }
            if let Ok(rd) = std::fs::read_dir(root.join(&dir)) {
                for child in rd.flatten() {
                    remove_entry(&child.path());
                }
            }
        } else if let Some(hidden) = name.strip_prefix(".wh.") {
            let victim = rel.with_file_name(hidden);
            if !parent_inside(root, &victim) {
                return Err(format!("whiteout escapes the rootfs: `{}`", raw.display()));
            }
            remove_entry(&root.join(&victim));
        }
    }

    // ---- pass 2: files
    let mut ar = tar::Archive::new(open_layer(blob)?);
    ar.set_preserve_permissions(true);
    ar.set_unpack_xattrs(false);
    ar.set_overwrite(true);
    ar.set_mask(0o6000); // drop setuid/setgid: nothing in the box may gain privileges
    for e in ar.entries().map_err(|e| e.to_string())? {
        let mut e = e.map_err(|e| e.to_string())?;
        let raw = e.path().map_err(|e| e.to_string())?.into_owned();
        let Some(rel) = clean(&raw) else { return Err(format!("refusing path `{}`", raw.display())) };
        if rel.as_os_str().is_empty() {
            continue;
        }
        let name = rel.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
        if name.starts_with(".wh.") {
            continue;
        }
        let kind = e.header().entry_type();
        if matches!(kind, tar::EntryType::Char | tar::EntryType::Block | tar::EntryType::Fifo) {
            continue; // the box gets its own minimal /dev
        }
        if !parent_inside(root, &rel) {
            return Err(format!("entry escapes the rootfs: `{}`", raw.display()));
        }
        if kind == tar::EntryType::Link {
            // A hardlink must point at a file already in this rootfs. Without
            // this check a layer could hardlink a file of the HOST user (same
            // filesystem) into the image and read it from inside the box.
            let target = e.link_name().map_err(|e| e.to_string())?.ok_or("hardlink without target")?.into_owned();
            let Some(trel) = clean(&target) else { return Err(format!("hardlink target `{}` refused", target.display())) };
            match std::fs::canonicalize(root.join(&trel)) {
                Ok(t) if t.starts_with(root) => {}
                _ => return Err(format!("hardlink `{}` → `{}` leaves the rootfs", raw.display(), target.display())),
            }
        }
        // What a lower layer left at this path is replaced — unless both are
        // directories, which merge.
        let dest = root.join(&rel);
        if let Ok(md) = std::fs::symlink_metadata(&dest) {
            if !(md.is_dir() && kind == tar::EntryType::Directory) {
                remove_entry(&dest);
            }
        }
        let mode = e.header().mode().unwrap_or(0o755) & 0o1777;
        e.unpack_in(root).map_err(|err| format!("unpack `{}`: {err}", raw.display()))?;
        if kind == tar::EntryType::Directory {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&dest, std::fs::Permissions::from_mode(mode | 0o700));
            modes.insert(dest, mode);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn layer(entries: &[(&str, tar::EntryType, &[u8], Option<&str>)]) -> Vec<u8> {
        let mut b = tar::Builder::new(Vec::new());
        for (path, kind, body, link) in entries {
            let mut h = tar::Header::new_gnu();
            h.set_entry_type(*kind);
            h.set_mode(if *kind == tar::EntryType::Directory { 0o755 } else { 0o644 });
            h.set_size(body.len() as u64);
            if let Some(l) = link {
                h.set_link_name(l).unwrap();
            }
            // set_path rejects `..`; write the raw name to build hostile layers.
            let bytes = path.as_bytes();
            let name = &mut h.as_old_mut().name;
            name[..bytes.len()].copy_from_slice(bytes);
            h.set_cksum();
            b.append(&h, *body).unwrap();
        }
        b.into_inner().unwrap()
    }

    fn apply(root: &Path, bytes: &[u8]) -> Result<(), String> {
        let blob = root.parent().unwrap().join(format!("blob-{}", bytes.len()));
        std::fs::write(&blob, bytes).unwrap();
        apply_layer(&blob, &std::fs::canonicalize(root).unwrap(), &mut BTreeMap::new())
    }

    fn scratch(name: &str) -> (PathBuf, PathBuf) {
        let base = std::env::temp_dir().join(format!("plybox-image-test-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let root = base.join("rootfs");
        let outside = base.join("outside");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        (root, outside)
    }

    #[test]
    fn whiteouts_and_opaque_dirs_apply() {
        let (root, _) = scratch("wh");
        apply(&root, &layer(&[
            ("etc/", tar::EntryType::Directory, b"", None),
            ("etc/a", tar::EntryType::Regular, b"a", None),
            ("etc/b", tar::EntryType::Regular, b"b", None),
            ("opt/", tar::EntryType::Directory, b"", None),
            ("opt/old", tar::EntryType::Regular, b"o", None),
        ])).unwrap();
        apply(&root, &layer(&[
            ("etc/.wh.a", tar::EntryType::Regular, b"", None),
            ("opt/new", tar::EntryType::Regular, b"n", None), // same layer, before the marker
            ("opt/.wh..wh..opq", tar::EntryType::Regular, b"", None),
        ])).unwrap();
        assert!(!root.join("etc/a").exists());
        assert!(root.join("etc/b").exists());
        assert!(!root.join("opt/old").exists(), "opaque dir keeps lower-layer content");
        assert!(root.join("opt/new").exists(), "opaque marker deleted same-layer content");
    }

    #[test]
    fn dotdot_paths_are_refused() {
        let (root, outside) = scratch("dotdot");
        std::fs::write(outside.join("victim"), b"keep").unwrap();
        let err = apply(&root, &layer(&[("../outside/.wh.victim", tar::EntryType::Regular, b"", None)])).unwrap_err();
        assert!(err.contains("refusing"), "{err}");
        assert!(outside.join("victim").exists());
    }

    #[test]
    fn whiteout_through_a_planted_symlink_is_refused() {
        let (root, outside) = scratch("symwh");
        std::fs::write(outside.join("victim"), b"keep").unwrap();
        let link = outside.to_str().unwrap().to_string();
        apply(&root, &layer(&[("esc", tar::EntryType::Symlink, b"", Some(&link))])).unwrap();
        let err = apply(&root, &layer(&[("esc/.wh.victim", tar::EntryType::Regular, b"", None)])).unwrap_err();
        assert!(err.contains("escapes"), "{err}");
        assert!(outside.join("victim").exists(), "a whiteout deleted a file outside the rootfs");
    }

    #[test]
    fn no_directory_is_created_outside_through_a_planted_symlink() {
        let (root, outside) = scratch("symdir");
        let link = outside.to_str().unwrap().to_string();
        apply(&root, &layer(&[("esc", tar::EntryType::Symlink, b"", Some(&link))])).unwrap();
        let err = apply(&root, &layer(&[("esc/newdir/file", tar::EntryType::Regular, b"x", None)])).unwrap_err();
        assert!(err.contains("escapes"), "{err}");
        assert!(!outside.join("newdir").exists(), "a directory was created outside the rootfs");
    }

    #[test]
    fn hardlink_to_a_host_file_is_refused() {
        let (root, outside) = scratch("hardlink");
        std::fs::write(outside.join("secret"), b"host secret").unwrap();
        let target = "../outside/secret".to_string();
        let err = apply(&root, &layer(&[("stolen", tar::EntryType::Link, b"", Some(&target))])).unwrap_err();
        assert!(err.contains("hardlink"), "{err}");
        assert!(!root.join("stolen").exists());
    }

    #[test]
    fn setuid_bits_are_dropped() {
        let (root, _) = scratch("suid");
        let mut b = tar::Builder::new(Vec::new());
        let mut h = tar::Header::new_gnu();
        h.set_path("bin/su").unwrap();
        h.set_mode(0o4755);
        h.set_size(1);
        h.set_cksum();
        b.append(&h, &b"x"[..]).unwrap();
        apply(&root, &b.into_inner().unwrap()).unwrap();
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(root.join("bin/su")).unwrap().permissions().mode();
        assert_eq!(mode & 0o6000, 0, "setuid survived: {mode:o}");
    }

    #[test]
    fn refs_parse() {
        let r = parse_ref("python:3.13-slim").unwrap();
        assert_eq!((r.registry.as_str(), r.repository.as_str(), r.reference.as_str()), ("registry-1.docker.io", "library/python", "3.13-slim"));
        let r = parse_ref("ghcr.io/owner/tool").unwrap();
        assert_eq!((r.registry.as_str(), r.repository.as_str(), r.reference.as_str()), ("ghcr.io", "owner/tool", "latest"));
        let r = parse_ref("localhost:5000/x@sha256:abc").unwrap();
        assert_eq!((r.registry.as_str(), r.repository.as_str(), r.reference.as_str()), ("localhost:5000", "x", "sha256:abc"));
        let r = parse_ref("jrottenberg/ffmpeg:7.1-alpine").unwrap();
        assert_eq!(r.repository, "jrottenberg/ffmpeg");
    }
}
