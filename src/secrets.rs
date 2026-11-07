//! Secrets never enter the box.
//!
//! Each secret has a real value (held here, in the supervisor) and a
//! placeholder (what the box sees in its environment). The proxy swaps the
//! placeholder for the value only inside a request to the one host the
//! secret belongs to — which requires terminating TLS for that host, so
//! this module also owns the session CA and the per-host certificates, and
//! the TLS configurations the proxy uses on both sides of the termination.

use std::collections::HashMap;
use std::io::Write;
use std::path::Path;
use std::sync::{Arc, Mutex};

use rcgen::{BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::{ClientConfig, RootCertStore, ServerConfig};

#[derive(Clone)]
pub struct Secret {
    pub name: String,
    pub value: String,
    pub host: String,
    pub placeholder: String,
}

/// Build the secret set. `specs` are `NAME@HOST` (value from the caller's
/// environment) or `NAME=VALUE@HOST`. Values are never logged.
pub fn parse(specs: &[String]) -> Result<Vec<Secret>, String> {
    let mut out: Vec<Secret> = vec![];
    for spec in specs {
        let (lhs, host) = spec.rsplit_once('@').ok_or_else(|| format!("secret `{}`: expected NAME@HOST or NAME=VALUE@HOST", redact(spec)))?;
        let host = host.trim().to_ascii_lowercase();
        let (name, value) = match lhs.split_once('=') {
            Some((n, v)) => (n.to_string(), v.to_string()),
            None => {
                let v = std::env::var(lhs).map_err(|_| format!("secret {lhs}: not set in the environment"))?;
                (lhs.to_string(), v)
            }
        };
        if name.is_empty() || host.is_empty() || value.is_empty() {
            return Err(format!("secret `{}`: empty name, host or value", redact(spec)));
        }
        // One placeholder per NAME, however many hosts it is allowed toward.
        let placeholder = out
            .iter()
            .find(|s| s.name == name)
            .map(|s| s.placeholder.clone())
            .unwrap_or_else(|| format!("PLYBOX_SECRET_{name}_{}", hex16()));
        out.push(Secret { name, value, host, placeholder });
    }
    Ok(out)
}

fn redact(spec: &str) -> String {
    match spec.split_once('=') {
        Some((n, _)) => format!("{n}=…"),
        None => spec.to_string(),
    }
}

fn hex16() -> String {
    let mut b = [0u8; 8];
    let r = unsafe { libc::getrandom(b.as_mut_ptr() as *mut libc::c_void, b.len(), 0) };
    if r != b.len() as isize {
        let t = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0);
        b = (t as u64 ^ (std::process::id() as u64) << 32).to_le_bytes();
    }
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Secrets grouped by the host they may go to.
pub fn by_host(secrets: &[Secret]) -> HashMap<String, Vec<Secret>> {
    let mut m: HashMap<String, Vec<Secret>> = HashMap::new();
    for s in secrets {
        m.entry(s.host.clone()).or_default().push(s.clone());
    }
    m
}

/// The session CA and the TLS configurations built on it.
pub struct Tls {
    ca_cert: rcgen::Certificate,
    ca_key: KeyPair,
    ca_pem: String,
    servers: Mutex<HashMap<String, Arc<ServerConfig>>>,
    client: Arc<ClientConfig>,
}

impl Tls {
    /// A fresh CA for this session, plus the client config used toward
    /// upstreams: the host's trust store, plus any extra roots (the lab's).
    pub fn new(extra_roots: &[String]) -> Result<Tls, String> {
        let _ = rustls::crypto::ring::default_provider().install_default();

        let ca_key = KeyPair::generate().map_err(|e| format!("ca key: {e}"))?;
        let mut p = CertificateParams::new(Vec::<String>::new()).map_err(|e| format!("ca params: {e}"))?;
        p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        p.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        p.distinguished_name.push(DnType::CommonName, "plybox session CA");
        let ca_cert = p.self_signed(&ca_key).map_err(|e| format!("ca cert: {e}"))?;
        let ca_pem = ca_cert.pem();

        let mut roots = RootCertStore::empty();
        let native = rustls_native_certs::load_native_certs();
        for c in native.certs {
            let _ = roots.add(c);
        }
        for path in extra_roots {
            for c in CertificateDer::pem_file_iter(path).map_err(|e| format!("trust_ca {path}: {e}"))? {
                let c = c.map_err(|e| format!("trust_ca {path}: {e}"))?;
                roots.add(c).map_err(|e| format!("trust_ca {path}: {e}"))?;
            }
        }
        let client = Arc::new(ClientConfig::builder().with_root_certificates(roots).with_no_client_auth());

        Ok(Tls { ca_cert, ca_key, ca_pem, servers: Mutex::new(HashMap::new()), client })
    }

    pub fn client_config(&self) -> Arc<ClientConfig> {
        Arc::clone(&self.client)
    }

    /// The server config presenting a leaf for `host`, made on first use.
    pub fn server_config(&self, host: &str) -> Result<Arc<ServerConfig>, String> {
        if let Some(c) = self.servers.lock().unwrap().get(host) {
            return Ok(Arc::clone(c));
        }
        let key = KeyPair::generate().map_err(|e| format!("leaf key: {e}"))?;
        let mut p = CertificateParams::new(vec![host.to_string()]).map_err(|e| format!("leaf params: {e}"))?;
        p.distinguished_name.push(DnType::CommonName, host);
        p.use_authority_key_identifier_extension = true;
        p.key_usages = vec![KeyUsagePurpose::DigitalSignature, KeyUsagePurpose::KeyEncipherment];
        p.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let leaf = p.signed_by(&key, &self.ca_cert, &self.ca_key).map_err(|e| format!("leaf cert: {e}"))?;

        let chain = vec![leaf.der().clone(), self.ca_cert.der().clone()];
        let pk = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()));
        let cfg = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(chain, pk)
            .map_err(|e| format!("server config {host}: {e}"))?;
        let cfg = Arc::new(cfg);
        self.servers.lock().unwrap().insert(host.to_string(), Arc::clone(&cfg));
        Ok(cfg)
    }

    /// Write `ca.pem` (our CA plus any extra roots) and `bundle.pem` (host
    /// trust store + the same) into the session directory, where the box
    /// sees them under /run/plybox.
    pub fn write_trust_files(&self, session: &Path, extra_roots: &[String]) -> Result<(), String> {
        let mut ours = self.ca_pem.clone();
        for path in extra_roots {
            let text = std::fs::read_to_string(path).map_err(|e| format!("trust_ca {path}: {e}"))?;
            if !ours.ends_with('\n') {
                ours.push('\n');
            }
            ours.push_str(&text);
        }
        std::fs::write(session.join("ca.pem"), &ours).map_err(|e| format!("ca.pem: {e}"))?;
        let mut bundle = std::fs::File::create(session.join("bundle.pem")).map_err(|e| format!("bundle.pem: {e}"))?;
        let host_bundle = ["/etc/ssl/certs/ca-certificates.crt", "/etc/pki/tls/certs/ca-bundle.crt", "/etc/ssl/cert.pem"]
            .iter()
            .map(Path::new)
            .find(|p| p.is_file());
        match host_bundle {
            Some(p) => {
                let text = std::fs::read(p).map_err(|e| format!("{}: {e}", p.display()))?;
                bundle.write_all(&text).map_err(|e| format!("bundle.pem: {e}"))?;
                if !text.ends_with(b"\n") {
                    let _ = bundle.write_all(b"\n");
                }
            }
            None => eprintln!("plybox: warning: no host CA bundle found; the box trusts only the session CA"),
        }
        bundle.write_all(ours.as_bytes()).map_err(|e| format!("bundle.pem: {e}"))?;
        Ok(())
    }
}
