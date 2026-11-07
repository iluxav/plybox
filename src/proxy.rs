//! The proxy that lives OUTSIDE the box.
//!
//! The box has loopback only; its one exit is a unix socket this proxy
//! listens on. Tools inside speak HTTP CONNECT to it, so the destination is
//! known *by name* before any packet exists, and the decision is made here,
//! in the supervisor, where the workload cannot reach.
//!
//! Rules, from the lab:
//!   * allow list only: exact host, `*.suffix` (subdomains, not the apex),
//!     optional `:port`, default port 443;
//!   * IP literals are refused unless listed as such;
//!   * a name that resolves only to private/loopback/link-local/multicast
//!     addresses is refused, so a public name cannot point the box at the
//!     host or the LAN (DNS rebinding);
//!   * request lines are bounded and must be printable ASCII;
//!   * every decision is one line in the record.
//!
//! Slice 1 carries CONNECT tunnels only (so, HTTPS). Secret substitution
//! with TLS termination is slice 2.

use std::collections::{HashMap, HashSet};
use std::io::{Read, Write};
use std::net::{IpAddr, Shutdown, SocketAddr, TcpStream, ToSocketAddrs};
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::Arc;
use std::time::{Duration, Instant};

use rustls::pki_types::ServerName;
use rustls::{ClientConnection, ServerConnection, Stream};
use serde_json::json;

use crate::record::Record;
use crate::byte_budget::{Budget, Metered};
use crate::secrets::{Secret, Tls};

const MAX_HEAD: usize = 64 * 1024;
const MAX_BODY: usize = 64 * 1024 * 1024;
const IO_TIMEOUT: Duration = Duration::from_secs(15);
// Non-streaming model calls can be silent for ten minutes; allow five more
// for transport/scheduling overhead. Keep a finite idle wait: each stalled
// connection holds a supervisor thread, sockets and a buffered request that
// can reach MAX_BODY before substitution, outside the workload's cgroup
// limits. With no connection cap, workload exit is the other lifetime bound.
// This limits a stalled read, not a response that keeps making progress.
const UPSTREAM_RESPONSE_TIMEOUT: Duration = Duration::from_secs(15 * 60);

#[derive(Default, Clone)]
pub struct Allow {
    exact: HashMap<String, HashSet<u16>>,
    suffix: Vec<(String, HashSet<u16>)>, // ".example.com"
}

impl Allow {
    pub fn parse(entries: &[String]) -> Result<Allow, String> {
        let mut a = Allow::default();
        for raw in entries {
            let raw = raw.trim().to_ascii_lowercase();
            if raw.is_empty() {
                continue;
            }
            let (host, port) = match raw.rsplit_once(':') {
                Some((h, p)) if !h.contains(':') => (h.to_string(), p.parse::<u16>().map_err(|_| format!("allow `{raw}`: bad port"))?),
                _ => (raw.clone(), 443),
            };
            if let Some(s) = host.strip_prefix("*.") {
                let key = format!(".{s}");
                match a.suffix.iter_mut().find(|(k, _)| *k == key) {
                    Some((_, ports)) => {
                        ports.insert(port);
                    }
                    None => a.suffix.push((key, HashSet::from([port]))),
                }
            } else {
                a.exact.entry(host).or_default().insert(port);
            }
        }
        Ok(a)
    }

    /// The first destination `inner` allows that `self` does not (an
    /// operator's host list over a policy's): `*.a.example` sits inside
    /// `*.example`; a plain name needs a matching name or a wildcard above it.
    pub fn first_outside(&self, inner: &Allow) -> Option<String> {
        for (host, ports) in &inner.exact {
            if let Some(p) = ports.iter().find(|&&p| !self.allows(host, p)) {
                return Some(format!("{host}:{p}"));
            }
        }
        for (suffix, ports) in &inner.suffix {
            let covered = |p: u16| self.suffix.iter().any(|(s, sp)| suffix.ends_with(s.as_str()) && sp.contains(&p));
            if let Some(p) = ports.iter().find(|&&p| !covered(p)) {
                return Some(format!("*{suffix}:{p}"));
            }
        }
        None
    }

    pub fn allows(&self, host: &str, port: u16) -> bool {
        if self.exact.get(host).is_some_and(|p| p.contains(&port)) {
            return true;
        }
        self.suffix
            .iter()
            .any(|(s, p)| host.ends_with(s.as_str()) && host != &s[1..] && p.contains(&port))
    }
}

pub enum Kind {
    Name,
    Ip(IpAddr),
}

/// Lower-case, strip a trailing dot and IPv6 brackets, validate labels.
pub fn normalize_host(raw: &str) -> Result<(String, Kind), &'static str> {
    if raw.len() > 253 {
        return Err("hostname too long");
    }
    let mut host = raw.to_ascii_lowercase();
    if host.ends_with('.') {
        host.pop();
    }
    if host.starts_with('[') && host.ends_with(']') {
        host = host[1..host.len() - 1].to_string();
    }
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok((ip.to_string(), Kind::Ip(ip)));
    }
    if host.is_empty() || !host.split('.').all(valid_label) {
        return Err("malformed hostname");
    }
    Ok((host, Kind::Name))
}

fn valid_label(l: &str) -> bool {
    let b = l.as_bytes();
    !b.is_empty()
        && b.len() <= 63
        && b.iter().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-')
        && b[0] != b'-'
        && b[b.len() - 1] != b'-'
}

/// Not private, loopback, link-local, multicast, reserved or unspecified.
pub fn is_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            !(v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_multicast()
                || v4.is_broadcast()
                || v4.is_unspecified()
                || v4.is_documentation()
                || o[0] == 0
                || (o[0] == 100 && (64..128).contains(&o[1])) // CGNAT 100.64/10
                || o[0] >= 240) // reserved
        }
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_public(IpAddr::V4(v4));
            }
            let s = v6.segments();
            !(v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || (s[0] & 0xfe00) == 0xfc00 // unique local fc00::/7
                || (s[0] & 0xffc0) == 0xfe80 // link-local fe80::/10
                || s[0] == 0x2001 && s[1] == 0x0db8) // documentation
        }
    }
}

pub struct Proxy {
    upload: Arc<Budget>,
    download: Arc<Budget>,
    allow: Allow,
    record: Arc<Record>,
    /// host → the secrets that may be substituted toward it. A host here is
    /// TLS-terminated; every other host gets an opaque tunnel.
    secrets: HashMap<String, Vec<Secret>>,
    tls: Option<Arc<Tls>>,
    /// host → fixed address (test upstreams only).
    maps: HashMap<String, SocketAddr>,
    /// Learn mode: destinations outside the allow list are let through and
    /// collected here, as allow-list entries.
    learn: Option<std::sync::Mutex<std::collections::BTreeSet<String>>>,
    /// Connections being handled right now. The supervisor waits for this to
    /// reach zero (briefly) after the box exits, so the last tunnel's record
    /// line is not lost to process exit.
    active: std::sync::atomic::AtomicUsize,
    stopping: std::sync::atomic::AtomicBool,
    listening: std::sync::atomic::AtomicBool,
    /// The listener's own path, so `drain` can wake a blocked accept by
    /// connecting to it. Set by `serve` before it first checks `stopping`.
    wake: std::sync::Mutex<Option<std::path::PathBuf>>,
}

impl Proxy {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        allow: Allow,
        record: Arc<Record>,
        secrets: HashMap<String, Vec<Secret>>,
        tls: Option<Arc<Tls>>,
        maps: HashMap<String, SocketAddr>,
        learn: bool,
        bytes_out: Option<u64>,
        bytes_in: Option<u64>,
    ) -> Arc<Proxy> {
        Arc::new(Proxy {
            upload: Budget::new(bytes_out, "out", record.clone()),
            download: Budget::new(bytes_in, "in", record.clone()),
            allow,
            record,
            secrets,
            tls,
            maps,
            learn: learn.then(|| std::sync::Mutex::new(std::collections::BTreeSet::new())),
            active: std::sync::atomic::AtomicUsize::new(0),
            stopping: std::sync::atomic::AtomicBool::new(false),
            listening: std::sync::atomic::AtomicBool::new(true),
            wake: std::sync::Mutex::new(None),
        })
    }

    pub fn record_usage(&self, run: u32) {
        // Establish whether workers are quiescent BEFORE reading counters.
        // active's acquire load observes all commits before their decrement.
        let complete = !self.listening.load(std::sync::atomic::Ordering::SeqCst)
            && self.active.load(std::sync::atomic::Ordering::SeqCst) == 0;
        self.record.event("net_usage", json!({ "run": run, "bytes_out": self.upload.used(),
            "bytes_in": self.download.used(), "unit": "upstream_tcp_payload",
            "complete": complete }));
    }

    /// The destinations learn mode let through, as allow-list entries.
    pub fn learned(&self) -> Vec<String> {
        self.learn.as_ref().map(|m| m.lock().unwrap().iter().cloned().collect()).unwrap_or_default()
    }

    /// Accept until the workload exits. Closing the listener before the
    /// final snapshot prevents a queued connection from racing its totals.
    ///
    /// accept() blocks: a connection is picked up the moment it arrives, with
    /// no polling delay. `drain` wakes it by connecting to the listener's own
    /// path. Ordering: the path is published BEFORE `stopping` is checked,
    /// and `drain` sets `stopping` BEFORE it reads the path, so either drain
    /// sees the path and wakes us, or we see `stopping` and never block.
    pub fn serve(self: Arc<Self>, listener: UnixListener) {
        use std::sync::atomic::Ordering::SeqCst;
        let path = listener.local_addr().ok().and_then(|a| a.as_pathname().map(|p| p.to_path_buf()));
        *self.wake.lock().unwrap() = path;
        while !self.stopping.load(SeqCst) {
            let conn = match listener.accept() {
                Ok((conn, _)) => conn,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => {
                    // EMFILE and the like are transient: back off, keep serving.
                    std::thread::sleep(Duration::from_millis(10));
                    continue;
                }
            };
            if self.stopping.load(SeqCst) {
                break; // the wake-up connection from `drain`, or a late one
            }
            let me = Arc::clone(&self);
            me.active.fetch_add(1, SeqCst);
            std::thread::spawn(move || {
                me.handle(conn);
                me.active.fetch_sub(1, SeqCst);
            });
        }
        drop(listener);
        self.listening.store(false, SeqCst);
    }

    /// Stop accepting, then give existing connections time to finish.
    pub fn drain(&self, max: Duration) {
        use std::sync::atomic::Ordering::SeqCst;
        self.stopping.store(true, SeqCst);
        if let Some(path) = self.wake.lock().unwrap().clone() {
            let _ = UnixStream::connect(path); // unblocks accept()
        }
        let t0 = Instant::now();
        while (self.listening.load(SeqCst) || self.active.load(SeqCst) > 0) && t0.elapsed() < max {
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    fn refuse(&self, mut conn: UnixStream, status: u16, reason: &str, extra: serde_json::Value) {
        let body = format!("plybox: {reason}\n");
        let _ = write!(
            conn,
            "HTTP/1.1 {status} {}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            if status == 403 { "Forbidden" } else if status == 502 { "Bad Gateway" } else { "Bad Request" },
            body.len()
        );
        let mut fields = json!({ "verdict": "refused", "status": status, "reason": reason });
        merge(&mut fields, extra);
        self.record.event("net", fields);
        let _ = conn.shutdown(Shutdown::Both);
    }

    fn handle(&self, mut conn: UnixStream) {
        let t0 = Instant::now();
        let _ = conn.set_read_timeout(Some(IO_TIMEOUT));
        let _ = conn.set_write_timeout(Some(IO_TIMEOUT));

        let Some(head) = read_head(&mut conn) else {
            return self.refuse(conn, 400, "request head missing or too long", json!({}));
        };
        let first = head.split(|b| *b == b'\n').next().unwrap_or(&[]);
        if !first.iter().all(|c| (0x20..0x7f).contains(c) || *c == b'\r') {
            return self.refuse(conn, 400, "non-printable bytes in request line", json!({}));
        }
        let line = String::from_utf8_lossy(first).trim_end().to_string();
        let parts: Vec<&str> = line.split(' ').collect();
        if parts.len() != 3 {
            return self.refuse(conn, 400, "malformed request line", json!({ "raw": truncate(&line) }));
        }
        let (method, target) = (parts[0], parts[1]);
        if method != "CONNECT" {
            return self.refuse(conn, 403, "only CONNECT (https) is carried", json!({ "method": method, "target": truncate(target) }));
        }
        if target.contains('@') {
            return self.refuse(conn, 400, "malformed CONNECT target", json!({ "target": truncate(target) }));
        }
        let Some((raw_host, raw_port)) = target.rsplit_once(':') else {
            return self.refuse(conn, 400, "CONNECT target needs host:port", json!({ "target": truncate(target) }));
        };
        let Ok(port) = raw_port.parse::<u16>().and_then(|p| if p == 0 { "0".parse::<u16>().map(|_| 0).and(Err("x".parse::<u16>().unwrap_err())) } else { Ok(p) }) else {
            return self.refuse(conn, 400, "bad port", json!({ "target": truncate(target) }));
        };
        let (host, kind) = match normalize_host(raw_host) {
            Ok(x) => x,
            Err(why) => return self.refuse(conn, 400, why, json!({ "target": truncate(target) })),
        };
        let mut learned_now = false;
        if !self.allow.allows(&host, port) {
            match &self.learn {
                Some(set) => {
                    // Learn mode: let it through, remember it as an entry.
                    let entry = if port == 443 { host.clone() } else { format!("{host}:{port}") };
                    set.lock().unwrap().insert(entry);
                    learned_now = true;
                }
                None => return self.refuse(conn, 403, "not in the allow list", json!({ "host": host, "port": port })),
            }
        }

        if !self.upload.available() || !self.download.available() {
            return self.refuse(conn, 403, "run network byte budget exhausted", json!({ "host": host, "port": port }));
        }

        // Resolve: a test map, an IP literal (allowed by name above), or DNS
        // filtered to public addresses.
        let addrs: Vec<SocketAddr> = match (&kind, self.maps.get(&host)) {
            (_, Some(fixed)) => vec![*fixed],
            (Kind::Ip(ip), None) => vec![SocketAddr::new(*ip, port)],
            (Kind::Name, None) => match (host.as_str(), port).to_socket_addrs() {
                Ok(it) => {
                    let all: Vec<SocketAddr> = it.collect();
                    let public: Vec<SocketAddr> = all.iter().copied().filter(|a| is_public(a.ip())).collect();
                    if public.is_empty() {
                        let seen: Vec<String> = all.iter().map(|a| a.ip().to_string()).collect();
                        return self.refuse(conn, 403, "resolves only to private addresses", json!({ "host": host, "port": port, "addrs": seen }));
                    }
                    public
                }
                Err(e) => return self.refuse(conn, 502, "cannot resolve", json!({ "host": host, "port": port, "error": e.to_string() })),
            },
        };

        let mut upstream = None;
        let mut used = None;
        for a in &addrs {
            if let Ok(s) = TcpStream::connect_timeout(a, Duration::from_secs(10)) {
                used = Some(a.ip().to_string());
                upstream = Some(s);
                break;
            }
        }
        let Some(upstream) = upstream else {
            return self.refuse(conn, 502, "upstream unreachable", json!({ "host": host, "port": port }));
        };
        let _ = upstream.set_nodelay(true);
        let upstream = Metered::new(upstream, self.upload.clone(), self.download.clone());
        if conn.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n").is_err() {
            return;
        }

        // A host that carries a secret is terminated so the placeholder can
        // be swapped; everything else is an opaque tunnel.
        if let (Some(tls), Some(secs), Kind::Name) = (&self.tls, self.secrets.get(&host), &kind) {
            return self.terminate(conn, upstream, &host, port, used, secs, tls, t0);
        }
        let _ = conn.set_read_timeout(None);
        let _ = conn.set_write_timeout(None);
        let (out_bytes, in_bytes) = tunnel(conn, upstream);
        self.record.event(
            "net",
            json!({
                "verdict": if learned_now { "learned" } else { "allowed" }, "mode": "tunnel",
                "host": host, "port": port, "addr": used,
                "bytes_out": out_bytes, "bytes_in": in_bytes,
                "ms": t0.elapsed().as_millis() as u64,
            }),
        );
    }

    /// TLS on both sides; one request per connection. The request is read
    /// whole (head and body), placeholders are swapped, `Connection: close`
    /// is forced, and the response is streamed back until the upstream
    /// closes. Sequential by design: no threads around TLS state.
    #[allow(clippy::too_many_arguments)]
    fn terminate(
        &self,
        mut conn: UnixStream,
        mut upstream: Metered<TcpStream>,
        host: &str,
        port: u16,
        used: Option<String>,
        secs: &[Secret],
        tls: &Tls,
        t0: Instant,
    ) {
        let fail = |why: String| {
            self.record.event("net", json!({ "verdict": "error", "mode": "terminated", "host": host, "port": port, "reason": why }));
        };
        let server_cfg = match tls.server_config(host) {
            Ok(c) => c,
            Err(e) => return fail(e),
        };
        let mut sconn = match ServerConnection::new(server_cfg) {
            Ok(c) => c,
            Err(e) => return fail(format!("tls server: {e}")),
        };
        // Socket I/O stall limits, not total upload/response deadlines: a
        // progressing transfer can take longer. No client read is pending
        // while we wait for the model; keep bounds on clients that stop
        // uploading or stop reading the response.
        let _ = conn.set_read_timeout(Some(Duration::from_secs(60)));
        let _ = conn.set_write_timeout(Some(Duration::from_secs(60)));
        let mut client = Stream::new(&mut sconn, &mut conn);

        let (mut head, mut body) = match read_request(&mut client) {
            Ok(x) => x,
            Err(why) => return fail(format!("request: {why}")),
        };
        let mut swapped = 0usize;
        for s in secs {
            let (ph, val) = (s.placeholder.as_bytes(), s.value.as_bytes());
            swapped += replace_all(&mut head, ph, val) + replace_all(&mut body, ph, val);
        }
        let head = rewrite_head(&head, body.len());

        let name = match ServerName::try_from(host.to_string()) {
            Ok(n) => n,
            Err(e) => return fail(format!("server name: {e}")),
        };
        let mut cconn = match ClientConnection::new(tls.client_config(), name) {
            Ok(c) => c,
            Err(e) => return fail(format!("tls client: {e}")),
        };
        let _ = upstream.stream.set_read_timeout(Some(UPSTREAM_RESPONSE_TIMEOUT));
        // Likewise, bound a stalled upstream write, not total upload time.
        let _ = upstream.stream.set_write_timeout(Some(Duration::from_secs(60)));
        let mut up = Stream::new(&mut cconn, &mut upstream);
        if let Err(e) = up.write_all(&head).and_then(|_| up.write_all(&body)).and_then(|_| up.flush()) {
            return fail(format!("upstream write: {e}"));
        }

        let mut in_bytes = 0u64;
        let mut buf = [0u8; 16384];
        loop {
            match up.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    in_bytes += n as u64;
                    if client.write_all(&buf[..n]).is_err() {
                        break;
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                    // Do not turn a budget-truncated response into a clean
                    // TLS EOF (HTTP bodies may be delimited by EOF).
                    let _ = client.sock.shutdown(Shutdown::Both);
                    return fail(format!("upstream read: {e}"));
                }
                Err(_) => break, // existing handling of upstream unclean EOF / timeout
            }
        }
        let _ = client.flush();
        client.conn.send_close_notify();
        let _ = client.flush();

        self.record.event(
            "net",
            json!({
                "verdict": "allowed", "mode": "terminated", "host": host, "port": port, "addr": used,
                "secrets_substituted": swapped,
                "bytes_out": (head.len() + body.len()) as u64, "bytes_in": in_bytes,
                "ms": t0.elapsed().as_millis() as u64,
            }),
        );
    }
}

/// Read one HTTP/1.x request: the head (through the blank line) and the
/// body (Content-Length or chunked, decoded). Bounded.
fn read_request<R: Read>(r: &mut R) -> Result<(Vec<u8>, Vec<u8>), String> {
    let mut buf: Vec<u8> = Vec::with_capacity(4096);
    let mut chunk = [0u8; 16384];
    let head_end = loop {
        if let Some(i) = find(&buf, b"\r\n\r\n") {
            break i + 4;
        }
        if buf.len() > MAX_HEAD {
            return Err("head too long".into());
        }
        match r.read(&mut chunk) {
            Ok(0) => return Err("closed before the head ended".into()),
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
            Err(e) => return Err(format!("read: {e}")),
        }
    };
    let head = buf[..head_end].to_vec();
    let mut rest = buf[head_end..].to_vec();
    let lower = String::from_utf8_lossy(&head).to_ascii_lowercase();
    let content_length = header_value(&lower, "content-length").and_then(|v| v.trim().parse::<usize>().ok());
    let chunked = header_value(&lower, "transfer-encoding").is_some_and(|v| v.contains("chunked"));

    let mut need = |rest: &mut Vec<u8>, n: usize| -> Result<(), String> {
        while rest.len() < n {
            if n > MAX_BODY {
                return Err("body too large".into());
            }
            match r.read(&mut chunk) {
                Ok(0) => return Err("closed inside the body".into()),
                Ok(k) => rest.extend_from_slice(&chunk[..k]),
                Err(e) => return Err(format!("read body: {e}")),
            }
        }
        Ok(())
    };

    if let Some(n) = content_length {
        need(&mut rest, n)?;
        rest.truncate(n);
        return Ok((head, rest));
    }
    if chunked {
        let mut body = Vec::new();
        loop {
            // chunk-size line
            let line_end = loop {
                if let Some(i) = find(&rest, b"\r\n") {
                    break i;
                }
                let want = rest.len() + 1;
                need(&mut rest, want)?;
            };
            let size_text = String::from_utf8_lossy(&rest[..line_end]).trim().split(';').next().unwrap_or("").to_string();
            let size = usize::from_str_radix(&size_text, 16).map_err(|_| "bad chunk size".to_string())?;
            rest.drain(..line_end + 2);
            if size == 0 {
                // trailers until blank line (usually just CRLF)
                loop {
                    if rest.starts_with(b"\r\n") {
                        break;
                    }
                    if let Some(i) = find(&rest, b"\r\n") {
                        rest.drain(..i + 2);
                        continue;
                    }
                    let want = rest.len() + 1;
                    need(&mut rest, want)?;
                }
                break;
            }
            if body.len() + size > MAX_BODY {
                return Err("body too large".into());
            }
            need(&mut rest, size + 2)?;
            body.extend_from_slice(&rest[..size]);
            rest.drain(..size + 2);
        }
        return Ok((head, body));
    }
    Ok((head, Vec::new()))
}

fn header_value(lower_head: &str, name: &str) -> Option<String> {
    lower_head.lines().find_map(|l| l.strip_prefix(&format!("{name}:")).map(|v| v.trim().to_string()))
}

/// One request per connection, body length made explicit: drop keep-alive,
/// transfer-encoding and any client content-length; add ours.
fn rewrite_head(head: &[u8], body_len: usize) -> Vec<u8> {
    let text = String::from_utf8_lossy(head);
    let mut out: Vec<String> = vec![];
    let mut had_body_header = false;
    for (i, line) in text.trim_end_matches("\r\n").split("\r\n").enumerate() {
        let l = line.to_ascii_lowercase();
        if i > 0 && (l.starts_with("connection:") || l.starts_with("proxy-connection:")) {
            continue;
        }
        if i > 0 && (l.starts_with("content-length:") || l.starts_with("transfer-encoding:")) {
            had_body_header = true;
            continue;
        }
        out.push(line.to_string());
    }
    out.push("Connection: close".into());
    if body_len > 0 || had_body_header {
        out.push(format!("Content-Length: {body_len}"));
    }
    (out.join("\r\n") + "\r\n\r\n").into_bytes()
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

/// Replace every occurrence in place; returns the count.
fn replace_all(buf: &mut Vec<u8>, from: &[u8], to: &[u8]) -> usize {
    if from.is_empty() {
        return 0;
    }
    let mut count = 0;
    let mut i = 0;
    while let Some(p) = find(&buf[i..], from) {
        let at = i + p;
        buf.splice(at..at + from.len(), to.iter().copied());
        i = at + to.len();
        count += 1;
    }
    count
}

fn merge(into: &mut serde_json::Value, extra: serde_json::Value) {
    if let (Some(a), Some(b)) = (into.as_object_mut(), extra.as_object()) {
        for (k, v) in b {
            a.insert(k.clone(), v.clone());
        }
    }
}

fn truncate(s: &str) -> String {
    s.chars().take(120).collect()
}

/// Read through the blank line that ends an HTTP head, bounded.
fn read_head(conn: &mut UnixStream) -> Option<Vec<u8>> {
    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];
    loop {
        if buf.windows(4).any(|w| w == b"\r\n\r\n") || buf.windows(2).any(|w| w == b"\n\n") {
            return Some(buf);
        }
        if buf.len() > MAX_HEAD {
            return None;
        }
        match conn.read(&mut chunk) {
            Ok(0) | Err(_) => return None,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
        }
    }
}

/// Copy both ways until both sides are done. Returns (client→upstream, upstream→client) bytes.
fn tunnel(client: UnixStream, upstream: Metered<TcpStream>) -> (u64, u64) {
    let mut c2 = match client.try_clone() { Ok(c) => c, Err(_) => return (0, 0) };
    let u2 = match upstream.stream.try_clone() { Ok(u) => u, Err(_) => return (0, 0) };
    let mut u2 = upstream.with_stream(u2);
    let mut c1 = client;
    let mut u1 = upstream;
    let t = std::thread::spawn(move || {
        let (n, failed) = transfer(&mut c1, &mut u1);
        let _ = u1.stream.shutdown(if failed { Shutdown::Both } else { Shutdown::Write });
        if failed { let _ = c1.shutdown(Shutdown::Both); }
        n
    });
    let (back, failed) = transfer(&mut u2, &mut c2);
    let _ = c2.shutdown(if failed { Shutdown::Both } else { Shutdown::Write });
    if failed { let _ = u2.stream.shutdown(Shutdown::Both); }
    (t.join().unwrap_or(0), back)
}

// Unlike io::copy, preserve partial byte counts when a limit ends a stream.
fn transfer(from: &mut impl Read, to: &mut impl Write) -> (u64, bool) {
    let mut total = 0;
    let mut buf = [0; 16384];
    loop {
        let n = match from.read(&mut buf) {
            Ok(0) => return (total, false),
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return (total, true),
        };
        let mut sent = 0;
        while sent < n {
            match to.write(&buf[sent..n]) {
                Ok(0) => return (total, true),
                Ok(k) => { sent += k; total += k as u64; }
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => return (total, true),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn model_response_wait_exceeds_ten_minutes() {
        // Non-streaming calls can stay silent for ten minutes. Leave room
        // for transport overhead; the short TLS integration is in tests/limits.
        assert!(
            UPSTREAM_RESPONSE_TIMEOUT > Duration::from_secs(10 * 60),
            "proxy must outwait a ten-minute model call, got {UPSTREAM_RESPONSE_TIMEOUT:?}"
        );
    }
}
