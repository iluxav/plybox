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

use serde_json::json;

use crate::record::Record;

const MAX_HEAD: usize = 8 * 1024;
const IO_TIMEOUT: Duration = Duration::from_secs(15);

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
    allow: Allow,
    record: Arc<Record>,
    /// Connections being handled right now. The supervisor waits for this to
    /// reach zero (briefly) after the box exits, so the last tunnel's record
    /// line is not lost to process exit.
    active: std::sync::atomic::AtomicUsize,
}

impl Proxy {
    pub fn new(allow: Allow, record: Arc<Record>) -> Arc<Proxy> {
        Arc::new(Proxy { allow, record, active: std::sync::atomic::AtomicUsize::new(0) })
    }

    /// Accept forever; one thread per connection. Runs in the supervisor.
    pub fn serve(self: Arc<Self>, listener: UnixListener) {
        for conn in listener.incoming() {
            let Ok(conn) = conn else { continue };
            let me = Arc::clone(&self);
            me.active.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            std::thread::spawn(move || {
                me.handle(conn);
                me.active.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
            });
        }
    }

    /// Wait until no connection is in flight, or `max` has passed.
    pub fn drain(&self, max: Duration) {
        let t0 = Instant::now();
        while self.active.load(std::sync::atomic::Ordering::SeqCst) > 0 && t0.elapsed() < max {
            std::thread::sleep(Duration::from_millis(10));
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
        if !self.allow.allows(&host, port) {
            return self.refuse(conn, 403, "not in the allow list", json!({ "host": host, "port": port }));
        }

        // Resolve to public addresses only (an IP literal was allowed by name above).
        let addrs: Vec<SocketAddr> = match kind {
            Kind::Ip(ip) => vec![SocketAddr::new(ip, port)],
            Kind::Name => match (host.as_str(), port).to_socket_addrs() {
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
        if conn.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n").is_err() {
            return;
        }
        let _ = conn.set_read_timeout(None);
        let _ = conn.set_write_timeout(None);

        let (out_bytes, in_bytes) = tunnel(conn, upstream);
        self.record.event(
            "net",
            json!({
                "verdict": "allowed", "mode": "tunnel", "host": host, "port": port, "addr": used,
                "bytes_out": out_bytes, "bytes_in": in_bytes,
                "ms": t0.elapsed().as_millis() as u64,
            }),
        );
    }
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
fn tunnel(client: UnixStream, upstream: TcpStream) -> (u64, u64) {
    let mut c2 = match client.try_clone() { Ok(c) => c, Err(_) => return (0, 0) };
    let mut u2 = match upstream.try_clone() { Ok(u) => u, Err(_) => return (0, 0) };
    let mut c1 = client;
    let mut u1 = upstream;
    let t = std::thread::spawn(move || {
        let n = std::io::copy(&mut c1, &mut u1).unwrap_or(0);
        let _ = u1.shutdown(Shutdown::Write);
        n
    });
    let back = std::io::copy(&mut u2, &mut c2).unwrap_or(0);
    let _ = c2.shutdown(Shutdown::Write);
    let fwd = t.join().unwrap_or(0);
    (fwd, back)
}
