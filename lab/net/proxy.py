#!/usr/bin/env python3
"""plybox lab: the proxy that lives OUTSIDE the box (steps 2 and 4).

The box has loopback only. Its one way out is a unix socket this proxy
listens on. Tools inside speak HTTP CONNECT to it, so the proxy knows the
destination *by name*, before any packet exists, and decides there.

    proxy.py --socket PATH --allow HOST[,HOST...] --log FILE
             [--secret NAME=VALUE@HOST]... [--ca-dir DIR]
             [--map HOST=IP:PORT]... [--placeholders FILE]
    proxy.py mkcert --ca-dir DIR --host H [--host H...]

Allow entries: `api.example.com`, `*.example.com` (subdomains only),
`host:port` (default port 443). IP literals are refused unless listed as
such. Names that resolve only to private, loopback, link-local or multicast
addresses are refused, so a public name cannot point the box at the host or
the LAN. `--map` pins a lab name to a lab upstream and is the one exception.

Secrets (step 4). `--secret NAME=VALUE@HOST` keeps VALUE here and hands the
box a placeholder (written to --placeholders as NAME=PLACEHOLDER). For a
CONNECT to HOST the proxy terminates TLS with a certificate from the lab CA
in --ca-dir, swaps the placeholder for VALUE in the request head, and
re-encrypts upstream. Any other host gets an opaque tunnel and never sees
the real value — nor does anything inside the box.

Lab code: one thread per connection, bounded reads, no persistence.
"""
import argparse
import ipaddress
import json
import re
import secrets as pysecrets
import socket
import ssl
import subprocess
import sys
import threading
import time
from pathlib import Path

LABEL = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")
MAX_HEAD = 64 * 1024


# ----------------------------------------------------------------- policy

class Policy:
    def __init__(self, entries):
        self.exact = {}
        self.suffix = {}
        for raw in entries:
            raw = raw.strip().lower()
            if not raw:
                continue
            if raw.count(":") == 1:
                host, port = raw.split(":")
            else:
                host, port = raw, "443"
            ports = {int(port)}
            if host.startswith("*."):
                self.suffix.setdefault(host[1:], set()).update(ports)
            else:
                self.exact.setdefault(host, set()).update(ports)

    def allows(self, host, port):
        if port in self.exact.get(host, ()):
            return True
        return any(host.endswith(s) and host != s[1:] and port in p for s, p in self.suffix.items())


def normalize_host(raw):
    """Return (host, 'name'|'ip') or (None, reason)."""
    if len(raw) > 253:
        return None, "hostname too long"
    host = raw.lower().rstrip(".")
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    try:
        return str(ipaddress.ip_address(host)), "ip"
    except ValueError:
        pass
    if not host or any(not LABEL.match(label) for label in host.split(".")):
        return None, "malformed hostname"
    return host, "name"


def is_public(addr):
    ip = ipaddress.ip_address(addr)
    return not (ip.is_private or ip.is_loopback or ip.is_link_local
                or ip.is_multicast or ip.is_reserved or ip.is_unspecified)


# ----------------------------------------------------------- certificates

def _openssl(*args):
    subprocess.run(["openssl", *args], check=True, capture_output=True)


def ensure_ca(ca_dir: Path):
    ca_dir.mkdir(parents=True, exist_ok=True)
    key, pem = ca_dir / "ca.key", ca_dir / "ca.pem"
    if not pem.exists():
        # OpenSSL 3.x verifies strictly: a CA must say it is one (basicConstraints)
        # and be allowed to sign (keyUsage), or every chain built on it fails
        # with "CA cert does not include key usage extension".
        _openssl("req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
                 "-nodes", "-keyout", str(key), "-out", str(pem), "-days", "2",
                 "-subj", "/CN=plybox lab CA",
                 "-addext", "basicConstraints=critical,CA:TRUE",
                 "-addext", "keyUsage=critical,keyCertSign,cRLSign")
    return key, pem


def ensure_leaf(ca_dir: Path, host: str):
    key, pem = ca_dir / f"{host}.key", ca_dir / f"{host}.pem"
    if pem.exists():
        return key, pem
    ca_key, ca_pem = ensure_ca(ca_dir)
    csr, ext = ca_dir / f"{host}.csr", ca_dir / f"{host}.ext"
    ext.write_text(
        f"subjectAltName=DNS:{host}\n"
        "basicConstraints=CA:FALSE\n"
        "keyUsage=digitalSignature,keyEncipherment\n"
        "extendedKeyUsage=serverAuth\n"
    )
    _openssl("req", "-new", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
             "-nodes", "-keyout", str(key), "-out", str(csr), "-subj", f"/CN={host}")
    _openssl("x509", "-req", "-in", str(csr), "-CA", str(ca_pem), "-CAkey", str(ca_key),
             "-CAcreateserial", "-out", str(pem), "-days", "2", "-extfile", str(ext))
    return key, pem


# ------------------------------------------------------------------ bytes

def recv_head(sock, limit=MAX_HEAD):
    """Read an HTTP head (through the blank line). Returns (head, rest) or None."""
    buf = b""
    while b"\r\n\r\n" not in buf:
        if len(buf) > limit:
            return None
        chunk = sock.recv(16384)
        if not chunk:
            return None
        buf += chunk
    head, _, rest = buf.partition(b"\r\n\r\n")
    return head + b"\r\n\r\n", rest


def force_close(head: bytes) -> bytes:
    """One request per connection: drop keep-alive, add Connection: close."""
    lines = head.rstrip(b"\r\n").split(b"\r\n")
    kept = [l for l in lines if not l.lower().startswith((b"connection:", b"proxy-connection:"))]
    kept.append(b"Connection: close")
    return b"\r\n".join(kept) + b"\r\n\r\n"


def pump(src, dst, counter, key):
    try:
        while True:
            data = src.recv(65536)
            if not data:
                break
            counter[key] += len(data)
            dst.sendall(data)
    except OSError:
        pass
    finally:
        try:
            dst.shutdown(socket.SHUT_WR)
        except OSError:
            pass


def relay(a, b):
    """Copy both ways until both sides are done; returns bytes {a->b, b->a}."""
    counts = {"out": 0, "in": 0}
    t = threading.Thread(target=pump, args=(a, b, counts, "out"), daemon=True)
    t.start()
    pump(b, a, counts, "in")
    t.join(timeout=30)
    return counts


# ------------------------------------------------------------------ proxy

class Proxy:
    def __init__(self, policy, log, secrets_by_host, ca_dir, maps):
        self.policy = policy
        self.log = log
        self.lock = threading.Lock()
        self.secrets = secrets_by_host      # host -> [(name, real, placeholder)]
        self.ca_dir = ca_dir
        self.maps = maps                    # host -> (ip, port)
        self.server_ctx = {}
        self.client_ctx = ssl.create_default_context()
        if ca_dir:
            self.client_ctx.load_verify_locations(str(ensure_ca(ca_dir)[1]))

    def record(self, **fields):
        fields["t"] = round(time.time(), 3)
        with self.lock:
            self.log.write(json.dumps(fields, sort_keys=True) + "\n")
            self.log.flush()

    def refuse(self, conn, status, reason, **fields):
        body = f"plybox: {reason}\n".encode()
        try:
            conn.sendall(f"HTTP/1.1 {status}\r\nContent-Type: text/plain\r\n"
                         f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode() + body)
        except OSError:
            pass
        self.record(verdict="refused", status=status, reason=reason, **fields)
        conn.close()

    def handle(self, conn):
        t0 = time.monotonic()
        conn.settimeout(15)
        got = recv_head(conn, 4096)
        if got is None:
            return self.refuse(conn, 400, "request head missing or too long")
        head, _rest = got
        try:
            first = head.split(b"\r\n", 1)[0].decode("ascii")
        except UnicodeDecodeError:
            return self.refuse(conn, 400, "non-ascii bytes in request line", raw=repr(head[:80]))
        if any(ord(c) < 0x20 for c in first):
            return self.refuse(conn, 400, "control character in request line", raw=repr(head[:80]))
        parts = first.split(" ")
        if len(parts) != 3:
            return self.refuse(conn, 400, "malformed request line", raw=first[:80])
        method, target, _ = parts
        if method != "CONNECT":
            return self.refuse(conn, 403, "only CONNECT (https) is carried", method=method, target=target[:120])
        if "@" in target or ":" not in target:
            return self.refuse(conn, 400, "malformed CONNECT target", target=target[:120])
        raw_host, _, raw_port = target.rpartition(":")
        if not raw_port.isdigit() or not 0 < int(raw_port) < 65536:
            return self.refuse(conn, 400, "bad port", target=target[:120])
        port = int(raw_port)
        host, kind = normalize_host(raw_host)
        if host is None:
            return self.refuse(conn, 400, kind, target=target[:120])
        if not self.policy.allows(host, port):
            return self.refuse(conn, 403, "not in the allow list", host=host, port=port, kind=kind)

        # Resolve: lab map, IP literal, or DNS filtered to public addresses.
        if host in self.maps:
            addrs = [self.maps[host]]
        elif kind == "ip":
            addrs = [(host, port)]
        else:
            try:
                infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
            except socket.gaierror as e:
                return self.refuse(conn, 502, f"cannot resolve: {e}", host=host, port=port)
            seen = []
            for info in infos:
                if info[4][0] not in seen:
                    seen.append(info[4][0])
            public = [a for a in seen if is_public(a)]
            if not public:
                return self.refuse(conn, 403, "resolves only to private addresses", host=host, port=port, addrs=seen)
            addrs = [(a, port) for a in public]

        upstream = None
        for addr in addrs:
            try:
                upstream = socket.create_connection(addr, timeout=10)
                break
            except OSError:
                continue
        if upstream is None:
            return self.refuse(conn, 502, "upstream unreachable", host=host, port=port, addrs=[a for a, _ in addrs])
        upstream.settimeout(30)

        conn.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
        try:
            if host in self.secrets:
                counts, swapped = self.terminate_and_inject(conn, upstream, host)
                mode = "terminated"
            else:
                counts, swapped = relay(conn, upstream), 0
                mode = "tunnel"
        except (OSError, ssl.SSLError) as e:
            # An error is its own outcome — never also logged as "allowed".
            self.record(verdict="error", host=host, port=port, addr=addr[0], reason=str(e)[:160],
                        ms=int((time.monotonic() - t0) * 1000))
            return
        finally:
            for s in (conn, upstream):
                try:
                    s.close()
                except OSError:
                    pass
        self.record(verdict="allowed", host=host, port=port, addr=addr[0], mode=mode,
                    secrets_substituted=swapped, bytes_out=counts["out"], bytes_in=counts["in"],
                    ms=int((time.monotonic() - t0) * 1000))

    def server_context(self, host):
        if host not in self.server_ctx:
            key, pem = ensure_leaf(self.ca_dir, host)
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(str(pem), str(key))
            self.server_ctx[host] = ctx
        return self.server_ctx[host]

    def terminate_and_inject(self, conn, upstream, host):
        """TLS on both sides; swap placeholders for real values in the request head."""
        tls_client = self.server_context(host).wrap_socket(conn, server_side=True)
        tls_up = self.client_ctx.wrap_socket(upstream, server_hostname=host)
        got = recv_head(tls_client)
        if got is None:
            raise OSError("no request head inside the TLS session")
        head, rest = got
        swapped = 0
        for _name, real, placeholder in self.secrets[host]:
            swapped += head.count(placeholder.encode())
            head = head.replace(placeholder.encode(), real.encode())
        tls_up.sendall(force_close(head) + rest)
        counts = relay(tls_client, tls_up)
        counts["out"] += len(head) + len(rest)
        return counts, swapped


# ------------------------------------------------------------------- main

def parse_secrets(entries):
    """NAME=VALUE@HOST -> ({host: [(name, real, placeholder)]}, {name: placeholder})."""
    by_host, placeholders = {}, {}
    for e in entries:
        name, _, rest = e.partition("=")
        value, _, host = rest.rpartition("@")
        if not (name and value and host):
            sys.exit(f"--secret wants NAME=VALUE@HOST, got {e!r}")
        host = host.lower()
        ph = placeholders.setdefault(name, f"PLYBOX_SECRET_{name}_{pysecrets.token_hex(8)}")
        by_host.setdefault(host, []).append((name, value, ph))
    return by_host, placeholders


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "mkcert":
        ap = argparse.ArgumentParser(prog="proxy.py mkcert")
        ap.add_argument("--ca-dir", required=True)
        ap.add_argument("--host", action="append", default=[])
        a = ap.parse_args(sys.argv[2:])
        ca_dir = Path(a.ca_dir)
        _, ca_pem = ensure_ca(ca_dir)
        print(ca_pem)
        for h in a.host:
            print(ensure_leaf(ca_dir, h)[1])
        return

    ap = argparse.ArgumentParser()
    ap.add_argument("--socket", required=True)
    ap.add_argument("--allow", default="")
    ap.add_argument("--log", required=True)
    ap.add_argument("--secret", action="append", default=[])
    ap.add_argument("--ca-dir")
    ap.add_argument("--map", action="append", default=[])
    ap.add_argument("--placeholders")
    a = ap.parse_args()

    by_host, placeholders = parse_secrets(a.secret)
    if by_host and not a.ca_dir:
        sys.exit("--secret needs --ca-dir (TLS must be terminated to substitute)")
    if a.placeholders:
        Path(a.placeholders).write_text("".join(f"{n}={p}\n" for n, p in placeholders.items()))
    maps = {}
    for m in a.map:
        host, _, addr = m.partition("=")
        ip, _, port = addr.rpartition(":")
        maps[host.lower()] = (ip, int(port))

    proxy = Proxy(Policy(a.allow.split(",")), open(a.log, "a"), by_host,
                  Path(a.ca_dir) if a.ca_dir else None, maps)
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    Path(a.socket).unlink(missing_ok=True)
    srv.bind(a.socket)
    srv.listen(64)
    while True:
        conn, _ = srv.accept()
        threading.Thread(target=proxy.handle, args=(conn,), daemon=True).start()


if __name__ == "__main__":
    main()
