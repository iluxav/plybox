#!/usr/bin/env python3
"""plybox lab, step 2: the proxy that lives OUTSIDE the box.

The box has loopback only. Its one way out is a unix socket this proxy
listens on. Tools inside speak plain HTTP CONNECT to it, so the proxy knows
the destination *by name*, before any packet exists, and decides there.

    proxy.py --socket PATH --allow HOST[,HOST...] --log FILE

Allow entries: `api.example.com`, `*.example.com` (subdomains only),
`host:port` (default port 443). IP literals are refused unless listed as
such. Names that resolve only to private, loopback, link-local or
multicast addresses are refused, so a public name cannot point the box at
the host or the LAN.

Lab code: deliberately small, blocking reads bounded, no TLS inspection.
"""
import argparse
import asyncio
import ipaddress
import json
import re
import socket
import time

LABEL = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")
MAX_LINE = 2048


class Policy:
    def __init__(self, entries):
        self.exact = {}  # host -> set(ports)
        self.suffix = {}  # ".example.com" -> set(ports)
        for raw in entries:
            raw = raw.strip().lower()
            if not raw:
                continue
            host, _, port = raw.rpartition(":") if raw.count(":") == 1 else (raw, "", "")
            if not port:
                host, port = raw, "443"
            ports = {int(port)}
            if host.startswith("*."):
                self.suffix.setdefault(host[1:], set()).update(ports)
            else:
                self.exact.setdefault(host, set()).update(ports)

    def allows(self, host, port):
        if port in self.exact.get(host, ()):
            return True
        for suffix, ports in self.suffix.items():
            if host.endswith(suffix) and host != suffix[1:] and port in ports:
                return True
        return False


def normalize_host(raw):
    """Return (host, kind) or (None, reason). kind is 'name' or 'ip'."""
    if len(raw) > 253:
        return None, "hostname too long"
    host = raw.lower()
    if host.endswith("."):
        host = host[:-1]
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    try:
        ip = ipaddress.ip_address(host)
        return str(ip), "ip"
    except ValueError:
        pass
    if not host or any(not LABEL.match(label) for label in host.split(".")):
        return None, "malformed hostname"
    return host, "name"


def is_public(addr):
    ip = ipaddress.ip_address(addr)
    return not (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


class Proxy:
    def __init__(self, policy, log):
        self.policy = policy
        self.log = log

    def record(self, **fields):
        fields["t"] = round(time.time(), 3)
        self.log.write(json.dumps(fields, sort_keys=True) + "\n")
        self.log.flush()

    async def refuse(self, writer, status, reason, **fields):
        body = f"plybox: {reason}\n".encode()
        writer.write(
            f"HTTP/1.1 {status}\r\nContent-Type: text/plain\r\nContent-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode()
            + body
        )
        self.record(verdict="refused", status=status, reason=reason, **fields)
        try:
            await writer.drain()
        finally:
            writer.close()

    async def handle(self, reader, writer):
        t0 = time.monotonic()
        try:
            line = await asyncio.wait_for(reader.readline(), 10)
        except (asyncio.TimeoutError, ConnectionError):
            writer.close()
            return
        if len(line) > MAX_LINE or not line.endswith(b"\n"):
            return await self.refuse(writer, 400, "request line too long")
        try:
            text = line.decode("ascii")
        except UnicodeDecodeError:
            return await self.refuse(writer, 400, "non-ascii bytes in request line", raw=repr(line[:80]))
        if any(ord(c) < 0x20 and c not in "\r\n" for c in text):
            return await self.refuse(writer, 400, "control character in request line", raw=repr(line[:80]))
        parts = text.strip().split(" ")
        if len(parts) != 3:
            return await self.refuse(writer, 400, "malformed request line", raw=text.strip()[:80])
        method, target, _version = parts

        # Drain headers (bounded) — we do not need them for CONNECT.
        for _ in range(100):
            try:
                hdr = await asyncio.wait_for(reader.readline(), 10)
            except (asyncio.TimeoutError, ConnectionError):
                writer.close()
                return
            if hdr in (b"\r\n", b"\n", b""):
                break

        if method != "CONNECT":
            return await self.refuse(writer, 403, "only CONNECT (https) is carried", method=method, target=target[:120])
        if "@" in target or target.count(":") == 0:
            return await self.refuse(writer, 400, "malformed CONNECT target", target=target[:120])
        raw_host, _, raw_port = target.rpartition(":")
        if not raw_port.isdigit() or not 0 < int(raw_port) < 65536:
            return await self.refuse(writer, 400, "bad port", target=target[:120])
        port = int(raw_port)
        host, kind = normalize_host(raw_host)
        if host is None:
            return await self.refuse(writer, 400, kind, target=target[:120])
        if not self.policy.allows(host, port):
            return await self.refuse(writer, 403, "not in the allow list", host=host, port=port, kind=kind)

        if kind == "ip":
            addrs = [host]
        else:
            try:
                infos = await asyncio.get_running_loop().getaddrinfo(host, port, type=socket.SOCK_STREAM)
            except socket.gaierror as e:
                return await self.refuse(writer, 502, f"cannot resolve: {e}", host=host, port=port)
            addrs = []
            for info in infos:
                if info[4][0] not in addrs:
                    addrs.append(info[4][0])
            public = [a for a in addrs if is_public(a)]
            if not public:
                return await self.refuse(writer, 403, "resolves only to private addresses", host=host, port=port, addrs=addrs)
            addrs = public

        upstream = None
        for addr in addrs:
            try:
                upstream = await asyncio.wait_for(asyncio.open_connection(addr, port), 10)
                break
            except (OSError, asyncio.TimeoutError):
                continue
        if upstream is None:
            return await self.refuse(writer, 502, "upstream unreachable", host=host, port=port, addrs=addrs)
        up_reader, up_writer = upstream
        writer.write(b"HTTP/1.1 200 Connection established\r\n\r\n")
        await writer.drain()

        counts = {"in": 0, "out": 0}

        async def pump(src, dst, key):
            try:
                while True:
                    data = await src.read(65536)
                    if not data:
                        break
                    counts[key] += len(data)
                    dst.write(data)
                    await dst.drain()
            except (ConnectionError, asyncio.CancelledError):
                pass
            finally:
                try:
                    dst.write_eof()
                except (OSError, RuntimeError):
                    pass

        await asyncio.gather(pump(reader, up_writer, "out"), pump(up_reader, writer, "in"))
        up_writer.close()
        writer.close()
        self.record(
            verdict="allowed", host=host, port=port, addr=addr,
            bytes_out=counts["out"], bytes_in=counts["in"],
            ms=int((time.monotonic() - t0) * 1000),
        )


async def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--socket", required=True)
    ap.add_argument("--allow", default="")
    ap.add_argument("--log", required=True)
    args = ap.parse_args()
    policy = Policy(args.allow.split(","))
    with open(args.log, "a") as log:
        proxy = Proxy(policy, log)
        server = await asyncio.start_unix_server(proxy.handle, path=args.socket)
        async with server:
            await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
