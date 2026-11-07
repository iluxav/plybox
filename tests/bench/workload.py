#!/usr/bin/env python3
"""Identical host/box workloads. READY/GO/DONE/EXIT exclude setup and teardown."""
import argparse
import http.client
import http.server
import json
import math
import os
from pathlib import Path
import socket
import ssl
import statistics
import subprocess
import sys
import tempfile
import time


def percentile(values, p):
    return sorted(values)[max(0, math.ceil(len(values) * p) - 1)]


def latencies(samples, seconds):
    return {"requests": len(samples), "seconds": seconds, "requests_s": len(samples) / seconds,
            "p50_ms": statistics.median(samples) * 1000, "p99_ms": percentile(samples, .99) * 1000}


class HTTPS:
    def __init__(self, args):
        self.args = args
        ca = os.environ.get("SSL_CERT_FILE", args.ca) if args.secret and args.proxy else args.ca
        self.ctx = ssl.create_default_context(cafile=ca)
        self.ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        self.block = b"x" * 65536
        self.body = json.dumps({"model": "fixture", "messages": [{"role": "user", "content": "Hello"}]}).encode()
        self.tls = None

    def request(self, route, size=0):
        a = self.args
        sock = socket.create_connection(("127.0.0.1", 3128 if a.proxy else a.port), timeout=60)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        if a.proxy:
            sock.sendall(b"CONNECT fixture.test:443 HTTP/1.1\r\nHost: fixture.test:443\r\n\r\n")
            head = bytearray()
            while not head.endswith(b"\r\n\r\n"):
                char = sock.recv(1)
                if not char:
                    raise EOFError("proxy closed CONNECT")
                head.extend(char)
                if len(head) > 8192:
                    raise ValueError("oversized CONNECT response")
            assert head.startswith(b"HTTP/1.1 200"), head
        with self.ctx.wrap_socket(sock, server_hostname="fixture.test") as tls:
            self.tls = {"version": tls.version(), "cipher": tls.cipher()[0]}
            upload = route == "/upload"
            path = f"{route}?bytes={size}&secret={int(a.secret)}"
            token = os.environ.get("BENCH_TOKEN", "")
            length = size if upload else len(self.body)
            head = (f"POST {path} HTTP/1.1\r\nHost: fixture.test\r\nConnection: close\r\n"
                    f"Authorization: Bearer {token}\r\nContent-Type: application/json\r\n"
                    f"Content-Length: {length}\r\n\r\n").encode()
            tls.sendall(head)
            if upload:
                remaining = size
                while remaining:
                    chunk = self.block[:min(remaining, len(self.block))]
                    tls.sendall(chunk)
                    remaining -= len(chunk)
            else:
                tls.sendall(self.body)
            response = http.client.HTTPResponse(tls)
            response.begin()
            assert response.status == 200, (response.status, response.read(1024))
            if route == "/download":
                received = 0
                while data := response.read(65536):
                    received += len(data)
                assert received == size, (received, size)
                result = received
            else:
                body = response.read()
                result = json.loads(body)
                if upload:
                    assert result["received"] == size, result
                else:
                    assert result["content"] == "x" * 16300
            response.close()
            return result


def service_server():
    class Handler(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def setup(self):
            super().setup()
            self.connection.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

        def do_GET(self):
            body = b'{"ok":true,"data":"' + b"x" * 1000 + b'"}'
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_):
            pass

    server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
    print(server.server_port, flush=True)
    server.serve_forever()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("case")
    ap.add_argument("--proxy", action="store_true")
    ap.add_argument("--secret", action="store_true")
    ap.add_argument("--port", type=int)
    ap.add_argument("--ca")
    ap.add_argument("--requests", type=int, default=500)
    ap.add_argument("--transfer-bytes", type=int, default=200_000_000)
    ap.add_argument("--service-requests", type=int, default=10000)
    ap.add_argument("--cpu-iterations", type=int, default=100000)
    ap.add_argument("--file-iterations", type=int, default=20000)
    a = ap.parse_args()
    if a.case == "serve":
        service_server()
        return
    cleanup = lambda: None
    info = {}
    if a.case.startswith(("agent-", "stream-", "download-", "upload-")):
        client = HTTPS(a)
        route = "/" + ("model" if a.case.startswith("agent-") else a.case.split("-")[0])
        if route in ["/download", "/upload"]:
            client.request(route, 1_000_000)

            def work():
                start = time.perf_counter()
                client.request(route, a.transfer_bytes)
                elapsed = time.perf_counter() - start
                return {"seconds": elapsed, "bytes": a.transfer_bytes,
                        "MB_s": a.transfer_bytes / 1e6 / elapsed}
        else:
            for _ in range(20):
                client.request(route)

            def work():
                samples = []
                start = time.perf_counter()
                for _ in range(a.requests):
                    begin = time.perf_counter()
                    client.request(route)
                    samples.append(time.perf_counter() - begin)
                return latencies(samples, time.perf_counter() - start)
        info["tls"] = client.tls
    elif a.case == "service":
        server = subprocess.Popen([sys.executable, __file__, "serve"], stdout=subprocess.PIPE, text=True)
        port = int(server.stdout.readline())
        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=60)

        def once():
            connection.request("GET", "/")
            reply = connection.getresponse()
            assert reply.status == 200 and json.loads(reply.read())["ok"]

        for _ in range(30):
            once()

        def work():
            samples = []
            start = time.perf_counter()
            for _ in range(a.service_requests):
                begin = time.perf_counter()
                once()
                samples.append(time.perf_counter() - begin)
            return latencies(samples, time.perf_counter() - start)

        def cleanup():
            connection.close()
            server.terminate()
            server.wait(timeout=10)
    elif a.case == "cpu":
        obj = {"messages": [{"role": "user", "content": "x" * 80, "index": i} for i in range(16)]}

        def loop(n):
            for _ in range(n):
                value = json.loads(json.dumps(obj, separators=(",", ":")))
                assert value["messages"][15]["index"] == 15

        loop(1000)

        def work():
            start = time.perf_counter()
            loop(a.cpu_iterations)
            return {"seconds": time.perf_counter() - start, "iterations": a.cpu_iterations}
    elif a.case == "files":
        directory = tempfile.TemporaryDirectory(prefix="plybox-bench-files-", dir="/tmp")
        path = Path(directory.name) / "small-file"
        data = b"x" * 4096

        def loop(n):
            for _ in range(n):
                with path.open("wb") as f:
                    f.write(data)
                with path.open("rb") as f:
                    assert f.read() == data
                path.unlink()

        loop(100)

        def work():
            start = time.perf_counter()
            loop(a.file_iterations)
            return {"seconds": time.perf_counter() - start, "iterations": a.file_iterations}

        cleanup = directory.cleanup
    else:
        raise ValueError(a.case)
    print(json.dumps({"ready": True, **info}), flush=True)
    assert sys.stdin.readline().strip() == "GO"
    result = work()
    print(json.dumps({"done": True, **result}), flush=True)
    assert sys.stdin.readline().strip() == "EXIT"
    cleanup()


if __name__ == "__main__":
    main()
